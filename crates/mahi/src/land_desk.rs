use std::{
    collections::HashMap,
    fmt::Write as _,
    path::PathBuf,
    sync::{
        Arc,
        Mutex,
        MutexGuard,
        atomic::{
            AtomicBool,
            AtomicU64,
            Ordering,
        },
        mpsc::{
            self,
            RecvTimeoutError,
        },
    },
    thread,
    time::{
        Duration,
        Instant,
    },
};

use mahi_core::{
    AgentSlot,
    ParticipantName,
    ThreadId,
};
use mahi_store::{
    GlobalPatterns,
    Identity,
    LandedTree,
    ObjectId,
    Pushed,
    SnapshotCache,
    Store,
    StoreError,
};
use serde_json::{
    Map,
    Value,
};

use crate::{
    auto_merge::AutoMerge,
    conflicts,
    landed_branch::{
        Answer,
        BranchRecord,
    },
    landing::{
        self,
        Call,
        Onto,
        Refused,
    },
    mcp::ToolError,
    note,
    session::CommitKey,
    settings::Settings,
    sync::{
        FetchError,
        Reach,
        SyncSetup,
    },
};

const SNAPSHOT_ATTEMPTS: usize = 3;
const WATCH_EVERY: Duration = Duration::from_secs(1);
const PUSH_WAIT: Duration = Duration::from_secs(180);
const FETCH_WAIT: Duration = Duration::from_secs(60);
const PUSHES: &str = "Enter pushes  Esc cancels";
const ASKS: &str = "y lands them again  n they were merged  Esc cancels";
const CLOSES: &str = "Esc closes";
const DESCRIPTION_FILE: &str = "PR.md";
const LANDING_DIR: &str = "landing";
const MOST_COPIED: usize = 64 * 1024;

pub(crate) struct Desk {
    git_dir: PathBuf,
    thread: ThreadId,
    owner: ParticipantName,
    note: PathBuf,
    landing: String,
    stage: Mutex<Stage>,
    offers: AtomicU64,
}

enum Stage {
    Idle,
    Asking {
        merged: Result<Pending, String>,
        remote: String,
        shown: bool,
        generation: u64,
    },
    Waiting {
        pending: Pending,
        shown: bool,
        generation: u64,
    },
    Pushing {
        pending: Pending,
        generation: u64,
    },
    Done {
        text: String,
        shown: bool,
        generation: u64,
        clipboard: Option<String>,
    },
}

#[derive(Clone, Copy)]
struct Built {
    landed: ObjectId,
    tip: ObjectId,
    worktree: ObjectId,
    from: ObjectId,
}

impl Stage {
    fn is_busy(&self) -> bool {
        match self {
            Self::Asking { .. } | Self::Waiting { .. } | Self::Pushing { .. } => true,
            Self::Idle | Self::Done { .. } => false,
        }
    }
}

pub(crate) struct Pending {
    built: Built,
    commits: Vec<(String, Vec<String>)>,
    title: String,
    description: String,
    remote: SyncSetup,
    behind: Vec<(AgentSlot, Instant)>,
}

pub(crate) struct LandingView {
    pub(crate) title: String,
    pub(crate) body: String,
    pub(crate) hint: String,
    pub(crate) generation: u64,
}

impl std::fmt::Debug for Desk {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Desk")
            .field("thread", &self.thread)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Noted {
    Answered,
    BranchBack,
    NoRecord,
}

impl Desk {
    pub(crate) fn new(
        (git_dir, thread): (PathBuf, ThreadId),
        (owner, note): (ParticipantName, PathBuf),
        landing: String,
    ) -> Self {
        Self {
            git_dir,
            thread,
            owner,
            note,
            landing,
            stage: Mutex::new(Stage::Idle),
            offers: AtomicU64::new(0),
        }
    }

    fn stage(&self) -> Option<MutexGuard<'_, Stage>> {
        self.stage.lock().ok()
    }

    #[must_use]
    fn offer(&self, pending: Pending) -> bool {
        self.open(|generation| Stage::Waiting {
            pending,
            shown: false,
            generation,
        })
    }

    #[must_use]
    fn ask(&self, merged: Result<Pending, String>, remote: String) -> bool {
        self.open(|generation| Stage::Asking {
            merged,
            remote,
            shown: false,
            generation,
        })
    }

    fn open(&self, stage_at: impl FnOnce(u64) -> Stage) -> bool {
        let Some(mut stage) = self.stage() else {
            return false;
        };
        if stage.is_busy() {
            return false;
        }
        let generation = self.offers.fetch_add(1, Ordering::SeqCst) + 1;
        *stage = stage_at(generation);
        true
    }

    fn is_busy(&self) -> bool {
        self.stage().is_none_or(|stage| stage.is_busy())
    }

    pub(crate) fn wants_open(&self) -> bool {
        let Some(mut stage) = self.stage() else {
            return false;
        };
        match &mut *stage {
            Stage::Asking { shown, .. }
            | Stage::Waiting { shown, .. }
            | Stage::Done { shown, .. }
                if !*shown =>
            {
                *shown = true;
                true
            }
            Stage::Idle
            | Stage::Asking { .. }
            | Stage::Waiting { .. }
            | Stage::Pushing { .. }
            | Stage::Done { .. } => false,
        }
    }

    pub(crate) fn shown(&self) -> Option<u64> {
        let stage = self.stage()?;
        match &*stage {
            Stage::Idle => None,
            Stage::Asking { generation, .. }
            | Stage::Waiting { generation, .. }
            | Stage::Pushing { generation, .. }
            | Stage::Done { generation, .. } => Some(*generation),
        }
    }

    pub(crate) fn view(&self) -> Option<LandingView> {
        let stage = self.stage()?;
        match &*stage {
            Stage::Idle => None,
            Stage::Asking {
                remote, generation, ..
            } => Some(LandingView {
                title: self.title(),
                body: format!(
                    "The last landing's branch is gone from {remote}. If its pull request was closed without a merge, its changes can land again."
                ),
                hint: ASKS.to_owned(),
                generation: *generation,
            }),
            Stage::Waiting {
                pending,
                generation,
                ..
            } => Some(self.confirmation(pending, (PUSHES.to_owned(), *generation))),
            Stage::Pushing {
                pending,
                generation,
            } => {
                let hint = format!("Pushing to {}…", pending.remote.name);
                Some(self.confirmation(pending, (hint, *generation)))
            }
            Stage::Done {
                text, generation, ..
            } => Some(LandingView {
                title: self.title(),
                body: text.clone(),
                hint: CLOSES.to_owned(),
                generation: *generation,
            }),
        }
    }

    fn title(&self) -> String {
        format!(
            "Land thread {} on {}",
            self.thread.short(),
            branch_of(self.thread)
        )
    }

    fn confirmation(&self, pending: &Pending, (hint, generation): (String, u64)) -> LandingView {
        let mut body = String::new();
        for (first, paths) in &pending.commits {
            body.push_str("  ");
            push_line(&mut body, first);
            for path in paths {
                body.push_str("    ");
                push_line(&mut body, path);
            }
        }
        body.push_str("\nPull request: ");
        push_line(&mut body, &pending.title);
        if !pending.behind.is_empty() {
            body.push_str("\nNot merged yet, so not in this landing:\n");
        }
        for (slot, since) in &pending.behind {
            let _ = write!(body, "  {slot}  turn ended ");
            crate::palette::push_age(&mut body, since.elapsed());
            body.push_str(" ago\n");
        }
        LandingView {
            title: self.title(),
            body,
            hint,
            generation,
        }
    }

    pub(crate) fn confirm(self: &Arc<Self>) {
        let Some(mut stage) = self.stage() else {
            return;
        };
        let taken = std::mem::replace(&mut *stage, Stage::Idle);
        let Stage::Waiting {
            mut pending,
            generation,
            ..
        } = taken
        else {
            *stage = taken;
            return;
        };
        let built = pending.built;
        let count = pending.commits.len();
        let remote = pending.remote.clone();
        let description = std::mem::take(&mut pending.description);
        *stage = Stage::Pushing {
            pending,
            generation,
        };
        drop(stage);
        let desk = Arc::clone(self);
        thread::spawn(move || {
            let deadline = Deadline::after(PUSH_WAIT);
            let pushed = desk.push(&remote, built, &description, &deadline.interrupt);
            desk.finish((&remote, count, &description), &pushed, generation);
        });
    }

    pub(crate) fn cancel(&self) {
        let Some(mut stage) = self.stage() else {
            return;
        };
        match &*stage {
            Stage::Asking { .. } | Stage::Waiting { .. } => {
                *stage = Stage::Idle;
                drop(stage);
                let _ = note::record_landing(&self.note, &self.cancelled());
            }
            Stage::Done { .. } => *stage = Stage::Idle,
            Stage::Idle | Stage::Pushing { .. } => {}
        }
    }

    pub(crate) fn land_again(&self) {
        let Some(mut stage) = self.stage() else {
            return;
        };
        let taken = std::mem::replace(&mut *stage, Stage::Idle);
        let Stage::Asking { remote, .. } = taken else {
            *stage = taken;
            return;
        };
        drop(stage);
        let line = match self.note_answer(Answer::LandAgain) {
            Noted::Answered => format!(
                "{} cancelled your landing: the last landing's pull request was closed without a merge, so its paths count as changed again; call land again with commits that place them.",
                self.owner
            ),
            Noted::BranchBack => format!(
                "{} cancelled your landing: the last landing's branch is on {remote} again, so its paths do not land again; call land again.",
                self.owner
            ),
            Noted::NoRecord => self.cancelled(),
        };
        let _ = note::record_landing(&self.note, &line);
    }

    fn note_answer(&self, answer: Answer) -> Noted {
        let mut back = false;
        let noted = Store::open(&self.git_dir).map(|store| {
            BranchRecord::update(&store, self.thread, |record| {
                back = !record.gone;
                record.note_answer(answer)
            })
        });
        match noted {
            Ok(Ok(true)) => Noted::Answered,
            Ok(Ok(false)) if back => Noted::BranchBack,
            _ => Noted::NoRecord,
        }
    }

    fn cancelled(&self) -> String {
        format!("{} cancelled your landing; nothing was pushed.", self.owner)
    }

    pub(crate) fn merged(&self) {
        let Some(mut stage) = self.stage() else {
            return;
        };
        let taken = std::mem::replace(&mut *stage, Stage::Idle);
        let Stage::Asking { merged, .. } = taken else {
            *stage = taken;
            return;
        };
        let generation = self.offers.fetch_add(1, Ordering::SeqCst) + 1;
        let _noted = self.note_answer(Answer::Merged);
        match merged {
            Ok(pending) => {
                *stage = Stage::Waiting {
                    pending,
                    shown: true,
                    generation,
                };
            }
            Err(refusal) => {
                let _ = note::record_landing(&self.note, &refusal);
                *stage = Stage::Done {
                    text: refusal,
                    shown: true,
                    generation,
                    clipboard: None,
                };
            }
        }
    }

    pub(crate) fn take_clipboard(&self) -> Option<String> {
        let mut stage = self.stage()?;
        match &mut *stage {
            Stage::Done { clipboard, .. } => clipboard.take(),
            Stage::Idle | Stage::Asking { .. } | Stage::Waiting { .. } | Stage::Pushing { .. } => {
                None
            }
        }
    }

    fn keep_description(&self, store: &Store, description: &str) -> Kept {
        let file = crate::session::state_root(store, self.thread)
            .join(LANDING_DIR)
            .join(DESCRIPTION_FILE);
        crate::sync_state::write(&file, description.as_bytes())
            .map(|()| file.clone())
            .map_err(|error| (file, error.to_string()))
    }

    fn push(
        &self,
        remote: &SyncSetup,
        Built {
            landed,
            tip,
            worktree,
            from,
        }: Built,
        description: &str,
        interrupt: &Arc<AtomicBool>,
    ) -> Result<Landed, String> {
        let branch = branch_of(self.thread);
        let described = |error: &dyn std::error::Error| crate::describe(error);
        let store = Store::open(&self.git_dir).map_err(|error| described(&error))?;
        let current = store
            .branch_tip(&branch)
            .map_err(|error| described(&error))?;
        if current.is_some_and(|current| current != landed) {
            let moved = StoreError::Conflict {
                name: format!("refs/heads/{branch}"),
                expected: Some(landed),
                found: current,
            };
            return Err(described(&moved));
        }
        store
            .move_branch(&branch, current, tip, "mahi land")
            .map_err(|error| described(&error))?;
        let pushed = remote
            .connect(interrupt)
            .map_err(|error| described(&error))
            .and_then(|transport| {
                store
                    .push_branch_telling(transport, &branch, remote.push_limit, interrupt)
                    .map_err(|error| described(&error))
            })
            .and_then(|(pushed, link)| {
                refusal(&remote.name.to_string(), &branch, pushed).map_or(Ok(link), Err)
            });
        let link = match pushed {
            Ok(link) => link,
            Err(reason) => {
                let _ = match current {
                    Some(current) => store.move_branch(&branch, Some(tip), current, "mahi land"),
                    None => store.delete_branch(&branch, tip),
                };
                return Err(reason);
            }
        };
        let apart = store
            .commit_tree(tip)
            .map_or(true, |landed| landed != worktree)
            .then_some(worktree);
        let record = BranchRecord {
            remote: remote.name.to_string(),
            branch,
            tip,
            landing: self.landing.clone(),
            worktree: apart,
            from: Some(from),
            gone: false,
            answer: None,
        };
        let unremembered = store
            .keep_landed_tree((self.thread, LandedTree::Measured), apart)
            .and_then(|()| store.keep_landed_tree((self.thread, LandedTree::From), Some(from)))
            .map_err(|error| described(&error))
            .and_then(|()| {
                record
                    .write(&store, self.thread)
                    .map_err(|error| error.to_string())
            })
            .err()
            .map(|error| format!("cannot remember the pushed branch: {error}"));
        Ok(Landed {
            unremembered,
            kept: self.keep_description(&store, description),
            link,
        })
    }

    fn finish(
        &self,
        (remote, count, description): (&SyncSetup, usize, &str),
        pushed: &Result<Landed, String>,
        generation: u64,
    ) {
        let branch = branch_of(self.thread);
        let remote = remote.name.to_string();
        let clipboard = match pushed {
            Ok(Landed { kept: Ok(_), .. }) => copied(description),
            Ok(Landed { kept: Err(_), .. }) | Err(_) => None,
        };
        let (line, text) = match pushed {
            Ok(landed) => {
                let unremembered = &landed.unremembered;
                let mut line = format!(
                    "{} pushed your landing: {} on {branch} to {remote}.",
                    self.owner,
                    commits(count)
                );
                if let Some(unremembered) = unremembered {
                    line.push('\n');
                    line.push_str(unremembered);
                }
                let text = pushed_text((count, &branch, &remote), landed, clipboard.is_some());
                (line, text)
            }
            Err(reason) => (
                format!("your landing was not pushed: {reason}"),
                format!("Not pushed: {reason}"),
            ),
        };
        let _ = note::record_landing(&self.note, &line);
        if let Some(mut stage) = self.stage() {
            *stage = Stage::Done {
                text,
                shown: false,
                generation,
                clipboard,
            };
        }
    }
}

type Kept = Result<PathBuf, (PathBuf, String)>;

struct Landed {
    unremembered: Option<String>,
    kept: Kept,
    link: Option<String>,
}

fn copied(description: &str) -> Option<String> {
    (description.len() <= MOST_COPIED).then(|| description.to_owned())
}

fn pushed_text(
    (count, branch, remote): (usize, &str, &str),
    landed: &Landed,
    copied: bool,
) -> String {
    let mut text = format!("Pushed {} on {branch} to {remote}.", commits(count));
    if let Some(link) = &landed.link {
        let _ = write!(text, "\nOpen the pull request: {link}");
    }
    match (&landed.kept, copied) {
        (Ok(file), true) => {
            let _ = write!(
                text,
                "\nIts description is in {} and on your clipboard.",
                file.display()
            );
        }
        (Ok(file), false) => {
            let _ = write!(text, "\nIts description is in {}.", file.display());
        }
        (Err((file, error)), _) => {
            let _ = write!(
                text,
                "\ncannot keep the pull request draft in {}: {error}",
                file.display()
            );
        }
    }
    if let Some(unremembered) = &landed.unremembered {
        text.push('\n');
        text.push_str(unremembered);
    }
    text
}

fn push_line(body: &mut String, text: &str) {
    let line = text.chars().map(|character| {
        if character.is_control() {
            ' '
        } else {
            character
        }
    });
    body.extend(line);
    body.push('\n');
}

fn commits(count: usize) -> String {
    match count {
        1 => "1 commit".to_owned(),
        count => format!("{count} commits"),
    }
}

fn refusal(remote: &str, branch: &str, pushed: Pushed) -> Option<String> {
    Some(match pushed {
        Pushed::Updated | Pushed::UpToDate => return None,
        Pushed::Behind => format!(
            "{branch} on {remote} has commits this one does not; fetch and merge them, then push again"
        ),
        Pushed::Unchecked(reason) => {
            format!("cannot tell whether {branch} moves forward on {remote}: {reason}")
        }
        Pushed::Refused(reason) => format!("{remote} refused {branch}: {reason}"),
        Pushed::TooLarge(limit) => format!(
            "{branch} was not pushed: its new commits are larger than push-limit ({limit} bytes); raise push-limit in config.toml"
        ),
        Pushed::Deferred => format!("{branch} was not pushed; push again"),
    })
}

struct Deadline {
    interrupt: Arc<AtomicBool>,
    _cancel: mpsc::Sender<()>,
}

impl Deadline {
    fn after(wait: Duration) -> Self {
        let interrupt = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&interrupt);
        let (cancel, cancelled) = mpsc::channel::<()>();
        thread::spawn(move || {
            if cancelled.recv_timeout(wait) == Err(RecvTimeoutError::Timeout) {
                stopping.store(true, Ordering::SeqCst);
            }
        });
        Self {
            interrupt,
            _cancel: cancel,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OnRemote {
    Kept,
    Gone,
}

struct LastLanding {
    tip: ObjectId,
    measured: ObjectId,
    on_remote: OnRemote,
    ask: bool,
}

fn branch_of(thread: ThreadId) -> String {
    format!("mahi/{thread}")
}

pub(crate) type GitIdentity = (Option<String>, Option<String>);

pub(crate) struct Lander {
    thread: ThreadId,
    me: AgentSlot,
    worktree: String,
    globals: GlobalPatterns,
    identity: GitIdentity,
    reach: Reach,
    limits: Settings,
    commits: CommitKey,
    desk: Arc<Desk>,
    query: AutoMerge,
    first_seen: FirstSeen,
}

#[derive(Debug, Default)]
struct FirstSeen(Mutex<HashMap<AgentSlot, (ObjectId, Instant)>>);

impl FirstSeen {
    fn note(&self, slot: &AgentSlot, commit: ObjectId) -> Instant {
        let now = Instant::now();
        let Ok(mut seen) = self.0.lock() else {
            return now;
        };
        match seen.get(slot) {
            Some(&(noted, since)) if noted == commit => since,
            Some(_) | None => {
                seen.insert(slot.clone(), (commit, now));
                now
            }
        }
    }
}

pub(crate) fn watch_turn_ends(lander: &Arc<Lander>) {
    let lander = Arc::downgrade(lander);
    thread::spawn(move || {
        let mut seen = (Vec::new(), Vec::new());
        loop {
            thread::sleep(WATCH_EVERY);
            let Some(lander) = lander.upgrade() else {
                return;
            };
            let Ok(store) = Store::open(&lander.query.git_dir) else {
                continue;
            };
            let Ok(heads) = store.thread_refs() else {
                continue;
            };
            let held: Vec<(AgentSlot, ObjectId)> =
                crate::held::list(&store, lander.thread, &lander.me)
                    .into_iter()
                    .map(|(slot, record)| (slot, record.commit))
                    .collect();
            let now = (heads, held);
            if now == seen {
                continue;
            }
            let Ok(behind) = lander.query.behind(&store) else {
                continue;
            };
            for (slot, commit) in &behind {
                lander.first_seen.note(slot, *commit);
            }
            seen = now;
        }
    });
}

impl std::fmt::Debug for Lander {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Lander")
            .field("thread", &self.thread)
            .field("me", &self.me)
            .finish_non_exhaustive()
    }
}

impl Lander {
    pub(crate) fn new(
        (thread, me): (ThreadId, AgentSlot),
        (worktree, globals): (String, GlobalPatterns),
        (identity, (reach, limits), commits): (GitIdentity, (Reach, Settings), CommitKey),
        (desk, query): (Arc<Desk>, AutoMerge),
    ) -> Self {
        Self {
            thread,
            me,
            worktree,
            globals,
            identity,
            reach,
            limits,
            commits,
            desk,
            query,
            first_seen: FirstSeen::default(),
        }
    }

    pub(crate) fn land(
        &self,
        store: &Store,
        arguments: &Map<String, Value>,
        (base, collaborators): (ObjectId, &[ParticipantName]),
    ) -> Result<String, ToolError> {
        let call = landing::parse(arguments)?;
        let owner = self.me.participant();
        if let Some(refusal) = landing::message_refusal(&call) {
            return Ok(refusal);
        }
        if self.desk.is_busy() {
            return Ok(landing::waiting(owner));
        }
        let (Some(name), Some(email)) = &self.identity else {
            let key = if self.identity.0.is_none() {
                "user.name"
            } else {
                "user.email"
            };
            return Ok(landing::identity_unset(key, owner));
        };
        let remote =
            match SyncSetup::chosen_by(store, (&self.reach, || self.limits.push_limit), true) {
                Ok(Some(remote)) => remote,
                Ok(None) => return Ok(landing::no_remote(owner)),
                Err(error) => return Err(ToolError::Failed(crate::describe(&error))),
            };
        let failed = |error: &StoreError| ToolError::Failed(crate::describe(error));
        let behind = self.behind(store)?;
        let worktree = self.snapshot(store).map_err(|error| failed(&error))?;
        if let Some(paths) = self.unresolved(store, worktree) {
            return Ok(landing::conflicts_first(&paths));
        }
        let last = self
            .last_landing(store, &remote, base)
            .map_err(|error| failed(&error))?;
        let ask = last.ask;
        let gone_from = remote.name.to_string();
        let identity = Identity::now(name.clone(), email.clone());
        let prepared = self.prepare(
            store,
            (call, worktree, last),
            (remote, behind),
            (&identity, collaborators),
        )?;
        match (ask, prepared) {
            (true, prepared) => {
                let _asked = self.desk.ask(prepared, gone_from);
            }
            (false, Ok(pending)) => {
                let _offered = self.desk.offer(pending);
            }
            (false, Err(refusal)) => return Ok(refusal),
        }
        Ok(landing::waiting(owner))
    }

    fn prepare(
        &self,
        store: &Store,
        (mut call, worktree, last): (Call, ObjectId, LastLanding),
        (remote, behind): (SyncSetup, Vec<(AgentSlot, Instant)>),
        (identity, collaborators): (&Identity, &[ParticipantName]),
    ) -> Result<Result<Pending, String>, ToolError> {
        let failed = |error: &StoreError| ToolError::Failed(crate::describe(error));
        let LastLanding {
            tip: landed,
            measured,
            on_remote,
            ..
        } = last;
        let listed = store
            .changed_paths(measured, worktree, landing::MAX_LANDED_PATHS)
            .map_err(|error| failed(&error))?;
        let changed = match landing::landable(listed) {
            Ok(changed) => changed,
            Err(refused) => return Ok(Err(refused.text())),
        };
        if let Err(misplaced) = landing::check(&call, &changed.paths) {
            return Ok(Err(misplaced.text()));
        }
        let parent = match on_remote {
            OnRemote::Gone => self
                .landing_tip(store, &remote)
                .map_err(|error| ToolError::Failed(crate::describe(&error)))?
                .ok_or_else(|| {
                    ToolError::Failed(landing::no_landing_branch(
                        &BranchRecord::shown(&self.desk.landing),
                        &remote.name,
                    ))
                })?,
            OnRemote::Kept => landed,
        };
        let parent_tree = store.commit_tree(parent).map_err(|error| failed(&error))?;
        let merged = match landing::onto(store, (measured, parent_tree, worktree), &changed)
            .map_err(|error| failed(&error))?
        {
            Onto::Merged(merged) => merged,
            Onto::Conflicts(paths) => {
                return Ok(Err(landing::changed_upstream(
                    &BranchRecord::shown(&self.desk.landing),
                    &remote.name,
                    &paths,
                )));
            }
        };
        let agents = crate::threads::thread_agents(store, self.thread)
            .map_err(|error| failed(&error))?
            .into_iter()
            .filter(|slot| collaborators.contains(slot.participant()))
            .collect::<Vec<_>>();
        let built = landing::build(
            store,
            (parent, merged),
            &changed.gone,
            &mut call,
            (self.thread, &agents),
            (identity, self.commits.signer()),
        )
        .map_err(|error| failed(&error))?;
        let Some(&tip) = built.last() else {
            return Ok(Err(Refused::NothingChanged.text()));
        };

        Ok(Ok(pending(
            Built {
                landed,
                tip,
                worktree,
                from: measured,
            },
            (call, &changed.gone),
            (remote, behind),
        )))
    }

    fn behind(&self, store: &Store) -> Result<Vec<(AgentSlot, Instant)>, ToolError> {
        let behind = self
            .query
            .behind(store)
            .map_err(|error| ToolError::Failed(crate::describe(&error)))?;
        let dated = behind.into_iter().map(|(slot, commit)| {
            let since = self.first_seen.note(&slot, commit);
            (slot, since)
        });
        Ok(dated.collect())
    }

    fn last_landing(
        &self,
        store: &Store,
        remote: &SyncSetup,
        base: ObjectId,
    ) -> Result<LastLanding, StoreError> {
        let branch = branch_of(self.thread);
        let record = BranchRecord::read(store, self.thread)
            .filter(|record| record.branch == branch && record.remote == remote.name.as_str());
        let Some(record) = record else {
            return Ok(LastLanding {
                tip: base,
                measured: store.commit_tree(base)?,
                on_remote: OnRemote::Kept,
                ask: false,
            });
        };
        let measured = match (record.landing_again_from(), record.worktree) {
            (Some(tree), _) | (None, Some(tree)) => tree,
            (None, None) => store.commit_tree(record.tip)?,
        };
        let on_remote = if record.gone {
            OnRemote::Gone
        } else {
            OnRemote::Kept
        };
        Ok(LastLanding {
            tip: record.tip,
            measured,
            on_remote,
            ask: record.asks(),
        })
    }

    fn landing_tip(
        &self,
        store: &Store,
        remote: &SyncSetup,
    ) -> Result<Option<ObjectId>, FetchError> {
        let deadline = Deadline::after(FETCH_WAIT);
        remote.fetch_within(self.limits.fetch_limit, &deadline.interrupt, |transport| {
            Ok(store.fetch_branch(transport, &self.desk.landing, &deadline.interrupt)?)
        })
    }

    fn snapshot(&self, store: &Store) -> Result<ObjectId, StoreError> {
        let interrupt = AtomicBool::new(false);
        let mut left = SNAPSHOT_ATTEMPTS;
        loop {
            left -= 1;
            let taken = store.snapshot(
                &self.worktree,
                &self.globals,
                &mut SnapshotCache::default(),
                &interrupt,
            );
            match taken {
                Err(StoreError::ChangedDuringSnapshot(_)) if left > 0 => {}
                taken => return taken.map(|snapshot| snapshot.tree),
            }
        }
    }

    fn unresolved(&self, store: &Store, worktree: ObjectId) -> Option<Vec<String>> {
        let file = conflicts::file(store, self.thread, &self.me);
        let kept = match conflicts::KeptConflicts::load(&file) {
            Ok(None) => return None,
            Ok(Some(kept)) => Some(kept),
            Err(_) => None,
        };
        if conflicts::resolved(store, &self.me, &file, worktree).unwrap_or(false) {
            return None;
        }
        Some(kept.map_or_else(Vec::new, |kept| {
            kept.paths()
                .map(|path| String::from_utf8_lossy(path).into_owned())
                .collect()
        }))
    }
}

fn pending(
    built: Built,
    (call, gone): (Call, &[Vec<u8>]),
    (remote, behind): (SyncSetup, Vec<(AgentSlot, Instant)>),
) -> Pending {
    let mut commits: Vec<(String, Vec<String>)> = call
        .commits
        .into_iter()
        .map(|planned| {
            let first = planned
                .message
                .lines()
                .next()
                .unwrap_or_default()
                .to_owned();
            (first, planned.paths)
        })
        .collect();
    if let Some((_, paths)) = commits.last_mut() {
        let deleted = gone.iter().map(|path| {
            format!(
                "{} (deleted, name not UTF-8)",
                String::from_utf8_lossy(path)
            )
        });
        paths.extend(deleted);
    }
    Pending {
        built,
        commits,
        title: call.title,
        description: landing::printable(&call.description),
        remote,
        behind,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #[cfg(target_os = "linux")]
    use std::{
        ffi::OsStr,
        os::unix::ffi::OsStrExt as _,
    };
    use std::{
        fs,
        time::Instant,
    };

    use mahi_core::{
        RefKind,
        ThreadRef,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::{
        environment::Environment,
        remote::{
            self,
            Visibility,
        },
        session::tests::repository_on_main,
    };

    pub(crate) struct Landing {
        repo: TempDir,
        pub(crate) store: Store,
        pub(crate) desk: Arc<Desk>,
        pub(crate) thread: ThreadId,
        pub(crate) note: PathBuf,
        landed: ObjectId,
        tip: ObjectId,
    }

    fn unreachable_remote(store: &Store, home: &std::path::Path) -> SyncSetup {
        let config = store.common_dir().join("config");
        let mut text = fs::read_to_string(&config).unwrap();
        text.push_str("[remote \"up\"]\n\turl = ssh://git@127.0.0.1:1/x.git\n");
        fs::write(&config, text).unwrap();
        let store = Store::open(store.common_dir()).unwrap();
        remote::choose(&store, &"up".parse().unwrap(), Visibility::Private).unwrap();
        SyncSetup::chosen(&store, &environment(home), true)
            .unwrap()
            .unwrap()
    }

    fn environment(home: &std::path::Path) -> Environment {
        Environment {
            ssh_auth_sock: Some(home.join("agent.sock")),
            user: Some("tester".to_owned()),
            home: Some(home.to_path_buf()),
            ..Environment::default()
        }
    }

    pub(crate) fn waiting_landing() -> Landing {
        let (repo, store) = repository_on_main();
        let thread = ThreadId::random().unwrap();
        let note = repo.path().join("note");
        let remote = unreachable_remote(&store, repo.path());
        let landed = store.head_commit().unwrap();
        let tree = store.commit_tree(landed).unwrap();
        let other = ThreadRef::new(thread, RefKind::Meta);
        let tip = store.append(&other, None, tree, "landing").unwrap();
        let desk = Arc::new(Desk::new(
            (store.common_dir().to_path_buf(), thread),
            (ParticipantName::new("alice").unwrap(), note.clone()),
            "main".to_owned(),
        ));
        let pending = Pending {
            built: Built {
                landed,
                tip,
                worktree: tree,
                from: tree,
            },
            commits: vec![
                (
                    "Retry failed requests in the client".to_owned(),
                    vec!["src/client.rs".to_owned(), "src/retry.rs".to_owned()],
                ),
                (
                    "Test the retry".to_owned(),
                    vec!["tests/retry.rs".to_owned()],
                ),
            ],
            title: "Retry failed\nrequests".to_owned(),
            description: "Why.".to_owned(),
            remote,
            behind: vec![("bob.claude".parse().unwrap(), Instant::now())],
        };
        assert!(desk.offer(pending));
        Landing {
            repo,
            store,
            desk,
            thread,
            note,
            landed,
            tip,
        }
    }

    pub(crate) fn push_now(landing: &Landing) {
        let mut stage = landing.desk.stage().unwrap();
        let Stage::Waiting {
            pending,
            generation,
            ..
        } = std::mem::replace(&mut *stage, Stage::Idle)
        else {
            panic!("the landing waits for the owner");
        };
        *stage = Stage::Pushing {
            pending,
            generation,
        };
    }

    fn record_of(landing: &Landing, gone: bool) -> BranchRecord {
        BranchRecord {
            remote: "up".to_owned(),
            branch: branch_of(landing.thread),
            tip: landing.tip,
            landing: "main".to_owned(),
            worktree: None,
            from: Some(landing.store.commit_tree(landing.tip).unwrap()),
            gone,
            answer: None,
        }
    }

    pub(crate) fn ask_about(landing: &Landing) {
        let mut stage = landing.desk.stage().unwrap();
        let Stage::Waiting {
            pending,
            generation,
            ..
        } = std::mem::replace(&mut *stage, Stage::Idle)
        else {
            panic!("the landing waits for the owner");
        };
        *stage = Stage::Asking {
            merged: Ok(pending),
            remote: "up".to_owned(),
            shown: false,
            generation,
        };
    }

    #[test]
    fn a_gone_branch_is_asked_about_first_and_n_goes_on_with_the_landing() {
        let landing = waiting_landing();
        ask_about(&landing);
        let asked = landing.desk.view().unwrap();
        assert_eq!(
            asked.body,
            "The last landing's branch is gone from up. If its pull request was closed without a \
             merge, its changes can land again."
        );
        assert_eq!(
            asked.hint,
            "y lands them again  n they were merged  Esc cancels"
        );
        assert!(landing.desk.is_busy());
        landing.desk.confirm();
        assert_eq!(landing.desk.view().unwrap().hint, asked.hint);
        landing.desk.merged();
        let confirmation = landing.desk.view().unwrap();
        assert_eq!(confirmation.hint, "Enter pushes  Esc cancels");
        assert_ne!(confirmation.generation, asked.generation);
        assert!(
            confirmation
                .body
                .contains("Retry failed requests in the client")
        );
        assert_eq!(crate::note::take(&landing.note).unwrap(), None);
    }

    #[test]
    fn n_is_remembered_so_the_next_landing_does_not_ask_again() {
        let landing = waiting_landing();
        let mut record = record_of(&landing, true);
        record.write(&landing.store, landing.thread).unwrap();
        ask_about(&landing);
        landing.desk.merged();
        record.answer = Some(Answer::Merged);
        let read = BranchRecord::read(&landing.store, landing.thread).unwrap();
        assert!(!read.asks());
        assert_eq!(read, record);
    }

    #[test]
    fn n_on_a_refused_landing_shows_the_refusal_and_tells_the_agent() {
        let landing = waiting_landing();
        *landing.desk.stage().unwrap() = Stage::Asking {
            merged: Err(landing::NOTHING_CHANGED.to_owned()),
            remote: "up".to_owned(),
            shown: true,
            generation: 3,
        };
        landing.desk.merged();
        let done = landing.desk.view().unwrap();
        assert_eq!(done.body, "nothing changed since the last landing");
        assert_eq!(done.hint, "Esc closes");
        assert!(!landing.desk.is_busy());
        let note = crate::note::take(&landing.note).unwrap().unwrap();
        assert!(
            note.contains("nothing changed since the last landing"),
            "{note}"
        );
    }

    #[test]
    fn y_marks_the_record_and_tells_the_agent_to_land_its_paths_again() {
        let landing = waiting_landing();
        let mut record = record_of(&landing, true);
        record.write(&landing.store, landing.thread).unwrap();
        ask_about(&landing);
        landing.desk.land_again();
        assert!(landing.desk.view().is_none());
        record.answer = Some(Answer::LandAgain);
        assert_eq!(
            BranchRecord::read(&landing.store, landing.thread),
            Some(record)
        );
        let note = crate::note::take(&landing.note).unwrap().unwrap();
        assert!(
            note.contains(
                "alice cancelled your landing: the last landing's pull request was closed without \
                 a merge, so its paths count as changed again; call land again with commits that \
                 place them."
            ),
            "{note}"
        );
        assert!(offer_again(&landing));
        landing.desk.land_again();
        assert_eq!(
            landing.desk.view().unwrap().hint,
            "Enter pushes  Esc cancels"
        );
    }

    #[test]
    fn y_after_the_branch_came_back_says_its_paths_do_not_land_again() {
        let landing = waiting_landing();
        let record = record_of(&landing, false);
        record.write(&landing.store, landing.thread).unwrap();
        ask_about(&landing);
        landing.desk.land_again();
        assert!(landing.desk.view().is_none());
        assert_eq!(
            BranchRecord::read(&landing.store, landing.thread),
            Some(record)
        );
        let note = crate::note::take(&landing.note).unwrap().unwrap();
        assert!(
            note.contains(
                "alice cancelled your landing: the last landing's branch is on up again, so its \
                 paths do not land again; call land again."
            ),
            "{note}"
        );
    }

    #[test]
    fn y_without_a_record_sends_the_plain_cancel_line() {
        let landing = waiting_landing();
        ask_about(&landing);
        landing.desk.land_again();
        assert!(landing.desk.view().is_none());
        assert_eq!(BranchRecord::read(&landing.store, landing.thread), None);
        let note = crate::note::take(&landing.note).unwrap().unwrap();
        assert!(
            note.contains("alice cancelled your landing; nothing was pushed."),
            "{note}"
        );
    }

    #[test]
    fn the_last_landing_asks_once_its_branch_is_gone_and_lands_from_its_start_after_y() {
        let (_dir, store) = repository_on_main();
        let key = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::OsRng,
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let started = crate::session::tests::start_with(&store, &key).unwrap();
        let store = Store::open(store.common_dir()).unwrap();
        let remote = unreachable_remote(&store, store.common_dir());
        let (lander, _desk) = lander_for(&started, &store);
        let store = Store::open(store.common_dir()).unwrap();
        let base = store.head_commit().unwrap();
        let base_tree = store.commit_tree(base).unwrap();
        let (measured, from) = (
            store
                .write_tree(&[(
                    "m",
                    mahi_store::EntryKind::Blob,
                    store.write_blob(b"m").unwrap(),
                )])
                .unwrap(),
            store
                .write_tree(&[(
                    "f",
                    mahi_store::EntryKind::Blob,
                    store.write_blob(b"f").unwrap(),
                )])
                .unwrap(),
        );
        let mut record = BranchRecord {
            remote: "up".to_owned(),
            branch: branch_of(started.thread),
            tip: base,
            landing: "main".to_owned(),
            worktree: Some(measured),
            from: Some(from),
            gone: false,
            answer: None,
        };
        let last = |record: &BranchRecord| {
            record.write(&store, started.thread).unwrap();
            let last = lander.last_landing(&store, &remote, base).unwrap();
            (last.measured, last.on_remote == OnRemote::Gone, last.ask)
        };
        assert_eq!(last(&record), (measured, false, false));
        record.gone = true;
        assert_eq!(last(&record), (measured, true, true));
        record.answer = Some(Answer::LandAgain);
        assert_eq!(last(&record), (from, true, false));
        record.answer = Some(Answer::Merged);
        assert_eq!(last(&record), (measured, true, false));
        record.from = None;
        record.answer = None;
        record.worktree = None;
        assert_eq!(last(&record), (base_tree, true, false));
    }

    pub(crate) fn offer_again(landing: &Landing) -> bool {
        let tree = landing.store.commit_tree(landing.tip).unwrap();
        landing.desk.offer(Pending {
            built: Built {
                landed: landing.landed,
                tip: landing.tip,
                worktree: tree,
                from: tree,
            },
            commits: vec![("Again".to_owned(), Vec::new())],
            title: "Again".to_owned(),
            description: String::new(),
            remote: unreachable_remote(&landing.store, landing.repo.path()),
            behind: Vec::new(),
        })
    }

    pub(crate) fn until_done(desk: &Desk) -> LandingView {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let view = desk.view().unwrap();
            if view.hint == CLOSES {
                return view;
            }
            assert!(Instant::now() < deadline, "the push never ended");
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn a_landing_shows_its_commits_and_pull_request_until_the_owner_cancels() {
        let landing = waiting_landing();
        let (desk, thread) = (&landing.desk, landing.thread);
        let view = desk.view().unwrap();
        assert_eq!(
            view.title,
            format!("Land thread {} on mahi/{thread}", thread.short())
        );
        assert_eq!(
            view.body,
            "  Retry failed requests in the client\n    src/client.rs\n    src/retry.rs\n  \
             Test the retry\n    tests/retry.rs\n\nPull request: Retry failed requests\n\nNot \
             merged yet, so not in this landing:\n  bob.claude  turn ended 0s ago\n"
        );
        assert_eq!(view.hint, "Enter pushes  Esc cancels");
        assert_eq!(desk.shown(), Some(1));
        assert!(desk.wants_open());
        assert!(!desk.wants_open());
        assert!(desk.is_busy());
        desk.cancel();
        assert!(desk.view().is_none());
        assert_eq!(
            note::take(&landing.note).unwrap().as_deref(),
            Some("alice cancelled your landing; nothing was pushed.")
        );
    }

    #[test]
    fn a_push_that_fails_says_why_and_leaves_no_branch_behind() {
        let landing = waiting_landing();
        let branch = format!("mahi/{}", landing.thread);
        landing.desk.confirm();
        assert!(
            landing
                .desk
                .view()
                .unwrap()
                .hint
                .starts_with("Pushing to up")
        );
        let view = until_done(&landing.desk);
        assert!(view.body.starts_with("Not pushed: "), "{}", view.body);
        assert!(landing.desk.wants_open());
        let line = note::take(&landing.note).unwrap().unwrap();
        assert!(line.starts_with("your landing was not pushed: "), "{line}");
        assert_eq!(landing.store.branch_tip(&branch).unwrap(), None);
        landing.desk.cancel();
        assert!(landing.desk.view().is_none());
        assert!(!landing.desk.is_busy());
    }

    #[test]
    fn a_branch_that_moved_since_the_last_landing_is_left_as_it_is() {
        let landing = waiting_landing();
        let branch = format!("mahi/{}", landing.thread);
        landing
            .store
            .move_branch(&branch, None, landing.tip, "elsewhere")
            .unwrap();
        let tree = landing.store.commit_tree(landing.tip).unwrap();
        let moved = landing.desk.push(
            &unreachable_remote(&landing.store, landing.repo.path()),
            Built {
                landed: landing.landed,
                tip: landing.tip,
                worktree: tree,
                from: tree,
            },
            "",
            &Arc::new(AtomicBool::new(false)),
        );
        assert!(moved.is_err());
        assert_eq!(
            landing.store.branch_tip(&branch).unwrap(),
            Some(landing.tip)
        );
    }

    #[test]
    fn only_a_push_the_remote_took_counts_and_the_others_say_why() {
        assert_eq!(refusal("up", "mahi/x", Pushed::Updated), None);
        assert_eq!(refusal("up", "mahi/x", Pushed::UpToDate), None);
        assert_eq!(
            refusal("up", "mahi/x", Pushed::Refused("hook declined".to_owned())).as_deref(),
            Some("up refused mahi/x: hook declined")
        );
        assert!(refusal("up", "mahi/x", Pushed::Behind).is_some());
        assert!(refusal("up", "mahi/x", Pushed::TooLarge(1)).is_some());
        assert!(refusal("up", "mahi/x", Pushed::Deferred).is_some());
        assert!(refusal("up", "mahi/x", Pushed::Unchecked(String::new())).is_some());
    }

    fn lander_for(started: &crate::session::Started, store: &Store) -> (Lander, Arc<Desk>) {
        let desk = Arc::new(Desk::new(
            (store.common_dir().to_path_buf(), started.thread),
            (
                ParticipantName::new("alice").unwrap(),
                PathBuf::from("/nonexistent/note"),
            ),
            "main".to_owned(),
        ));
        let home = store.common_dir().to_path_buf();
        let lander = Lander::new(
            (started.thread, started.slot.clone()),
            (
                crate::session::worktree_name(started.thread, started.slot.agent()),
                GlobalPatterns::default(),
            ),
            (
                (
                    Some("Alice".to_owned()),
                    Some("alice@example.com".to_owned()),
                ),
                (Reach::gather(&environment(&home)), Settings::default()),
                started.commits.clone(),
            ),
            (
                Arc::clone(&desk),
                AutoMerge {
                    git_dir: store.common_dir().to_path_buf(),
                    thread: started.thread,
                    owner: started.commits.key().clone(),
                    own: started.slot.clone(),
                    waiting: Arc::default(),
                },
            ),
        );
        (lander, desk)
    }

    fn call(paths: &[&str]) -> Map<String, Value> {
        let Value::Object(arguments) = serde_json::json!({
            "commits": [{ "message": "Add", "paths": paths }],
            "title": "t",
            "description": "d"
        }) else {
            panic!("the arguments are an object");
        };
        arguments
    }

    #[test]
    fn the_tool_answers_before_it_builds_when_it_cannot_land_yet() {
        let (_dir, store) = repository_on_main();
        let key = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::OsRng,
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let started = crate::session::tests::start_with(&store, &key).unwrap();
        let store = Store::open(store.common_dir()).unwrap();
        unreachable_remote(&store, store.common_dir());
        let (lander, desk) = lander_for(&started, &store);
        let store = Store::open(store.common_dir()).unwrap();
        let base = store.head_commit().unwrap();
        let land = |paths: &[&str]| lander.land(&store, &call(paths), (base, &[])).unwrap();
        assert_eq!(land(&["a.txt"]), landing::NOTHING_CHANGED);
        let Value::Object(escaped) = serde_json::json!({
            "commits": [{ "message": "Add", "paths": [] }, { "message": "Fix\u{1b}[2J", "paths": [] }],
            "title": "t",
            "description": "d"
        }) else {
            panic!("the arguments are an object");
        };
        assert_eq!(
            lander.land(&store, &escaped, (base, &[])).unwrap(),
            "not landed: the message of commit 2 holds control characters; write it without them"
        );
        let Value::Object(reordered) = serde_json::json!({
            "commits": [{ "message": "Add\u{202E}txt", "paths": [] }],
            "title": "t",
            "description": "d"
        }) else {
            panic!("the arguments are an object");
        };
        assert_eq!(
            lander.land(&store, &reordered, (base, &[])).unwrap(),
            "not landed: the message of commit 1 holds invisible or text direction characters; \
             write it without them"
        );

        fs::write(
            started.worktree.join("a.txt"),
            "a\n<<<<<<< mahi bob.claude\n",
        )
        .unwrap();
        let conflicts = conflicts::file(&store, started.thread, &started.slot);
        let kept = conflicts::KeptConflicts::of_merge(
            (
                &"bob.claude".parse().unwrap(),
                store.commit_tree(base).unwrap(),
            ),
            ["a.txt".to_owned()].iter(),
        )
        .unwrap();
        kept.save(&conflicts).unwrap();
        assert_eq!(land(&[]), landing::conflicts_first(&["a.txt".to_owned()]));

        fs::write(started.worktree.join("a.txt"), "a\n").unwrap();
        assert!(land(&[]).starts_with("not landed: each changed path goes in exactly one commit"));
        assert_eq!(desk.shown(), None);
        assert_eq!(
            land(&["a.txt"]),
            landing::waiting(started.slot.participant())
        );
        assert_eq!(desk.shown(), Some(1));
        let tip = store.branch_tip(&branch_of(started.thread)).unwrap();
        assert_eq!(
            land(&["a.txt"]),
            landing::waiting(started.slot.participant())
        );
        assert_eq!(desk.shown(), Some(1));
        assert_eq!(store.branch_tip(&branch_of(started.thread)).unwrap(), tip);
    }

    #[test]
    fn the_confirmation_lists_the_deleted_names_that_are_not_utf8_under_the_last_commit() {
        let (dir, store) = repository_on_main();
        let remote = unreachable_remote(&store, dir.path());
        let head = store.head_commit().unwrap();
        let mut call = landing::parse(&call(&["a.txt"])).unwrap();
        call.commits.push(landing::Planned {
            message: "Rename old\n\nWhy.".to_owned(),
            paths: vec!["old.txt".to_owned()],
        });
        let shown = pending(
            Built {
                landed: head,
                tip: head,
                worktree: head,
                from: head,
            },
            (call, &[b"old\xff".to_vec()]),
            (remote, Vec::new()),
        );
        assert_eq!(
            shown.commits.last().unwrap(),
            &(
                "Rename old".to_owned(),
                vec![
                    "old.txt".to_owned(),
                    "old\u{fffd} (deleted, name not UTF-8)".to_owned()
                ]
            )
        );
        assert_eq!(shown.commits.first().unwrap().1, ["a.txt"]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_worktree_file_whose_name_is_not_utf8_is_refused_before_the_landing_is_built() {
        let (_dir, store) = repository_on_main();
        let key = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::OsRng,
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let started = crate::session::tests::start_with(&store, &key).unwrap();
        let store = Store::open(store.common_dir()).unwrap();
        unreachable_remote(&store, store.common_dir());
        let (lander, _desk) = lander_for(&started, &store);
        let store = Store::open(store.common_dir()).unwrap();
        let base = store.head_commit().unwrap();
        fs::write(started.worktree.join("a.txt"), "a\n").unwrap();
        let odd = OsStr::from_bytes(b"caf\xe9.txt");
        fs::write(started.worktree.join(odd), "caf\n").unwrap();
        assert_eq!(
            lander.land(&store, &call(&["a.txt"]), (base, &[])).unwrap(),
            "not landed: rename these files, whose names are not UTF-8: caf\u{fffd}.txt"
        );
    }

    #[test]
    fn a_landing_starts_from_the_branch_last_pushed_or_from_the_remote_once_the_forge_deleted_it_there()
     {
        let (_dir, store) = repository_on_main();
        let key = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::OsRng,
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let started = crate::session::tests::start_with(&store, &key).unwrap();
        let store = Store::open(store.common_dir()).unwrap();
        unreachable_remote(&store, store.common_dir());
        let (lander, _desk) = lander_for(&started, &store);
        let store = Store::open(store.common_dir()).unwrap();
        let base = store.head_commit().unwrap();
        fs::write(started.worktree.join("a.txt"), "a\n").unwrap();
        let worktree = lander.snapshot(&store).unwrap();
        let pushed_tip = store
            .append(
                &ThreadRef::new(ThreadId::random().unwrap(), RefKind::Meta),
                None,
                worktree,
                "landed",
            )
            .unwrap();
        let mut record = BranchRecord {
            remote: "up".to_owned(),
            branch: branch_of(started.thread),
            tip: pushed_tip,
            landing: "main".to_owned(),
            worktree: None,
            from: None,
            gone: false,
            answer: None,
        };
        record.write(&store, started.thread).unwrap();
        let land = |paths: &[&str]| lander.land(&store, &call(paths), (base, &[])).unwrap();
        assert_eq!(land(&["a.txt"]), landing::NOTHING_CHANGED);
        record.gone = true;
        record.write(&store, started.thread).unwrap();
        assert_eq!(land(&["a.txt"]), landing::NOTHING_CHANGED);
        fs::write(started.worktree.join("b.txt"), "b\n").unwrap();
        let Err(ToolError::Failed(unreached)) = lander.land(&store, &call(&["b.txt"]), (base, &[]))
        else {
            panic!("the landing reaches the remote for its landing branch");
        };
        assert!(
            unreached.starts_with("cannot reach the remote: "),
            "{unreached}"
        );
        record.remote = "other".to_owned();
        record.write(&store, started.thread).unwrap();
        assert_eq!(
            land(&["a.txt", "b.txt"]),
            landing::waiting(started.slot.participant())
        );
    }

    #[test]
    fn a_landing_measures_from_the_worktree_tree_the_last_one_recorded_or_its_tip() {
        let (_dir, store) = repository_on_main();
        let key = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::OsRng,
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let started = crate::session::tests::start_with(&store, &key).unwrap();
        let store = Store::open(store.common_dir()).unwrap();
        unreachable_remote(&store, store.common_dir());
        let (lander, desk) = lander_for(&started, &store);
        let store = Store::open(store.common_dir()).unwrap();
        let base = store.head_commit().unwrap();
        let base_tree = store.commit_tree(base).unwrap();
        fs::write(started.worktree.join("m.txt"), "m\n").unwrap();
        let measured = lander.snapshot(&store).unwrap();
        let mut record = BranchRecord {
            remote: "up".to_owned(),
            branch: branch_of(started.thread),
            tip: base,
            landing: "main".to_owned(),
            worktree: Some(measured),
            from: None,
            gone: false,
            answer: None,
        };
        record.write(&store, started.thread).unwrap();
        fs::write(started.worktree.join("a.txt"), "a\n").unwrap();
        let from = |paths: &[&str]| {
            lander.land(&store, &call(paths), (base, &[])).unwrap();
            let Stage::Waiting { pending, .. } =
                std::mem::replace(&mut *desk.stage().unwrap(), Stage::Idle)
            else {
                panic!("the landing waits for the owner");
            };
            pending.built.from
        };
        assert_eq!(from(&["a.txt"]), measured);
        record.worktree = None;
        record.write(&store, started.thread).unwrap();
        assert_eq!(from(&["a.txt", "m.txt"]), base_tree);
    }

    pub(crate) fn done_with_clipboard(desk: &Desk, copied: &str) {
        *desk.stage().unwrap() = Stage::Done {
            text: "Pushed 1 commit on mahi/x to up.".to_owned(),
            shown: false,
            generation: 9,
            clipboard: Some(copied.to_owned()),
        };
    }

    #[test]
    fn the_outcome_says_where_the_description_is_and_whether_it_was_copied() {
        let file = PathBuf::from("/state/PR.md");
        let landed = |kept: Kept, link: Option<&str>, unremembered: Option<&str>| Landed {
            unremembered: unremembered.map(str::to_owned),
            kept,
            link: link.map(str::to_owned),
        };
        let shown = |landed: &Landed, copied| pushed_text((2, "mahi/x", "up"), landed, copied);
        assert_eq!(
            shown(
                &landed(
                    Ok(file.clone()),
                    Some("https://forge.example/pull/new/mahi/x"),
                    None
                ),
                true
            ),
            "Pushed 2 commits on mahi/x to up.\nOpen the pull request: https://forge.example/pull/new/mahi/x\nIts description is in /state/PR.md and on your clipboard."
        );
        assert_eq!(
            shown(&landed(Ok(file.clone()), None, None), false),
            "Pushed 2 commits on mahi/x to up.\nIts description is in /state/PR.md."
        );
        assert_eq!(
            pushed_text(
                (1, "mahi/x", "up"),
                &landed(
                    Err((file, "denied".to_owned())),
                    None,
                    Some("cannot remember the pushed branch: disk full")
                ),
                true
            ),
            "Pushed 1 commit on mahi/x to up.\ncannot keep the pull request draft in /state/PR.md: denied\ncannot remember the pushed branch: disk full"
        );
    }

    #[test]
    fn a_description_is_copied_only_up_to_64_kib() {
        let most = "a".repeat(MOST_COPIED);
        assert_eq!(copied(&most).as_deref(), Some(most.as_str()));
        assert_eq!(copied(&format!("{most}a")), None);
        assert_eq!(copied("").as_deref(), Some(""));
    }

    #[test]
    fn the_description_is_kept_in_the_threads_state_without_control_characters() {
        let landing = waiting_landing();
        let file = landing
            .desk
            .keep_description(
                &landing.store,
                &landing::printable("Why\u{1b}[31m.\n\tAnd\u{200b} how."),
            )
            .unwrap();
        assert_eq!(
            file,
            crate::session::state_root(&landing.store, landing.thread)
                .join("landing")
                .join("PR.md")
        );
        assert_eq!(fs::read_to_string(&file).unwrap(), "Why[31m.\n\tAnd how.");
        done_with_clipboard(&landing.desk, "Why.");
        assert_eq!(landing.desk.take_clipboard().as_deref(), Some("Why."));
        assert_eq!(landing.desk.take_clipboard(), None);
    }

    #[test]
    fn a_turn_end_is_dated_from_when_its_commit_was_first_seen() {
        let seen = FirstSeen::default();
        let bob: AgentSlot = "bob.claude".parse().unwrap();
        let (first, later) = (
            ObjectId::from_bytes_or_panic(&[1; 20]),
            ObjectId::from_bytes_or_panic(&[2; 20]),
        );
        let noted = seen.note(&bob, first);
        thread::sleep(Duration::from_millis(10));
        assert_eq!(seen.note(&bob, first), noted);
        assert!(seen.note(&bob, later) > noted);
        assert_eq!(seen.0.lock().unwrap().len(), 1);
    }

    #[test]
    fn a_remote_chosen_after_the_run_started_is_used_at_the_next_call() {
        let (_dir, store) = repository_on_main();
        let key = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::OsRng,
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let started = crate::session::tests::start_with(&store, &key).unwrap();
        let (lander, _desk) = lander_for(&started, &store);
        let base = store.head_commit().unwrap();
        let land = |store: &Store| lander.land(store, &call(&["a.txt"]), (base, &[])).unwrap();
        let owner = started.slot.participant();
        assert_eq!(land(&store), landing::no_remote(owner));
        unreachable_remote(&store, store.common_dir());
        let store = Store::open(store.common_dir()).unwrap();
        assert_eq!(land(&store), landing::NOTHING_CHANGED);
    }

    #[test]
    fn a_new_landing_counts_as_another_once_the_last_one_is_done() {
        let landing = waiting_landing();
        landing.desk.confirm();
        until_done(&landing.desk);
        assert_eq!(landing.desk.shown(), Some(1));
        assert!(offer_again(&landing));
        assert_eq!(landing.desk.shown(), Some(2));
        landing.desk.cancel();
        assert!(offer_again(&landing));
        assert_eq!(landing.desk.shown(), Some(3));
    }
}
