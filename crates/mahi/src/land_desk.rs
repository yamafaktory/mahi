use std::{
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
    },
    thread,
    time::Duration,
};

use mahi_core::{
    AgentSlot,
    ParticipantName,
    ThreadId,
};
use mahi_store::{
    GlobalPatterns,
    Identity,
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
    conflicts,
    landed_branch::BranchRecord,
    landing::{
        self,
        Call,
    },
    mcp::ToolError,
    note,
    session::CommitKey,
    sync::SyncSetup,
};

const SNAPSHOT_ATTEMPTS: usize = 3;
const PUSH_WAIT: Duration = Duration::from_secs(180);
const PUSHES: &str = "Enter pushes  Esc cancels";
const CLOSES: &str = "Esc closes";
const DESCRIPTION_FILE: &str = "PR.md";
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

pub(crate) struct Pending {
    landed: ObjectId,
    tip: ObjectId,
    commits: Vec<(String, Vec<String>)>,
    title: String,
    description: String,
    remote: SyncSetup,
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
        let Some(mut stage) = self.stage() else {
            return false;
        };
        if matches!(*stage, Stage::Waiting { .. } | Stage::Pushing { .. }) {
            return false;
        }
        let generation = self.offers.fetch_add(1, Ordering::SeqCst) + 1;
        *stage = Stage::Waiting {
            pending,
            shown: false,
            generation,
        };
        true
    }

    fn is_busy(&self) -> bool {
        self.stage()
            .is_none_or(|stage| matches!(*stage, Stage::Waiting { .. } | Stage::Pushing { .. }))
    }

    pub(crate) fn wants_open(&self) -> bool {
        let Some(mut stage) = self.stage() else {
            return false;
        };
        match &mut *stage {
            Stage::Waiting { shown, .. } | Stage::Done { shown, .. } if !*shown => {
                *shown = true;
                true
            }
            Stage::Idle | Stage::Waiting { .. } | Stage::Pushing { .. } | Stage::Done { .. } => {
                false
            }
        }
    }

    pub(crate) fn shown(&self) -> Option<u64> {
        let stage = self.stage()?;
        match &*stage {
            Stage::Idle => None,
            Stage::Waiting { generation, .. }
            | Stage::Pushing { generation, .. }
            | Stage::Done { generation, .. } => Some(*generation),
        }
    }

    pub(crate) fn view(&self) -> Option<LandingView> {
        let stage = self.stage()?;
        match &*stage {
            Stage::Idle => None,
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
        let Stage::Waiting {
            mut pending,
            generation,
            ..
        } = std::mem::replace(&mut *stage, Stage::Idle)
        else {
            return;
        };
        let (landed, tip, count) = (pending.landed, pending.tip, pending.commits.len());
        let remote = pending.remote.clone();
        let description = std::mem::take(&mut pending.description);
        *stage = Stage::Pushing {
            pending,
            generation,
        };
        drop(stage);
        let desk = Arc::clone(self);
        thread::spawn(move || {
            let interrupt = Arc::new(AtomicBool::new(false));
            let stopping = Arc::clone(&interrupt);
            thread::spawn(move || {
                thread::sleep(PUSH_WAIT);
                stopping.store(true, Ordering::SeqCst);
            });
            let pushed = desk.push(&remote, (landed, tip), &description, &interrupt);
            desk.finish((&remote, count, &description), &pushed, generation);
        });
    }

    pub(crate) fn cancel(&self) {
        let Some(mut stage) = self.stage() else {
            return;
        };
        match &*stage {
            Stage::Waiting { .. } => {
                *stage = Stage::Idle;
                drop(stage);
                let line = format!("{} cancelled your landing; nothing was pushed.", self.owner);
                let _ = note::record_landing(&self.note, &line);
            }
            Stage::Done { .. } => *stage = Stage::Idle,
            Stage::Idle | Stage::Pushing { .. } => {}
        }
    }

    pub(crate) fn take_clipboard(&self) -> Option<String> {
        let mut stage = self.stage()?;
        match &mut *stage {
            Stage::Done { clipboard, .. } => clipboard.take(),
            Stage::Idle | Stage::Waiting { .. } | Stage::Pushing { .. } => None,
        }
    }

    fn keep_description(&self, store: &Store, description: &str) -> Kept {
        let file = crate::session::state_root(store, self.thread).join(DESCRIPTION_FILE);
        crate::sync_state::write(&file, description.as_bytes())
            .map(|()| file.clone())
            .map_err(|error| (file, error.to_string()))
    }

    fn push(
        &self,
        remote: &SyncSetup,
        (landed, tip): (ObjectId, ObjectId),
        description: &str,
        interrupt: &Arc<AtomicBool>,
    ) -> Result<(Option<String>, Kept), String> {
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
                    .push_branch_within(transport, &branch, remote.push_limit, interrupt)
                    .map_err(|error| described(&error))
            })
            .and_then(|pushed| {
                refusal(&remote.name.to_string(), &branch, pushed).map_or(Ok(()), Err)
            });
        if let Err(reason) = pushed {
            let _ = match current {
                Some(current) => store.move_branch(&branch, Some(tip), current, "mahi land"),
                None => store.delete_branch(&branch, tip),
            };
            return Err(reason);
        }
        let record = BranchRecord {
            remote: remote.name.to_string(),
            branch,
            tip,
            landing: self.landing.clone(),
            gone: false,
        };
        let unremembered = record
            .write(&store, self.thread)
            .err()
            .map(|error| format!("cannot remember the pushed branch: {error}"));
        Ok((unremembered, self.keep_description(&store, description)))
    }

    fn finish(
        &self,
        (remote, count, description): (&SyncSetup, usize, &str),
        pushed: &Result<(Option<String>, Kept), String>,
        generation: u64,
    ) {
        let branch = branch_of(self.thread);
        let remote = remote.name.to_string();
        let clipboard = match pushed {
            Ok((_, Ok(_))) => copied(description),
            Ok((_, Err(_))) | Err(_) => None,
        };
        let (line, text) = match pushed {
            Ok((unremembered, kept)) => {
                let mut line = format!(
                    "{} pushed your landing: {} on {branch} to {remote}.",
                    self.owner,
                    commits(count)
                );
                if let Some(unremembered) = unremembered {
                    line.push('\n');
                    line.push_str(unremembered);
                }
                let text = pushed_text(
                    (count, &branch, &remote),
                    unremembered.as_deref(),
                    kept,
                    clipboard.is_some(),
                );
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

fn copied(description: &str) -> Option<String> {
    (description.len() <= MOST_COPIED).then(|| description.to_owned())
}

fn pushed_text(
    (count, branch, remote): (usize, &str, &str),
    unremembered: Option<&str>,
    kept: &Kept,
    copied: bool,
) -> String {
    let mut text = format!("Pushed {} on {branch} to {remote}.", commits(count));
    if let Some(unremembered) = unremembered {
        text.push('\n');
        text.push_str(unremembered);
    }
    match (kept, copied) {
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

fn branch_of(thread: ThreadId) -> String {
    format!("mahi/{thread}")
}

pub(crate) type GitIdentity = (Option<String>, Option<String>);
pub(crate) type ChosenRemote = Result<Option<SyncSetup>, String>;

pub(crate) struct Lander {
    thread: ThreadId,
    me: AgentSlot,
    worktree: String,
    globals: GlobalPatterns,
    identity: GitIdentity,
    remote: ChosenRemote,
    commits: CommitKey,
    desk: Arc<Desk>,
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
        (identity, remote, commits): (GitIdentity, ChosenRemote, CommitKey),
        desk: Arc<Desk>,
    ) -> Self {
        Self {
            thread,
            me,
            worktree,
            globals,
            identity,
            remote,
            commits,
            desk,
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
        let remote = match &self.remote {
            Ok(Some(remote)) => remote.clone(),
            Ok(None) => return Ok(landing::no_remote(owner)),
            Err(reason) => return Err(ToolError::Failed(reason.clone())),
        };
        let failed = |error: &StoreError| ToolError::Failed(crate::describe(error));
        let worktree = self.snapshot(store).map_err(|error| failed(&error))?;
        if let Some(paths) = self.unresolved(store, worktree) {
            return Ok(landing::conflicts_first(&paths));
        }
        let branch = branch_of(self.thread);
        let landed = BranchRecord::read(store, self.thread)
            .filter(|record| !record.gone && record.branch == branch)
            .map_or(base, |record| record.tip);
        let landed_tree = store.commit_tree(landed).map_err(|error| failed(&error))?;
        let Some(changed) =
            landing::changed(store, (landed_tree, worktree)).map_err(|error| failed(&error))?
        else {
            return Ok(landing::TOO_MANY.to_owned());
        };
        if changed.is_empty() {
            return Ok(landing::NOTHING_CHANGED.to_owned());
        }
        if let Err(misplaced) = landing::check(&call, &changed) {
            return Ok(misplaced.text());
        }
        let agents = crate::threads::thread_agents(store, self.thread)
            .map_err(|error| failed(&error))?
            .into_iter()
            .filter(|slot| collaborators.contains(slot.participant()))
            .collect::<Vec<_>>();
        let identity = Identity::now(name.clone(), email.clone());
        let built = landing::build(
            store,
            (landed, worktree),
            &call,
            (self.thread, &agents),
            (&identity, self.commits.signer()),
        )
        .map_err(|error| failed(&error))?;
        let Some(&tip) = built.last() else {
            return Ok(landing::NOTHING_CHANGED.to_owned());
        };
        let pending = pending((landed, tip), call, remote);
        let _offered = self.desk.offer(pending);
        Ok(landing::waiting(owner))
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

fn pending((landed, tip): (ObjectId, ObjectId), call: Call, remote: SyncSetup) -> Pending {
    let commits = call
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
    Pending {
        landed,
        tip,
        commits,
        title: call.title,
        description: landing::printable(&call.description),
        remote,
    }
}

#[cfg(test)]
pub(crate) mod tests {
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
        let environment = Environment {
            ssh_auth_sock: Some(home.join("agent.sock")),
            user: Some("tester".to_owned()),
            home: Some(home.to_path_buf()),
            ..Environment::default()
        };
        SyncSetup::chosen(&store, &environment, true)
            .unwrap()
            .unwrap()
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
            landed,
            tip,
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

    pub(crate) fn offer_again(landing: &Landing) -> bool {
        landing.desk.offer(Pending {
            landed: landing.landed,
            tip: landing.tip,
            commits: vec![("Again".to_owned(), Vec::new())],
            title: "Again".to_owned(),
            description: String::new(),
            remote: unreachable_remote(&landing.store, landing.repo.path()),
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
             Test the retry\n    tests/retry.rs\n\nPull request: Retry failed requests\n"
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
        let moved = landing.desk.push(
            &unreachable_remote(&landing.store, landing.repo.path()),
            (landing.landed, landing.tip),
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
                Ok(Some(unreachable_remote(store, &home))),
                started.commits.clone(),
            ),
            Arc::clone(&desk),
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
        let (lander, desk) = lander_for(&started, &store);
        let base = store.head_commit().unwrap();
        let land = |paths: &[&str]| lander.land(&store, &call(paths), (base, &[])).unwrap();
        assert_eq!(land(&["a.txt"]), landing::NOTHING_CHANGED);

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
    fn a_landing_starts_from_the_branch_last_pushed_unless_the_forge_deleted_it() {
        let (_dir, store) = repository_on_main();
        let key = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::OsRng,
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let started = crate::session::tests::start_with(&store, &key).unwrap();
        let store = Store::open(store.common_dir()).unwrap();
        let (lander, _desk) = lander_for(&started, &store);
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
            gone: false,
        };
        record.write(&store, started.thread).unwrap();
        let land = |paths: &[&str]| lander.land(&store, &call(paths), (base, &[])).unwrap();
        assert_eq!(land(&["a.txt"]), landing::NOTHING_CHANGED);
        record.gone = true;
        record.write(&store, started.thread).unwrap();
        assert_eq!(
            land(&["a.txt"]),
            landing::waiting(started.slot.participant())
        );
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
        let shown = |kept: &Kept, copied| pushed_text((2, "mahi/x", "up"), None, kept, copied);
        assert_eq!(
            shown(&Ok(file.clone()), true),
            "Pushed 2 commits on mahi/x to up.\nIts description is in /state/PR.md and on your clipboard."
        );
        assert_eq!(
            shown(&Ok(file.clone()), false),
            "Pushed 2 commits on mahi/x to up.\nIts description is in /state/PR.md."
        );
        assert_eq!(
            pushed_text(
                (1, "mahi/x", "up"),
                Some("cannot remember the pushed branch: disk full"),
                &Err((file, "denied".to_owned())),
                true
            ),
            "Pushed 1 commit on mahi/x to up.\ncannot remember the pushed branch: disk full\ncannot keep the pull request draft in /state/PR.md: denied"
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
            crate::session::state_root(&landing.store, landing.thread).join("PR.md")
        );
        assert_eq!(fs::read_to_string(&file).unwrap(), "Why[31m.\n\tAnd how.");
        done_with_clipboard(&landing.desk, "Why.");
        assert_eq!(landing.desk.take_clipboard().as_deref(), Some("Why."));
        assert_eq!(landing.desk.take_clipboard(), None);
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
