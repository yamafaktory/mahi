use std::{
    collections::HashSet,
    sync::atomic::AtomicBool,
};

use mahi_core::{
    AgentSlot,
    ThreadRef,
};
use mahi_store::{
    Applied,
    Conflict,
    GlobalPatterns,
    MAX_MERGED_PATHS,
    Merged,
    ObjectId,
    SnapshotCache,
    Store,
    StoreError,
};
use thiserror::Error;

use crate::{
    conflicts::{
        self,
        ConflictsError,
        KeptConflicts,
    },
    held::{
        self,
        HeldError,
        HeldSettings,
    },
    merged::MergedFrom,
    note,
    session::CommitKey,
    settings_links,
    source::{
        LandingBranch,
        Source,
    },
};

const SNAPSHOT_ATTEMPTS: usize = 3;
const AGENT_SETTINGS: [&str; 7] = [
    "CLAUDE.md",
    "CLAUDE.local.md",
    "AGENTS.md",
    "AGENTS.override.md",
    ".claude",
    ".mcp.json",
    ".codex",
];

#[derive(Debug, Error)]
pub(crate) enum MergeError {
    #[error("cannot open the git repository")]
    Store(#[from] StoreError),
    #[error("{0} merged from more agents than mahi records")]
    TooManySources(AgentSlot),
    #[error("the merge from {} changes agent settings, which wait for the user", .0.named())]
    HoldsAgentSettings(Source),
    #[error(transparent)]
    Held(#[from] HeldError),
    #[error(
        "{0} holds conflict markers from a merge and takes no other merge until they are resolved"
    )]
    MarkersUnresolved(AgentSlot),
    #[error(transparent)]
    Conflicts(#[from] ConflictsError),
    #[error("the agent's mahi stopped recording before it could merge")]
    RecorderGone,
}

/// What a merge brings into an agent's worktree: the latest snapshot of the agent `from`,
/// already checked to be signed by the key the thread lists for it, and the thread's base.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct MergeRequest {
    pub(crate) from: AgentSlot,
    pub(crate) commit: ObjectId,
    pub(crate) thread_base: ObjectId,
}

/// Where a merge writes: the agent's slot, worktree and snapshots, and how its snapshots are
/// taken and signed.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Recording<'a> {
    pub(crate) slot: &'a AgentSlot,
    pub(crate) worktree: &'a str,
    pub(crate) snapshots: &'a ThreadRef,
    pub(crate) globals: &'a GlobalPatterns,
    pub(crate) commits: &'a CommitKey,
}

/// What a merge did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MergeDone {
    /// The agent already has the requested snapshot; nothing changed.
    Already,
    /// The merge was written and recorded in the snapshot `commit` of the tree `tree`, leaving
    /// some paths of the worktree as they were or none.
    Merged {
        commit: ObjectId,
        tree: ObjectId,
        left: PathsLeft,
    },
}

/// Whether a merge may write the paths an agent reads as its settings or instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AgentSettings {
    /// Write them, as the user's take of a held snapshot does.
    Take,
    /// Refuse the whole merge, before it writes anything, when it would change one.
    Hold,
}

/// Merges `request` into `into`'s worktree, whose snapshots are at `head` and remembered in
/// `cache`, from the base [`merge_base`] gives, unless the worktree still holds the conflict
/// markers of a merge before, or `settings` holds a merge that changes agent settings; keeps
/// the paths it leaves with markers in the agent's state before it writes them, with the tree
/// of `head`, which the agent's snapshots keep; then takes a
/// snapshot whose trailers name
/// `request.commit` and what that snapshot had itself merged, or, when the merge left a path as
/// it was, the trailers it had before, so the next merge starts from the same base. Once the
/// worktree is written, the snapshot is taken even if `interrupt` is set, so the written files
/// are never left out of the agent's snapshots.
pub(crate) fn merge_now(
    store: &Store,
    into: Recording<'_>,
    (request, settings): (&MergeRequest, AgentSettings),
    (cache, head): (&mut SnapshotCache, Option<ObjectId>),
    interrupt: &AtomicBool,
) -> Result<MergeDone, MergeError> {
    let previous = MergedFrom::read(store, into.snapshots)?;
    let mut merged_from = previous.clone();
    let theirs = merged_by(store, request.commit);
    let own = head.map(|head| (into.slot, head));
    let base = merge_base(store, (&merged_from, own), (request, &theirs))?;
    let skipped = held::skipped_file(store, into.snapshots.thread(), (into.slot, &request.from));
    let base = match held::skipped(&skipped) {
        Some(skipped)
            if skip_is_base(store, skipped, (merged_from.of(&request.from), request))? =>
        {
            skipped
        }
        _ => base,
    };
    if base == request.commit {
        held::release_merged(store, into.snapshots.thread(), into.slot, &merged_from);
        return Ok(MergeDone::Already);
    }
    if !merged_from.record(request.from.clone(), request.commit) {
        return Err(MergeError::TooManySources(into.slot.clone()));
    }
    merged_from.absorb(store, (&theirs, into.snapshots.thread()), Some(into.slot));
    let (base, theirs) = (store.commit_tree(base)?, store.commit_tree(request.commit)?);
    let source = Source::Agent(request.from.clone());
    let done = merge_into(
        store,
        into,
        ((&source, request.commit), (base, theirs), settings),
        (&previous, &merged_from),
        (cache, head),
        interrupt,
    )?;
    if let MergeDone::Merged {
        left: PathsLeft::None,
        ..
    } = done
    {
        held::release_merged(store, into.snapshots.thread(), into.slot, &merged_from);
    }
    Ok(done)
}

/// Merges into `into`'s worktree what the landing on `landing`'s tip `tip` brought, from the
/// tree `measured` of the worktree that landing measured, as [`merge_now`] merges a teammate's
/// snapshot: refused while the worktree holds the markers of a merge before, or, unless
/// `settings` takes them, when it changes agent settings; its markers labelled with the
/// landing branch, and its snapshot keeping the trailers the agent's snapshots had.
pub(crate) fn merge_landing_now(
    store: &Store,
    into: Recording<'_>,
    ((landing, measured, tip), settings): ((&LandingBranch, ObjectId, ObjectId), AgentSettings),
    (cache, head): (&mut SnapshotCache, Option<ObjectId>),
    interrupt: &AtomicBool,
) -> Result<MergeDone, MergeError> {
    let previous = MergedFrom::read(store, into.snapshots)?;
    let source = Source::Landing(landing.clone());
    let theirs = store.commit_tree(tip)?;
    merge_into(
        store,
        into,
        ((&source, tip), (measured, theirs), settings),
        (&previous, &previous),
        (cache, head),
        interrupt,
    )
}

/// Whether a merge left some paths of the worktree as they were.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathsLeft {
    None,
    Some,
}

/// Merges the tree `theirs` from `from`, whose commit is `commit`, into `into`'s worktree from
/// the tree `base`, keeps the conflicts, writes the worktree, records it in a snapshot with the
/// trailers of `merged_from`, or of `previous` when a path was left as it was, and adds the
/// merge to the agent's note.
fn merge_into(
    store: &Store,
    into: Recording<'_>,
    ((from, commit), (base, theirs), settings): (
        (&Source, ObjectId),
        (ObjectId, ObjectId),
        AgentSettings,
    ),
    (previous, merged_from): (&MergedFrom, &MergedFrom),
    (cache, head): (&mut SnapshotCache, Option<ObjectId>),
    interrupt: &AtomicBool,
) -> Result<MergeDone, MergeError> {
    let ours = snapshot(store, into.worktree, (into.globals, cache), interrupt)?;
    let kept = conflicts::file(store, into.snapshots.thread(), into.slot);
    if !conflicts::resolved(store, into.slot, &kept, ours)? {
        return Err(MergeError::MarkersUnresolved(into.slot.clone()));
    }
    let labels = (conflicts::label(into.slot), from.label());
    let merged = store.merge_trees(base, ours, theirs, (&labels.0, &labels.1))?;
    let waiting = held::file_for(store, into.snapshots.thread(), (into.slot, from));
    let compared = [(ours, merged.tree), (base, theirs)];
    if settings == AgentSettings::Hold
        && let Some(paths) = agent_settings_changed(store, ours, compared)
    {
        HeldSettings::new(commit, &paths).keep(&waiting)?;
        return Err(MergeError::HoldsAgentSettings(from.clone()));
    }
    let markers = merged
        .conflicts
        .iter()
        .filter(|(_, conflict)| *conflict == Conflict::Markers)
        .map(|(path, _)| path);
    let before = match head {
        Some(head) => store.commit_tree(head)?,
        None => store.write_tree(&[])?,
    };
    if let Some(conflicts) = KeptConflicts::of_merge((from, before), markers) {
        conflicts.save(&kept)?;
    }
    let (applied, tree, written) = write_merge(
        store,
        into,
        (ours, merged.tree),
        (previous, merged_from),
        (cache, head),
        interrupt,
    )?;
    let left = if applied.left.is_empty() {
        PathsLeft::None
    } else {
        PathsLeft::Some
    };
    note_merge(store, into, (from, &merged), (ours, tree));
    Ok(MergeDone::Merged {
        commit: written,
        tree,
        left,
    })
}

/// Writes the tree `merged` into `into`'s worktree over `ours`, then records the worktree in a
/// snapshot after `head` with the trailers of `merged_from`, or of `previous` when a path was
/// left as it was; returns what was written, the snapshot's tree and its commit.
fn write_merge(
    store: &Store,
    into: Recording<'_>,
    (ours, merged): (ObjectId, ObjectId),
    (previous, merged_from): (&MergedFrom, &MergedFrom),
    (cache, head): (&mut SnapshotCache, Option<ObjectId>),
    interrupt: &AtomicBool,
) -> Result<(Applied, ObjectId, ObjectId), StoreError> {
    let applied = store.apply_merge(into.worktree, ours, merged, interrupt)?;
    let tree = snapshot(
        store,
        into.worktree,
        (into.globals, cache),
        &AtomicBool::new(false),
    )?;
    let recorded = if applied.left.is_empty() {
        merged_from
    } else {
        previous
    };
    let commit = store.append_signed(
        into.snapshots,
        head,
        tree,
        &recorded.message(),
        into.commits.signer(),
    )?;
    Ok((applied, tree, commit))
}

/// Adds to `into`'s note what the merge from `from` left in its worktree, whose tree went from
/// `ours` to `tree`: the paths with markers, those where the agent's side was kept, and the
/// files it changed. The merge stands whether or not the note could be kept.
fn note_merge(
    store: &Store,
    into: Recording<'_>,
    (from, merged): (&Source, &Merged),
    (ours, tree): (ObjectId, ObjectId),
) {
    let of_kind = |kind: Conflict| -> Vec<String> {
        merged
            .conflicts
            .iter()
            .filter(|(_, conflict)| *conflict == kind)
            .map(|(path, _)| path.to_string())
            .collect()
    };
    let conflicting: HashSet<String> = merged
        .conflicts
        .iter()
        .map(|(path, _)| path.to_string())
        .collect();
    let brought: Vec<String> = store
        .changed_paths(ours, tree, MAX_MERGED_PATHS)
        .map(|changes| {
            let changed = changes.paths.into_iter().map(|(path, _)| path);
            changed.filter(|path| !conflicting.contains(path)).collect()
        })
        .unwrap_or_default();
    let file = note::file(store, into.snapshots.thread(), into.slot);
    let _ = note::record(
        &file,
        from,
        note::Merged {
            markers: &of_kind(Conflict::Markers),
            kept: &of_kind(Conflict::KeptOurs),
            brought: &brought,
        },
    );
}

/// Says whether the snapshot `skipped`, which the user skipped, is the base for merging
/// `request`: the requested snapshot is it or a later one, and it is later than `last`, the
/// snapshot of the same agent merged last.
fn skip_is_base(
    store: &Store,
    skipped: ObjectId,
    (last, request): (Option<ObjectId>, &MergeRequest),
) -> Result<bool, StoreError> {
    let reaches = request.commit == skipped || store.descends_from(request.commit, skipped)?;
    let newer = match last {
        Some(last) => last != skipped && store.descends_from(skipped, last)?,
        None => true,
    };
    Ok(reaches && newer)
}

/// Returns the paths an agent reads as its settings or instructions that a pair of trees in
/// `compared`, the agent's tree `ours` against the merged one and the base against the
/// teammate's, changes, either named as such or read through a settings link of `ours`, or
/// `None` when they change none. Paths that cannot all be told give an empty list.
fn agent_settings_changed(
    store: &Store,
    ours: ObjectId,
    compared: [(ObjectId, ObjectId); 2],
) -> Option<Vec<String>> {
    let mut paths = Vec::new();
    let mut named = Vec::new();
    let mut seen = HashSet::new();
    for (old, new) in compared {
        let Ok(changes) = store.changed_paths(old, new, MAX_MERGED_PATHS) else {
            return Some(Vec::new());
        };
        if changes.truncated {
            return Some(Vec::new());
        }
        for (path, _) in changes.paths {
            if !seen.insert(path.clone()) {
                continue;
            }
            if is_agent_settings(&path) {
                named.push(path);
            } else {
                paths.push(path);
            }
        }
    }
    if !named.is_empty() {
        return Some(named);
    }
    if paths.is_empty() {
        return None;
    }
    let is_named = |path: &[u8]| is_agent_settings(&String::from_utf8_lossy(path));
    let Some(linked) = settings_links::read_through(store, ours, &is_named) else {
        return Some(Vec::new());
    };
    let linked: Vec<String> = linked
        .iter()
        .map(|read| settings_links::folded(read))
        .collect();
    let mut read = Vec::new();
    for path in paths {
        let folded = settings_links::fold(&path);
        if linked
            .iter()
            .any(|link| settings_links::covers(link, &folded))
        {
            read.push(path);
        }
    }
    (!read.is_empty()).then_some(read)
}

fn is_agent_settings(path: &str) -> bool {
    let mut parts = path.split('/');
    parts.any(|part| {
        let folded = settings_links::fold_name(part);
        settings_links::is_short_name(part)
            || AGENT_SETTINGS
                .iter()
                .any(|name| folded.eq_ignore_ascii_case(name))
    })
}

/// Returns the snapshot a merge of `request` starts from: the snapshot of `request.from` that
/// `merged` says was merged last, when the requested one descends from it; else a snapshot of
/// another agent that both the requested history, by its own trailers, and the target hold,
/// through `merged` or through its own snapshots at `own` when the target is that agent, as
/// after a handoff; or else the thread's base.
pub(crate) fn merge_base(
    store: &Store,
    (merged, own): (&MergedFrom, Option<(&AgentSlot, ObjectId)>),
    (request, theirs): (&MergeRequest, &MergedFrom),
) -> Result<ObjectId, StoreError> {
    if let Some(last) = merged.of(&request.from)
        && store.descends_from(request.commit, last)?
    {
        return Ok(last);
    }
    Ok(merged
        .shared_with(store, theirs, own)
        .unwrap_or(request.thread_base))
}

/// Reads what the snapshot history ending at `commit` merged, or nothing when it cannot be
/// read, since a merge only uses it to find a closer base.
pub(crate) fn merged_by(store: &Store, commit: ObjectId) -> MergedFrom {
    MergedFrom::read_from(store, Some(commit)).unwrap_or_default()
}

fn snapshot(
    store: &Store,
    worktree: &str,
    (globals, cache): (&GlobalPatterns, &mut SnapshotCache),
    interrupt: &AtomicBool,
) -> Result<ObjectId, StoreError> {
    let mut left = SNAPSHOT_ATTEMPTS;
    loop {
        left -= 1;
        match store.snapshot(worktree, globals, cache, interrupt) {
            Err(StoreError::ChangedDuringSnapshot(_)) if left > 0 => {}
            outcome => return outcome.map(|snapshot| snapshot.tree),
        }
    }
}

#[cfg(test)]
mod tests {
    use mahi_core::{
        RefKind,
        ThreadId,
    };

    use super::*;

    #[test]
    fn a_merge_starts_from_the_snapshot_the_sources_trailers_share_with_the_target() {
        let (_repo, store) = crate::session::tests::repository_on_main();
        let thread = ThreadId::random().unwrap();
        let base = store.head_commit().unwrap();
        let alice: AgentSlot = "alice.claude".parse().unwrap();
        let bob: AgentSlot = "bob.codex".parse().unwrap();
        let tree = store.write_tree(&[]).unwrap();
        let snapshots = |slot: &AgentSlot| ThreadRef::new(thread, RefKind::Snapshots(slot.clone()));
        let alices = store
            .append(
                &snapshots(&alice),
                None,
                tree,
                crate::session::SNAPSHOT_MESSAGE,
            )
            .unwrap();
        let mut took = MergedFrom::default();
        took.record(alice.clone(), alices);
        let bobs = store
            .append(&snapshots(&bob), None, tree, &took.message())
            .unwrap();
        let from_bob = MergeRequest {
            from: bob.clone(),
            commit: bobs,
            thread_base: base,
        };
        let mut holds_alice = MergedFrom::default();
        holds_alice.record(alice.clone(), alices);
        let bobs_record = merged_by(&store, bobs);
        assert_eq!(
            merge_base(&store, (&holds_alice, None), (&from_bob, &bobs_record)).unwrap(),
            alices
        );
        assert_eq!(
            merge_base(
                &store,
                (&MergedFrom::default(), None),
                (&from_bob, &bobs_record)
            )
            .unwrap(),
            base
        );
        let mut holds_bob = MergedFrom::default();
        holds_bob.record(bob, bobs);
        holds_bob.absorb(&store, (&bobs_record, thread), None);
        let from_alice = MergeRequest {
            from: alice,
            commit: alices,
            thread_base: base,
        };
        assert_eq!(
            merge_base(
                &store,
                (&holds_bob, None),
                (&from_alice, &merged_by(&store, alices))
            )
            .unwrap(),
            alices
        );
    }

    #[test]
    fn agent_settings_are_named_at_any_depth_in_any_case_and_nothing_else_is() {
        let settings = [
            "CLAUDE.md",
            "docs/agents.md",
            ".claude/settings.json",
            "sub/.Claude/commands/x.md",
            ".mcp.json",
            "a/b/.MCP.JSON",
            ".codex/config.toml",
            "AGENTS.md/inner",
            "AGENTS.override.md",
            "src/agents.OVERRIDE.md",
            "CLAUDE.local.md",
            "docs/claude.local.md",
            ".clau\u{200d}de/settings.json",
            "\u{feff}CLAUDE.md",
            "CLAUDE.md.",
            "CLAUDE.md . ",
            "AGENTS.md:stream",
            ".claude::$DATA/x",
            "CLAUDE~1.MD",
            "src/AGENTS~12.MD",
            "AGENT\u{17f}.md",
            "CLA\u{1e9e}UDE~1",
            "CLAUDE.md. :x",
            "\u{212a}/.codex",
        ];
        for path in settings {
            assert!(is_agent_settings(path), "{path}");
        }
        let others = [
            "CLAUDE.md.bak",
            "my.claude",
            "src/claude.rs",
            "docs/AGENTS.txt",
            "AGENTS.override.md.bak",
            "CLAUDE.local",
            "CLAUDE.md.bak.",
            "backup~",
            "~/notes",
            "cla\u{301}ude.md",
            "\u{ff23}\u{ff2c}\u{ff21}\u{ff35}\u{ff24}\u{ff25}.md",
            "mcp.json",
            ".codexrc",
            "",
        ];
        for path in others {
            assert!(!is_agent_settings(path), "{path}");
        }
    }
}
