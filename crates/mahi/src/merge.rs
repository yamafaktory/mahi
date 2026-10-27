use std::{
    collections::HashSet,
    fmt::Write as _,
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
    Left,
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
};

const SNAPSHOT_ATTEMPTS: usize = 3;
const LISTED: usize = 20;
const LONGEST_LISTED: usize = 200;
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
    #[error("the merge from {0} changes agent settings, which wait for the user")]
    HoldsAgentSettings(AgentSlot),
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// The merge was written and recorded in the snapshot `commit` of the tree `tree`.
    Merged { commit: ObjectId, tree: ObjectId },
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
    let ours = snapshot(store, into.worktree, (into.globals, cache), interrupt)?;
    let kept = conflicts::file(store, into.snapshots.thread(), into.slot);
    if !conflicts::resolved(store, into.slot, &kept, ours)? {
        return Err(MergeError::MarkersUnresolved(into.slot.clone()));
    }
    let labels = (conflicts::label(into.slot), conflicts::label(&request.from));
    let merged = store.merge_trees(base, ours, theirs, (&labels.0, &labels.1))?;
    let waiting = held::file(store, into.snapshots.thread(), (into.slot, &request.from));
    let compared = [(ours, merged.tree), (base, theirs)];
    if settings == AgentSettings::Hold
        && let Some(paths) = agent_settings_changed(store, ours, compared)
    {
        HeldSettings::new(request.commit, &paths).keep(&waiting)?;
        return Err(MergeError::HoldsAgentSettings(request.from.clone()));
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
    if let Some(conflicts) = KeptConflicts::of_merge((&request.from, before), markers) {
        conflicts.save(&kept)?;
    }
    let (applied, tree, commit) = write_merge(
        store,
        into,
        (ours, merged.tree),
        (&previous, &merged_from),
        (cache, head),
        interrupt,
    )?;
    if applied.left.is_empty() {
        held::release_merged(store, into.snapshots.thread(), into.slot, &merged_from);
    }
    note_merge(store, into, (&request.from, &merged), (ours, tree));
    Ok(MergeDone::Merged { commit, tree })
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
    (from, merged): (&AgentSlot, &Merged),
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

/// Says what a merge did: the files written and removed, the conflicts and the paths left.
pub(crate) fn report(
    from: &AgentSlot,
    into: &dyn std::fmt::Display,
    merged: &Merged,
    applied: &Applied,
) -> String {
    let mut report = format!(
        "merged {from} into {into}: {} written, {} removed\n",
        applied.written, applied.removed
    );
    let markers = merged
        .conflicts
        .iter()
        .filter(|(_, conflict)| *conflict == Conflict::Markers)
        .map(|(path, _)| path);
    list(
        &mut report,
        (format_args!("conflict markers to resolve in"), LISTED),
        markers,
    );
    let kept = merged
        .conflicts
        .iter()
        .filter(|(_, conflict)| *conflict == Conflict::KeptOurs)
        .map(|(path, _)| path);
    list(
        &mut report,
        (format_args!("kept {into}'s side of"), LISTED),
        kept,
    );
    for (why, label) in [
        (Left::UnsafeName, "names git refuses to check out"),
        (Left::TooDeep, "nested too deep"),
        (Left::TooLarge, "too large"),
        (Left::Blocked, "something else is in the way"),
        (Left::Unwritable, "cannot be written"),
    ] {
        let paths = applied
            .left
            .iter()
            .filter(|(_, left)| *left == why)
            .map(|(path, _)| path);
        list(
            &mut report,
            (format_args!("left as they were ({label})"), LISTED),
            paths,
        );
    }
    if !applied.left.is_empty() {
        let _ = writeln!(
            report,
            "this merge is not recorded, since paths were left as they were: the next merge of \
             {from} starts from the same base"
        );
    }
    report
}

fn list<'a, T: std::fmt::Debug + 'a>(
    report: &mut String,
    (heading, most): (std::fmt::Arguments<'_>, usize),
    paths: impl Iterator<Item = &'a T>,
) {
    let mut count = 0;
    for path in paths {
        if count == 0 {
            let _ = write!(report, "{heading}:");
        }
        if count < most {
            let start = report.len();
            let _ = write!(report, " {path:?}");
            if report.len() - start > LONGEST_LISTED {
                let mut end = start + LONGEST_LISTED;
                while !report.is_char_boundary(end) {
                    end -= 1;
                }
                report.truncate(end);
                report.push_str("...");
            }
        }
        count += 1;
    }
    if count > most {
        let _ = write!(report, " and {} more", count - most);
    }
    if count > 0 {
        report.push('\n');
    }
}

#[cfg(test)]
mod tests {
    use gix::bstr::BString;

    use super::*;

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

    #[test]
    fn the_report_lists_conflicts_and_left_paths_escaped_and_cut_short() {
        let from: AgentSlot = "bob.codex".parse().unwrap();
        let into: AgentSlot = "alice.claude".parse().unwrap();
        let merged = Merged {
            tree: ObjectId::empty_tree(gix::hash::Kind::Sha1),
            conflicts: vec![
                (BString::from("a.txt"), Conflict::Markers),
                (BString::from("bad\x1b]0;x\x07"), Conflict::Markers),
                (BString::from("image.bin"), Conflict::KeptOurs),
            ],
        };
        let applied = Applied {
            written: 3,
            removed: 1,
            left: (0..25)
                .map(|index| (BString::from(format!("p{index:02}")), Left::Blocked))
                .collect(),
        };
        let report = report(&from, &into, &merged, &applied);
        assert!(report.starts_with("merged bob.codex into alice.claude: 3 written, 1 removed\n"));
        assert!(
            report.contains("conflict markers to resolve in: \"a.txt\" \"bad\\x1b]0;x\\x07\"\n"),
            "{report}"
        );
        assert!(
            report.contains("kept alice.claude's side of: \"image.bin\"\n"),
            "{report}"
        );
        assert!(
            report.contains("something else is in the way): \"p00\""),
            "{report}"
        );
        assert!(report.contains("\"p19\" and 5 more\n"), "{report}");
        assert!(!report.contains('\x1b'));
    }

    #[test]
    fn a_long_path_is_cut_short_in_the_report() {
        let from: AgentSlot = "bob.codex".parse().unwrap();
        let into: AgentSlot = "alice.claude".parse().unwrap();
        let long = "\u{e9}".repeat(400);
        let merged = Merged {
            tree: ObjectId::empty_tree(gix::hash::Kind::Sha1),
            conflicts: vec![(BString::from(long.as_str()), Conflict::Markers)],
        };
        let report = report(&from, &into, &merged, &Applied::default());
        let line = report.lines().nth(1).unwrap();
        assert!(line.ends_with("..."), "{line}");
        assert!(line.len() < "conflict markers to resolve in:".len() + LONGEST_LISTED + 4);
    }
}
