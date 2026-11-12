use mahi_core::{
    AgentSlot,
    ThreadId,
};
use mahi_store::Store;
use mahi_term::StatusConflicts;

use crate::{
    auto_merge,
    changes_view::ChangesView,
    conflicts::{
        self,
        KeptConflicts,
    },
    held,
    note::{
        self,
        Note,
    },
};

const SHOWN_PATHS: usize = 20;

/// What the sync state of the user's agent holds that the panel shows: the landing branch
/// whose merge waits for the user's keypress, the teammates' agents whose turn does, the paths
/// a merge left with conflict markers, the files each teammate's merges brought since the
/// user's last prompt, and the worktree's changes since the base or the last landing.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct SyncView {
    landing: Option<String>,
    held: Vec<String>,
    conflicts: Option<Kept>,
    brought: Vec<(String, Vec<String>)>,
    changes: Option<ChangesView>,
}

/// The conflicts kept in the user's worktree: the agent they came from, the first paths with
/// markers and how many more there are.
#[derive(Debug, PartialEq, Eq)]
struct Kept {
    from: String,
    paths: Vec<String>,
    more: usize,
}

impl SyncView {
    /// Reads what the sync state of `own`'s agent in `thread` holds; what cannot be read
    /// shows as nothing.
    pub(crate) fn read(store: &Store, thread: ThreadId, own: &AgentSlot) -> Self {
        let held = held::list(store, thread, own)
            .into_iter()
            .map(|(from, _)| from.to_string())
            .collect();
        let conflicts = KeptConflicts::load(&conflicts::file(store, thread, own))
            .ok()
            .flatten()
            .map(|kept| {
                let paths: Vec<String> = kept
                    .paths()
                    .take(SHOWN_PATHS)
                    .map(|path| String::from_utf8_lossy(path).into_owned())
                    .collect();
                Kept {
                    from: kept.from().named(),
                    more: kept.paths().count() - paths.len(),
                    paths,
                }
            });
        let brought = Note::load(&note::file(store, thread, own))
            .map(|note| {
                note.brought()
                    .map(|(from, paths)| (from.to_string(), paths.to_vec()))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            landing: auto_merge::held_landing(store, thread, own).map(|(from, _)| from.shown()),
            held,
            conflicts,
            brought,
            changes: None,
        }
    }

    /// Returns the view with the worktree's `changes` since the base or the last landing.
    pub(crate) fn with_changes(mut self, changes: ChangesView) -> Self {
        self.changes = Some(changes);
        self
    }

    /// Returns the worktree's changes since the base or the last landing, once they were read.
    pub(crate) fn changes(&self) -> Option<&ChangesView> {
        self.changes.as_ref()
    }

    pub(crate) fn landing(&self) -> Option<&str> {
        self.landing.as_deref()
    }

    /// Says whether a turn of the teammate's agent `slot` waits for the user's keypress.
    pub(crate) fn waits(&self, slot: &str) -> bool {
        self.held.iter().any(|held| held == slot)
    }

    /// Returns the files the merges of the teammate's agent `slot` brought.
    pub(crate) fn brought(&self, slot: &str) -> &[String] {
        self.brought
            .iter()
            .find(|(from, _)| from == slot)
            .map_or(&[], |(_, paths)| paths.as_slice())
    }

    /// Returns the conflicts left in the user's worktree, when there are any.
    pub(crate) fn conflicts(&self) -> Option<StatusConflicts<'_>> {
        self.conflicts.as_ref().map(|kept| StatusConflicts {
            from: &kept.from,
            paths: &kept.paths,
            more: kept.more,
        })
    }

    /// Returns the teammates' agents this view names, in slot order, each once: those whose
    /// turn waits and those whose merges brought files.
    pub(crate) fn named(&self) -> impl Iterator<Item = &str> {
        let mut named: Vec<&str> = self
            .held
            .iter()
            .chain(self.brought.iter().map(|(from, _)| from))
            .map(String::as_str)
            .collect();
        named.sort_unstable();
        named.dedup();
        named.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use mahi_store::ObjectId;
    use mahi_term::TeammateState;

    use super::*;
    use crate::{
        held::HeldSettings,
        landed_branch::BranchRecord,
        note::Merged,
        palette::HELD_DETAIL,
        source::{
            LandingBranch,
            Source,
        },
        teammates::Teammates,
    };

    fn paths(paths: &[&str]) -> Vec<String> {
        paths.iter().map(|path| (*path).to_owned()).collect()
    }

    #[test]
    fn the_status_line_reads_held_turns_conflicts_and_merged_files_from_the_agents_sync_state() {
        let dir = tempfile::tempdir().unwrap();
        gix::init(dir.path()).unwrap();
        let store = Store::open(dir.path()).unwrap();
        let thread = ThreadId::random().unwrap();
        let own: AgentSlot = "alice.claude".parse().unwrap();
        let (bob, carol): (AgentSlot, AgentSlot) = (
            "bob.claude".parse().unwrap(),
            "carol.codex".parse().unwrap(),
        );
        assert_eq!(SyncView::read(&store, thread, &own), SyncView::default());
        let commit = ObjectId::from_bytes_or_panic(&[1; 20]);
        HeldSettings::new(commit, &paths(&["CLAUDE.md"]))
            .keep(&held::file(&store, thread, (&own, &bob)))
            .unwrap();
        let dan: AgentSlot = "dan.claude".parse().unwrap();
        HeldSettings::new(commit, &paths(&["AGENTS.md"]))
            .keep(&held::file(&store, thread, (&own, &dan)))
            .unwrap();
        let marked = paths(&["src/a.rs", "src/b.rs"]);
        KeptConflicts::of_merge((&Source::Agent(carol.clone()), commit), marked.iter())
            .unwrap()
            .save(&conflicts::file(&store, thread, &own))
            .unwrap();
        let brought = paths(&["src/client.rs"]);
        note::record(
            &note::file(&store, thread, &own),
            &Source::Agent(carol.clone()),
            Merged {
                markers: &[],
                kept: &[],
                brought: &brought,
            },
        )
        .unwrap();
        let view = SyncView::read(&store, thread, &own);
        assert!(view.waits("bob.claude") && !view.waits("carol.codex"));
        assert_eq!(view.brought("carol.codex"), brought);
        assert!(view.brought("bob.claude").is_empty());
        let conflicts = view.conflicts().unwrap();
        assert_eq!(
            (conflicts.from, conflicts.paths, conflicts.more),
            ("carol.codex", marked.as_slice(), 0)
        );
        assert_eq!(
            view.named().collect::<Vec<_>>(),
            ["bob.claude", "carol.codex", "dan.claude"]
        );

        let mut teammates = Teammates::new("alice".parse().unwrap(), "alice".parse().unwrap());
        for slot in [&bob, &carol] {
            teammates.apply(
                slot.participant(),
                mahi_live::Body::Heartbeat { slot: slot.clone() },
                std::time::Instant::now(),
            );
        }
        let status: Vec<_> = teammates
            .status(&view)
            .map(|agent| (agent.slot, agent.state, agent.waits, agent.brought.to_vec()))
            .collect();
        assert_eq!(
            status,
            [
                (
                    "bob.claude",
                    TeammateState::Live,
                    Some(HELD_DETAIL),
                    Vec::new()
                ),
                ("carol.codex", TeammateState::Live, None, brought.clone()),
                (
                    "dan.claude",
                    TeammateState::Offline,
                    Some(HELD_DETAIL),
                    Vec::new()
                ),
            ]
        );
    }

    #[test]
    fn the_view_names_the_landing_branch_while_its_held_merge_is_the_last_landings() {
        let dir = tempfile::tempdir().unwrap();
        gix::init(dir.path()).unwrap();
        let store = Store::open(dir.path()).unwrap();
        let thread = ThreadId::random().unwrap();
        let own: AgentSlot = "alice.claude".parse().unwrap();
        let (tip, measured, later) = (
            ObjectId::from_bytes_or_panic(&[1; 20]),
            ObjectId::from_bytes_or_panic(&[2; 20]),
            ObjectId::from_bytes_or_panic(&[3; 20]),
        );
        let record = |tip| BranchRecord {
            remote: "up".to_owned(),
            branch: format!("mahi/{thread}"),
            tip,
            landing: "main".to_owned(),
            worktree: Some(measured),
            from: None,
            gone: false,
            answer: None,
        };
        let landing = Source::Landing(LandingBranch::new("up", "main").unwrap());
        HeldSettings::new(tip, &paths(&["CLAUDE.md"]))
            .keep(&held::file_for(&store, thread, (&own, &landing)))
            .unwrap();
        assert_eq!(SyncView::read(&store, thread, &own).landing(), None);
        record(tip).write(&store, thread).unwrap();
        let view = SyncView::read(&store, thread, &own);
        assert_eq!(view.landing(), Some("main"));
        assert_eq!(view.named().count(), 0);
        record(later).write(&store, thread).unwrap();
        assert_eq!(SyncView::read(&store, thread, &own).landing(), None);
    }

    #[test]
    fn the_view_keeps_the_first_conflicting_paths_and_counts_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        gix::init(dir.path()).unwrap();
        let store = Store::open(dir.path()).unwrap();
        let thread = ThreadId::random().unwrap();
        let own: AgentSlot = "alice.claude".parse().unwrap();
        let bob: AgentSlot = "bob.claude".parse().unwrap();
        let marked: Vec<String> = (0..25).map(|index| format!("src/{index}.rs")).collect();
        KeptConflicts::of_merge(
            (&Source::Agent(bob), ObjectId::from_bytes_or_panic(&[1; 20])),
            marked.iter(),
        )
        .unwrap()
        .save(&conflicts::file(&store, thread, &own))
        .unwrap();
        let view = SyncView::read(&store, thread, &own);
        let conflicts = view.conflicts().unwrap();
        assert_eq!(conflicts.paths, &marked[..SHOWN_PATHS]);
        assert_eq!(conflicts.more, 5);
    }
}
