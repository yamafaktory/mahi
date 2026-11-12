use std::{
    fmt::Write as _,
    io,
    path::{
        Path,
        PathBuf,
    },
    sync::{
        Mutex,
        MutexGuard,
    },
};

use mahi_core::{
    AgentSlot,
    ThreadId,
    is_invisible,
};
use mahi_store::Store;
use serde::{
    Deserialize,
    Serialize,
};
use thiserror::Error;

use crate::{
    hook,
    mcp::push_clean,
    source::Source,
    sync_state,
};

const NOTE_FILE: &str = "note";
const MAX_NOTE_BYTES: usize = 1024 * 1024;
const MAX_TEXT_BYTES: usize = 32 * 1024;
const CUT: char = '…';
const MAX_LISTED: usize = 20;
const LONGEST_PATH: usize = 200;
const MAX_TEAMMATES: usize = 64;
const MAX_LANDED_CHARS: usize = 1024;
const OPENING: &str = "mahi merged your teammates' work into your worktree since your last prompt.";
const RESOLVE_FIRST: &str = "Resolve these conflicts before anything else.";

/// What came into an agent's worktree from its teammates since its user's last prompt, kept in
/// its sync state until an agent takes it: for each teammate, the paths left with conflict
/// markers, those where the agent's version was kept, and the files their merges brought.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Note {
    came: Vec<Came>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    landed: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Came {
    from: Source,
    markers: Listed,
    kept: Listed,
    brought: Listed,
}

/// The first paths of a kind, each cut to 200 bytes, and how many more there were.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Listed {
    paths: Vec<String>,
    more: usize,
}

/// What one merge from a teammate left: the paths with markers, those where the agent's version
/// was kept, and the files it brought.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Merged<'paths> {
    pub(crate) markers: &'paths [String],
    pub(crate) kept: &'paths [String],
    pub(crate) brought: &'paths [String],
}

#[derive(Debug, Error)]
pub(crate) enum NoteError {
    #[error("cannot keep the note of what came in in {0}")]
    Io(PathBuf, #[source] io::Error),
    #[error("the note kept in {0} cannot be read")]
    Malformed(PathBuf),
    #[error("the lock on the note is poisoned")]
    Poisoned,
}

/// Returns where the note of `slot`'s worktree in `thread` is kept: the agent's sync
/// directory, then `note`.
pub(crate) fn file(store: &Store, thread: ThreadId, slot: &AgentSlot) -> PathBuf {
    sync_state::dir(store, thread, slot).join(NOTE_FILE)
}

static KEEPING: Mutex<()> = Mutex::new(());

fn keeping() -> Result<MutexGuard<'static, ()>, NoteError> {
    KEEPING.lock().map_err(|_| NoteError::Poisoned)
}

/// Adds what a merge from `from` left to the note kept in `file`, which a note that cannot
/// be read no longer holds back; past 1 MiB the note keeps what it held.
pub(crate) fn record(file: &Path, from: &Source, merged: Merged<'_>) -> Result<(), NoteError> {
    let _kept = keeping()?;
    let mut note = match Note::load(file) {
        Err(NoteError::Malformed(_)) => Note::default(),
        loaded => loaded?,
    };
    note.add(from, merged);
    note.save(file)
}

/// Takes the note kept in `file`, as the text an agent reads, or `None` when nothing came in
/// or the note cannot be read, which is then dropped.
pub(crate) fn take(file: &Path) -> Result<Option<String>, NoteError> {
    let _kept = keeping()?;
    let note = match Note::load(file) {
        Err(NoteError::Malformed(_)) => Note::default(),
        loaded => loaded?,
    };
    sync_state::remove(file).map_err(|error| NoteError::Io(file.to_path_buf(), error))?;
    Ok((!note.is_empty()).then(|| note.render()))
}

pub(crate) fn record_landing(file: &Path, line: &str) -> Result<(), NoteError> {
    let _kept = keeping()?;
    let mut note = match Note::load(file) {
        Err(NoteError::Malformed(_)) => Note::default(),
        loaded => loaded?,
    };
    let mut cleaned = String::with_capacity(line.len().min(MAX_LANDED_CHARS));
    let end = line
        .char_indices()
        .nth(MAX_LANDED_CHARS)
        .map_or(line.len(), |(index, _)| index);
    push_clean(&mut cleaned, line.get(..end).unwrap_or(line));
    note.landed = Some(cleaned);
    note.save(file)
}

/// Returns the note kept in `file` as the text an agent reads, without taking it, or `None`
/// when nothing came in or it cannot be read.
pub(crate) fn peek(file: &Path) -> Option<String> {
    let _kept = keeping().ok()?;
    let note = Note::load(file).ok()?;
    (!note.is_empty()).then(|| note.render())
}

/// Returns the teammates' agents the note kept in `file` names, whose merges brought files or
/// left conflicts; none when it cannot be read.
pub(crate) fn listed(file: &Path) -> Vec<AgentSlot> {
    let Ok(_kept) = keeping() else {
        return Vec::new();
    };
    Note::load(file)
        .map(|note| note.teammates().cloned().collect())
        .unwrap_or_default()
}

/// Takes the note kept in `file` when it still reads `shown`, as an agent's hook read it; a
/// note that grew meanwhile stays, so what came in since is not lost.
pub(crate) fn take_shown(file: &Path, shown: &str) {
    let Ok(_kept) = keeping() else {
        return;
    };
    let still = Note::load(file).is_ok_and(|note| !note.is_empty() && note.render() == shown);
    if still {
        let _ = sync_state::remove(file);
    }
}

/// The note of an agent's worktree, as its prompt hook adds it to the user's prompt.
#[derive(Debug)]
pub(crate) struct NoteContext {
    pub(crate) file: PathBuf,
}

impl hook::Context for NoteContext {
    fn peek(&self) -> Option<String> {
        peek(&self.file)
    }

    fn taken(&self, shown: &str) {
        take_shown(&self.file, shown);
    }
}

/// How an agent gets the note: added to the user's prompt by its prompt hook, or from
/// `list_agents`, which its instructions ask it to call at the start of each turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NoteBy {
    PromptHook,
    ListAgents,
}

impl Listed {
    fn add(&mut self, paths: &[String]) {
        for path in paths {
            let (path, was_cut) = cut(path);
            if path.is_empty() || (!was_cut && self.paths.contains(&path)) {
                continue;
            }
            if self.paths.len() < MAX_LISTED && !self.paths.contains(&path) {
                self.paths.push(path);
            } else {
                self.more = self.more.saturating_add(1);
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    fn holds(&self) -> bool {
        self.paths.len() <= MAX_LISTED
            && self
                .paths
                .iter()
                .all(|path| !path.is_empty() && path.len() <= LONGEST_PATH + CUT.len_utf8())
    }

    fn push(&self, out: &mut String, (between, budget): (&str, &mut usize)) {
        let mut more = self.more;
        let mut shown = 0;
        for path in &self.paths {
            let start = out.len();
            if shown > 0 {
                out.push_str(between);
            }
            push_code(out, path, LONGEST_PATH + 1);
            let used = out.len() - start;
            if used > *budget {
                out.truncate(start);
                more = more.saturating_add(1);
                continue;
            }
            *budget -= used;
            shown += 1;
        }
        if more > 0 {
            let _ = write!(out, " and {more} more");
        }
        out.push('\n');
    }
}

/// Returns `path` cut to 200 bytes, ending with `…` when it was, and whether it was.
fn cut(path: &str) -> (String, bool) {
    if path.len() <= LONGEST_PATH {
        return (path.to_owned(), false);
    }
    let mut end = LONGEST_PATH;
    while !path.is_char_boundary(end) {
        end -= 1;
    }
    let mut cut = path.get(..end).unwrap_or_default().to_owned();
    cut.push(CUT);
    (cut, true)
}

impl Note {
    /// Reads the note kept in `file`, an empty one when there is none.
    pub(crate) fn load(file: &Path) -> Result<Self, NoteError> {
        let malformed = || NoteError::Malformed(file.to_path_buf());
        let bytes = match sync_state::read(file, MAX_NOTE_BYTES as u64) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Ok(Self::default()),
            Err(error) if error.kind() == io::ErrorKind::FileTooLarge => return Err(malformed()),
            Err(error) => return Err(NoteError::Io(file.to_path_buf(), error)),
        };
        let note: Self = serde_json::from_slice(&bytes).map_err(|_| malformed())?;
        let holds = note.came.len() <= MAX_TEAMMATES
            && note
                .landed
                .as_ref()
                .is_none_or(|landed| landed.len() <= MAX_TEXT_BYTES)
            && note.came.iter().all(|came| {
                [&came.markers, &came.kept, &came.brought]
                    .iter()
                    .all(|listed| listed.holds())
            });
        holds.then_some(note).ok_or_else(malformed)
    }

    fn is_empty(&self) -> bool {
        self.came.is_empty() && self.landed.is_none()
    }

    /// Returns each teammate's agent the note names, whose merges brought files or left
    /// conflicts.
    pub(crate) fn teammates(&self) -> impl Iterator<Item = &AgentSlot> {
        self.came.iter().filter_map(|came| came.from.agent())
    }

    /// Returns each teammate's agent the note names, with the first files its merges brought.
    pub(crate) fn brought(&self) -> impl Iterator<Item = (&AgentSlot, &[String])> {
        self.came.iter().filter_map(|came| {
            came.from
                .agent()
                .map(|slot| (slot, came.brought.paths.as_slice()))
        })
    }

    fn save(&self, file: &Path) -> Result<(), NoteError> {
        let bytes =
            serde_json::to_vec(self).map_err(|_| NoteError::Malformed(file.to_path_buf()))?;
        if bytes.len() > MAX_NOTE_BYTES {
            return Ok(());
        }
        sync_state::write(file, &bytes).map_err(|error| NoteError::Io(file.to_path_buf(), error))
    }

    /// Adds what a merge from `from` left, to what that teammate's earlier merges left; a
    /// teammate past the 64th is left out.
    pub(crate) fn add(&mut self, from: &Source, merged: Merged<'_>) {
        if merged.markers.is_empty() && merged.kept.is_empty() && merged.brought.is_empty() {
            return;
        }
        let index = match self.came.iter().position(|came| came.from == *from) {
            Some(index) => index,
            None if self.came.len() < MAX_TEAMMATES => {
                self.came.push(Came {
                    from: from.clone(),
                    markers: Listed::default(),
                    kept: Listed::default(),
                    brought: Listed::default(),
                });
                self.came.len() - 1
            }
            None => return,
        };
        let Some(came) = self.came.get_mut(index) else {
            return;
        };
        came.markers.add(merged.markers);
        came.kept.add(merged.kept);
        came.brought.add(merged.brought);
    }

    /// Returns the note as the agent reads it: the conflicts first, with the agent asked to
    /// resolve them before anything else, then the files each teammate's merges brought, each
    /// path in a code span.
    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        if !self.came.is_empty() {
            self.render_came(&mut out);
        }
        if let Some(landed) = &self.landed {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(landed);
        }
        out
    }

    fn render_came(&self, out: &mut String) {
        out.push_str(OPENING);
        let mut budget = MAX_TEXT_BYTES;
        out.push('\n');
        let conflicts = self
            .came
            .iter()
            .any(|came| !came.markers.is_empty() || !came.kept.is_empty());
        if conflicts {
            out.push_str(RESOLVE_FIRST);
            out.push('\n');
        }
        for came in &self.came {
            let from = came.from.named();
            if !came.markers.is_empty() {
                let _ = write!(out, "Resolve the conflict markers in (from {from}): ");
                came.markers.push(out, (" ", &mut budget));
            }
            if !came.kept.is_empty() {
                match came.from {
                    Source::Landing(_) => {
                        let _ =
                            write!(out, "Your version was kept, but {from} changed these too: ");
                    }
                    Source::Agent(_) => {
                        let _ = write!(
                            out,
                            "Your version was kept, but {from} changed these too; check them with read_diff: "
                        );
                    }
                }
                came.kept.push(out, (" ", &mut budget));
            }
        }
        for came in &self.came {
            if !came.brought.is_empty() {
                let _ = write!(out, "merged {}: ", came.from.named());
                came.brought.push(out, (", ", &mut budget));
            }
        }
        out.truncate(out.trim_end().len());
    }
}

fn shown_chars(text: &str) -> impl Iterator<Item = char> + '_ {
    text.chars().filter(|character| {
        (!character.is_control() || matches!(character, '\n' | '\t')) && !is_invisible(*character)
    })
}

fn push_code(out: &mut String, text: &str, max_chars: usize) {
    let mut longest = 0;
    let mut run = 0;
    for character in shown_chars(text).take(max_chars) {
        run = if character == '`' { run + 1 } else { 0 };
        longest = longest.max(run);
    }
    let fence = |out: &mut String| out.extend(std::iter::repeat_n('`', longest + 1));
    fence(out);
    out.push(' ');
    let mut chars = shown_chars(text);
    for character in chars.by_ref().take(max_chars) {
        out.push(if matches!(character, '\n' | '\t') {
            ' '
        } else {
            character
        });
    }
    if chars.next().is_some() {
        out.push('…');
    }
    out.push(' ');
    fence(out);
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn the_listed_teammates_are_those_whose_merges_brought_files_or_conflicts() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("note");
        assert!(listed(&file).is_empty());
        let (bob, carol, dan): (AgentSlot, AgentSlot, AgentSlot) = (
            "bob.claude".parse().unwrap(),
            "carol.codex".parse().unwrap(),
            "dan.claude".parse().unwrap(),
        );
        let paths = ["src/lib.rs".to_owned()];
        let none: [String; 0] = [];
        let merged = |markers, brought| Merged {
            markers,
            kept: &none,
            brought,
        };
        record(&file, &Source::Agent(bob.clone()), merged(&none, &paths)).unwrap();
        record(&file, &Source::Agent(carol), merged(&none, &none)).unwrap();
        record(&file, &Source::Agent(dan.clone()), merged(&paths, &none)).unwrap();
        assert_eq!(listed(&file), [bob, dan]);
    }

    #[test]
    fn a_code_span_is_fenced_past_its_backquotes_on_one_line_and_cut_short() {
        let mut out = String::new();
        push_code(&mut out, "a``b\nc\u{1b}[2J\u{200b}", 20);
        assert_eq!(out, "``` a``b c[2J ```");
        out.clear();
        push_code(&mut out, "abcdef", 3);
        assert_eq!(out, "` abc… `");
    }

    #[test]
    fn a_code_span_drops_what_could_hide_text_or_break_its_line() {
        let mut out = String::new();
        push_code(&mut out, "evil\u{202e}txt.exe\u{2028}# x\u{e0041}", 40);
        for hidden in ['\u{202e}', '\u{2028}', '\u{e0041}'] {
            assert!(!out.contains(hidden), "{hidden:?}");
        }
        assert_eq!(out, "` eviltxt.exe# x `");
    }

    fn paths(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn the_note_lists_conflicts_first_then_what_each_teammate_brought() {
        let mut note = Note::default();
        let bob: Source = "bob.claude".parse().unwrap();
        let carol: Source = "carol.codex".parse().unwrap();
        let brought: Vec<String> = (0..23).map(|index| format!("src/{index}.rs")).collect();
        note.add(
            &bob,
            Merged {
                markers: &paths(&["src/client.rs", "src/lib.rs"]),
                kept: &paths(&["logo.png"]),
                brought: &brought,
            },
        );
        note.add(
            &carol,
            Merged {
                markers: &[],
                kept: &[],
                brought: &paths(&["tests/parse.rs"]),
            },
        );
        note.add(
            &bob,
            Merged {
                markers: &paths(&["src/lib.rs"]),
                kept: &[],
                brought: &paths(&["src/0.rs"]),
            },
        );
        let text = note.render();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], OPENING);
        assert_eq!(lines[1], RESOLVE_FIRST);
        assert_eq!(
            lines[2],
            "Resolve the conflict markers in (from bob.claude): ` src/client.rs ` ` src/lib.rs `"
        );
        assert_eq!(
            lines[3],
            "Your version was kept, but bob.claude changed these too; check them with read_diff: \
             ` logo.png `"
        );
        assert!(lines[4].starts_with("merged bob.claude: ` src/0.rs `, ` src/1.rs `"));
        assert!(lines[4].ends_with(" and 3 more"), "{}", lines[4]);
        assert_eq!(lines[5], "merged carol.codex: ` tests/parse.rs `");
        assert_eq!(lines.len(), 6);
    }

    #[test]
    fn the_landing_branchs_merge_is_named_with_its_remote_and_points_to_no_tool() {
        let mut note = Note::default();
        let main: Source = "landing:up:main".parse().unwrap();
        note.add(
            &main,
            Merged {
                markers: &paths(&["m.txt"]),
                kept: &paths(&["logo.png"]),
                brought: &paths(&["upstream.txt", "m.txt"]),
            },
        );
        assert_eq!(
            note.render(),
            format!(
                "{OPENING}\n{RESOLVE_FIRST}\n\
                 Resolve the conflict markers in (from main on up): ` m.txt `\n\
                 Your version was kept, but main on up changed these too: ` logo.png `\n\
                 merged main on up: ` upstream.txt `, ` m.txt `"
            )
        );
        assert_eq!(note.brought().count(), 0);
    }

    #[test]
    fn a_teammates_path_is_quoted_as_data_and_cut_short() {
        let mut note = Note::default();
        let bob: Source = "bob.claude".parse().unwrap();
        let long = format!("{}.rs", "\u{e9}".repeat(300));
        note.add(
            &bob,
            Merged {
                markers: &[],
                kept: &[],
                brought: &paths(&["a``b.rs", "x\u{202e}\x1b[2J.rs", &long]),
            },
        );
        let text = note.render();
        assert!(text.contains("``` a``b.rs ```"), "{text}");
        assert!(text.contains("` x[2J.rs `"), "{text}");
        assert!(!text.contains('\u{1b}') && !text.contains('\u{202e}'));
        let longest = text.lines().last().unwrap();
        assert!(longest.len() < 300, "{longest}");
        assert!(
            !note.came[0]
                .brought
                .paths
                .iter()
                .any(|path| path.len() > LONGEST_PATH + CUT.len_utf8())
        );
    }

    #[test]
    fn a_note_is_kept_until_taken_and_one_with_nothing_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("sync/alice.claude/note");
        assert_eq!(take(&file).unwrap(), None);
        let bob: Source = "bob.claude".parse().unwrap();
        let merged = Merged {
            markers: &[],
            kept: &[],
            brought: &paths(&["a.rs"]),
        };
        record(&file, &bob, merged).unwrap();
        record(&file, &bob, merged).unwrap();
        let text = take(&file).unwrap().unwrap();
        assert!(text.ends_with("merged bob.claude: ` a.rs `"), "{text}");
        assert!(!text.contains(RESOLVE_FIRST));
        assert_eq!(take(&file).unwrap(), None);
    }

    #[test]
    fn a_landings_outcome_reads_alone_or_after_the_merges_and_the_latest_replaces_the_last() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("sync/alice.claude/note");
        record_landing(&file, "alice cancelled your landing; nothing was pushed.").unwrap();
        record_landing(
            &file,
            "alice pushed your landing: 2 commits on mahi/x to origin.\u{7}",
        )
        .unwrap();
        assert_eq!(
            take(&file).unwrap().as_deref(),
            Some("alice pushed your landing: 2 commits on mahi/x to origin.")
        );
        let bob: Source = "bob.claude".parse().unwrap();
        let brought = paths(&["a.rs"]);
        let merged = Merged {
            markers: &[],
            kept: &[],
            brought: &brought,
        };
        record(&file, &bob, merged).unwrap();
        record_landing(&file, "alice cancelled your landing; nothing was pushed.").unwrap();
        let text = take(&file).unwrap().unwrap();
        assert!(text.starts_with(OPENING), "{text}");
        assert!(
            text.ends_with("` a.rs `\nalice cancelled your landing; nothing was pushed."),
            "{text}"
        );
    }

    #[test]
    fn a_note_never_grows_past_what_it_reads_back_and_its_text_stays_within_a_reply() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("note");
        let crafted: Vec<String> = (0..25)
            .map(|index| format!("{index}{}", "\u{1}".repeat(199)))
            .collect();
        for teammate in 0..64 {
            let from: AgentSlot = format!("p{teammate}.claude").parse().unwrap();
            let merged = Merged {
                markers: &crafted,
                kept: &crafted,
                brought: &crafted,
            };
            assert!(
                record(&file, &Source::Agent(from.clone()), merged).is_ok()
                    || Note::load(&file).is_ok()
            );
        }
        let text = take(&file).unwrap().unwrap();
        assert!(text.len() <= MAX_TEXT_BYTES + 1024, "{}", text.len());
        assert!(text.contains(" more"), "{text}");
    }

    #[test]
    fn a_cut_path_says_so_and_a_merge_that_left_nothing_adds_nothing() {
        let mut note = Note::default();
        let bob: Source = "bob.claude".parse().unwrap();
        let long = |end: &str| format!("{}{end}", "d/".repeat(150));
        note.add(
            &bob,
            Merged {
                markers: &[],
                kept: &[],
                brought: &[long("a.rs"), long("b.rs")],
            },
        );
        let brought = &note.came[0].brought;
        assert_eq!(brought.paths.len(), 1);
        assert!(brought.paths[0].ends_with('…'));
        assert_eq!(brought.more, 1);
        note.add(
            &"carol.codex".parse().unwrap(),
            Merged {
                markers: &[],
                kept: &[],
                brought: &[],
            },
        );
        assert_eq!(note.came.len(), 1);
    }

    #[test]
    fn a_note_that_cannot_be_read_is_dropped_so_later_ones_still_come() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("note");
        fs::write(&file, "not json").unwrap();
        assert_eq!(take(&file).unwrap(), None);
        fs::write(&file, "not json").unwrap();
        let bob: Source = "bob.claude".parse().unwrap();
        record(
            &file,
            &bob,
            Merged {
                markers: &[],
                kept: &[],
                brought: &paths(&["a.rs"]),
            },
        )
        .unwrap();
        assert!(take(&file).unwrap().unwrap().contains("` a.rs `"));
    }

    #[test]
    fn a_note_the_hook_read_is_taken_but_one_that_grew_since_stays() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("note");
        let bob: Source = "bob.claude".parse().unwrap();
        let brought = |name: &str| vec![name.to_owned()];
        let merged = |paths: &[String]| {
            record(
                &file,
                &bob,
                Merged {
                    markers: &[],
                    kept: &[],
                    brought: paths,
                },
            )
            .unwrap();
        };
        assert_eq!(peek(&file), None);
        merged(&brought("a.rs"));
        let shown = peek(&file).unwrap();
        merged(&brought("b.rs"));
        take_shown(&file, &shown);
        let kept = peek(&file).unwrap();
        assert!(kept.contains("` b.rs `"), "{kept}");
        take_shown(&file, &kept);
        assert_eq!(peek(&file), None);
    }

    #[test]
    fn a_note_file_that_is_not_one_mahi_wrote_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("note");
        let long = "x".repeat(LONGEST_PATH + CUT.len_utf8() + 1);
        for text in [
            "not json".to_owned(),
            r#"{"came":[{"from":"no slot","markers":{"paths":[],"more":0},"kept":{"paths":[],"more":0},"brought":{"paths":[],"more":0}}]}"#.to_owned(),
            format!(
                r#"{{"came":[{{"from":"bob.claude","markers":{{"paths":["{long}"],"more":0}},"kept":{{"paths":[],"more":0}},"brought":{{"paths":[],"more":0}}}}]}}"#
            ),
        ] {
            fs::write(&file, &text).unwrap();
            assert!(
                matches!(Note::load(&file), Err(NoteError::Malformed(_))),
                "{text}"
            );
        }
    }
}
