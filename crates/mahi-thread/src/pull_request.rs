use std::fmt::{
    self,
    Write as _,
};

use mahi_store::{
    Change,
    Changes,
};

use crate::handoff::{
    cut,
    push_code,
    push_count,
    shown_chars,
};

/// The largest draft [`PullRequestDraft::render`] writes, in bytes.
pub const MAX_DRAFT_BYTES: usize = 60 * 1024;

const GOALS_BYTES: usize = 22 * 1024;
const FILES_BYTES: usize = 10 * 1024;
const REPLIES_BYTES: usize = 18 * 1024;
const MAX_GOAL_CHARS: usize = 2000;
const MAX_GOAL_LINES: usize = 40;
const MAX_REPLY_CHARS: usize = 4000;
const MAX_REPLY_LINES: usize = 60;
const MAX_LINE_CHARS: usize = 200;
const MAX_LISTED_NAMES: usize = 64;
const MIN_FENCE: usize = 3;

/// What one landed agent brings to a pull request draft.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct LandedAgent {
    /// The agent, such as `alice.claude`.
    pub slot: String,
    /// The first prompt it was given, when its transcript holds one.
    pub goal: Option<String>,
    /// Whether its transcript could not be read back to its start, so [`LandedAgent::goal`]
    /// is only the earliest prompt read.
    pub goal_cut: bool,
    /// Its last reply, when its session could be read.
    pub last_reply: Option<String>,
}

impl fmt::Debug for LandedAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LandedAgent")
            .field("slot", &self.slot)
            .field("goal", &self.goal.is_some())
            .field("last_reply", &self.last_reply.is_some())
            .finish_non_exhaustive()
    }
}

/// The first text of a thread's pull request, drafted from its records: the thread, each
/// landed agent's goal and last reply, the people involved and the files changed.
///
/// Every text comes from the thread's records, written by participants and their agents, and
/// the draft is meant for a forge, so records are shown in code spans and fenced blocks, where
/// a forge neither notifies the people they mention nor loads the images they link.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct PullRequestDraft {
    /// The thread's title.
    pub title: String,
    /// The thread's ID.
    pub thread: String,
    /// The agents whose work was landed.
    pub agents: Vec<LandedAgent>,
    /// The participants those agents belong to.
    pub people: Vec<String>,
    /// The files the landing branch changed from the branch it lands on.
    pub changes: Changes,
}

impl fmt::Debug for PullRequestDraft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PullRequestDraft")
            .field("agents", &self.agents)
            .field("changes", &self.changes.paths.len())
            .finish_non_exhaustive()
    }
}

impl PullRequestDraft {
    /// Writes the draft as Markdown, at most [`MAX_DRAFT_BYTES`] bytes, each section within
    /// its own share of that size and saying what it left out. Control, invisible and
    /// text-direction characters are left out.
    #[must_use]
    pub fn render(&self) -> String {
        let mut text = String::new();
        text.push_str("## Thread\n\n- Title: ");
        push_code(&mut text, &self.title, MAX_LINE_CHARS);
        text.push_str("\n- Thread: ");
        push_code(&mut text, &self.thread, MAX_LINE_CHARS);
        text.push_str("\n- Agents: ");
        push_names(
            &mut text,
            self.agents.iter().map(|agent| agent.slot.as_str()),
        );
        text.push_str("\n- People: ");
        push_names(&mut text, self.people.iter().map(String::as_str));
        text.push_str("\n\n");
        push_agents(
            &mut text,
            ("Goals", GOALS_BYTES),
            &self.agents,
            (
                |_| true,
                |out: &mut String, agent: &LandedAgent| {
                    if agent.goal_cut {
                        out.push_str(
                            "(the earliest prompt read; the transcript could not be read back to \
                         its start)\n\n",
                        );
                    }
                    match &agent.goal {
                        Some(goal) => push_fenced(out, goal, MAX_GOAL_CHARS, MAX_GOAL_LINES),
                        None => out.push_str("No prompt was recorded.\n"),
                    }
                },
            ),
        );
        self.push_files(&mut text);
        push_agents(
            &mut text,
            ("Last replies", REPLIES_BYTES),
            &self.agents,
            (
                |agent| agent.last_reply.is_some(),
                |out: &mut String, agent: &LandedAgent| {
                    if let Some(reply) = &agent.last_reply {
                        push_fenced(out, reply, MAX_REPLY_CHARS, MAX_REPLY_LINES);
                    }
                },
            ),
        );
        cut(text, MAX_DRAFT_BYTES)
    }

    fn push_files(&self, text: &mut String) {
        let start = text.len();
        text.push_str("## Files changed\n\n");
        if self.changes.paths.is_empty() {
            text.push_str(if self.changes.truncated {
                "Too many to list.\n\n"
            } else {
                "None.\n\n"
            });
            return;
        }
        let mut listed = 0;
        for (path, change) in &self.changes.paths {
            let line_start = text.len();
            text.push_str(match change {
                Change::Added => "- added ",
                Change::Deleted => "- deleted ",
                Change::Modified => "- modified ",
            });
            push_code(text, path, MAX_LINE_CHARS);
            text.push('\n');
            if text.len() - start > FILES_BYTES {
                text.truncate(line_start);
                break;
            }
            listed += 1;
        }
        let left_out = self.changes.paths.len() - listed;
        if left_out > 0 {
            text.push_str("- and ");
            push_count(text, left_out, "more file");
            text.push('\n');
        } else if self.changes.truncated {
            text.push_str("- and more\n");
        }
        text.push('\n');
    }
}

fn push_names<'a>(out: &mut String, names: impl ExactSizeIterator<Item = &'a str>) {
    let count = names.len();
    if count == 0 {
        out.push_str("none");
        return;
    }
    for (index, name) in names.take(MAX_LISTED_NAMES).enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        push_code(out, name, MAX_LINE_CHARS);
    }
    if count > MAX_LISTED_NAMES {
        let _ = write!(out, ", and {} more", count - MAX_LISTED_NAMES);
    }
}

fn push_agents(
    text: &mut String,
    (heading, budget): (&str, usize),
    agents: &[LandedAgent],
    (has_body, body): (fn(&LandedAgent) -> bool, impl Fn(&mut String, &LandedAgent)),
) {
    let start = text.len();
    let _ = write!(text, "## {heading}\n\n");
    let mut shown = 0;
    let mut left_out = 0;
    for agent in agents.iter().filter(|agent| has_body(agent)) {
        if left_out > 0 {
            left_out += 1;
            continue;
        }
        let block_start = text.len();
        text.push_str("### ");
        push_code(text, &agent.slot, MAX_LINE_CHARS);
        text.push_str("\n\n");
        body(text, agent);
        text.push('\n');
        if text.len() - start > budget {
            text.truncate(block_start);
            left_out += 1;
            continue;
        }
        shown += 1;
    }
    if shown == 0 && left_out == 0 {
        text.truncate(start);
        return;
    }
    if left_out > 0 {
        text.push('(');
        push_count(text, left_out, "more agent");
        text.push_str(" left out)\n\n");
    }
}

/// Writes `text` as a fenced block of at most `max_chars` characters and `max_lines` lines,
/// with `…` where it was cut, fenced longer than any run of backquotes in it.
fn push_fenced(out: &mut String, text: &str, max_chars: usize, max_lines: usize) {
    let mut body = String::new();
    let mut lines = 1;
    let mut shortened = false;
    for (taken, character) in shown_chars(text).enumerate() {
        if taken == max_chars {
            shortened = true;
            break;
        }
        if character == '\n' {
            if lines == max_lines {
                shortened = true;
                break;
            }
            lines += 1;
        }
        body.push(character);
    }
    let body = body.trim_end();
    let mut longest = 0;
    let mut run = 0;
    for character in body.chars() {
        run = if character == '`' { run + 1 } else { 0 };
        longest = longest.max(run);
    }
    let fence = (longest + 1).max(MIN_FENCE);
    out.extend(std::iter::repeat_n('`', fence));
    out.push_str("text\n");
    out.push_str(body);
    if shortened {
        out.push_str(if body.is_empty() { "…" } else { "\n…" });
    }
    out.push('\n');
    out.extend(std::iter::repeat_n('`', fence));
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft() -> PullRequestDraft {
        PullRequestDraft {
            title: "login page".to_owned(),
            thread: "7f3a".to_owned(),
            agents: vec![
                LandedAgent {
                    slot: "alice.claude".to_owned(),
                    goal: Some("Add a login page\nwith tests".to_owned()),
                    goal_cut: false,
                    last_reply: Some("Done; tests pass.".to_owned()),
                },
                LandedAgent {
                    slot: "bob.codex".to_owned(),
                    goal: None,
                    goal_cut: false,
                    last_reply: None,
                },
            ],
            people: vec!["alice".to_owned(), "bob".to_owned()],
            changes: Changes {
                paths: vec![
                    ("src/login.rs".to_owned(), Change::Added),
                    ("src/api.rs".to_owned(), Change::Modified),
                ],
                truncated: false,
            },
        }
    }

    #[test]
    fn a_draft_names_the_thread_the_goals_the_files_and_the_last_replies() {
        let text = draft().render();
        for expected in [
            "## Thread\n\n- Title: ` login page `\n- Thread: ` 7f3a `\n",
            "- Agents: ` alice.claude `, ` bob.codex `\n- People: ` alice `, ` bob `\n",
            "## Goals\n\n### ` alice.claude `\n\n```text\nAdd a login page\nwith tests\n```\n",
            "### ` bob.codex `\n\nNo prompt was recorded.\n",
            "## Files changed\n\n- added ` src/login.rs `\n- modified ` src/api.rs `\n",
            "## Last replies\n\n### ` alice.claude `\n\n```text\nDone; tests pass.\n```\n",
        ] {
            assert!(text.contains(expected), "{expected}\n{text}");
        }
        assert_eq!(text.matches("bob.codex").count(), 2, "{text}");
    }

    #[test]
    fn records_stay_inside_their_fences_without_controls() {
        let mut hostile = draft();
        hostile.agents[0].goal =
            Some("@team look ![x](http://t/p.png)\n```\nout\x1b[2J".to_owned());
        hostile.agents[0].last_reply = Some("````\n".to_owned());
        let text = hostile.render();
        assert!(
            text.contains("````text\n@team look ![x](http://t/p.png)\n```\nout[2J\n````\n"),
            "{text}"
        );
        assert!(text.contains("`````text\n````\n`````\n"), "{text}");
        assert!(!text.contains('\x1b'));
    }

    #[test]
    fn every_section_stays_within_its_share_and_says_what_it_left_out() {
        let mut long = draft();
        long.agents = (0..300)
            .map(|index| LandedAgent {
                slot: format!("p{index}.claude"),
                goal: Some(format!("goal {index}\n{}", "g".repeat(5000))),
                goal_cut: index == 0,
                last_reply: Some(format!("reply {index}\n{}", "line\n".repeat(200))),
            })
            .collect();
        long.people = (0..100).map(|index| format!("p{index}")).collect();
        long.changes.paths = (0..5000)
            .map(|index| (format!("src/file{index}.rs"), Change::Modified))
            .collect();
        let text = long.render();
        assert!(text.len() <= MAX_DRAFT_BYTES, "{}", text.len());
        assert!(!text.contains("was cut"), "{text}");
        assert!(text.contains("could not be read back"));
        assert!(text.contains(&format!(
            "goal 0\n{}\n…\n```",
            "g".repeat(MAX_GOAL_CHARS - 7)
        )));
        assert!(text.contains("more agents left out)"));
        assert!(text.contains(", and 236 more\n- People: "));
        assert!(text.contains(", and 36 more\n\n## Goals"));
        assert!(text.contains("- modified ` src/file0.rs `"));
        assert!(text.contains("more files\n"));
        assert!(text.contains(&format!(
            "reply 0\n{}…\n```",
            "line\n".repeat(MAX_REPLY_LINES - 1)
        )));
    }

    #[test]
    fn a_draft_without_replies_or_changes_says_so_briefly() {
        let mut quiet = draft();
        quiet.agents[0].last_reply = None;
        quiet.changes.paths.clear();
        let text = quiet.render();
        assert!(!text.contains("## Last replies"), "{text}");
        assert!(text.contains("## Files changed\n\nNone.\n"), "{text}");
    }

    #[test]
    fn many_agents_with_the_longest_names_still_fit_without_a_cut() {
        let name = |index: usize| format!("{index:0>32}");
        let mut crowded = draft();
        crowded.title = "\u{1F600}".repeat(400);
        crowded.agents = (0..200)
            .map(|index| LandedAgent {
                slot: format!("{}.{}", name(index), name(index)),
                goal: Some("g".repeat(5000)),
                goal_cut: true,
                last_reply: Some("r".repeat(5000)),
            })
            .collect();
        crowded.people = (0..200).map(name).collect();
        crowded.changes.paths = (0..5000)
            .map(|index| ("p".repeat(150) + &index.to_string(), Change::Deleted))
            .collect();
        let text = crowded.render();
        assert!(text.len() <= MAX_DRAFT_BYTES, "{}", text.len());
        assert!(!text.contains("was cut"), "{text}");
        assert_eq!(text.matches("more agents left out)").count(), 2, "{text}");
    }
}
