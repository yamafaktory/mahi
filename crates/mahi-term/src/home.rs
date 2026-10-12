use std::borrow::Cow;

use mahi_core::is_invisible;
use ratatui_core::{
    buffer::Buffer,
    layout::{
        Constraint,
        Layout,
        Rect,
    },
    style::{
        Color,
        Modifier,
        Style,
    },
    text::Line,
    widgets::{
        StatefulWidget,
        Widget,
    },
};
use ratatui_widgets::{
    block::Block,
    table::{
        Row,
        Table,
        TableState,
    },
};

use crate::PaletteInput;

/// One thread as the home screen lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeRow {
    /// The thread's id.
    pub thread: String,
    /// Its agents, as `mahi threads` lists them.
    pub agents: String,
    /// Whether its worktree is still here.
    pub worktree: bool,
    /// Whether the user owns it, so it can be resumed.
    pub owned: bool,
}

/// What the user chose on the home screen; a thread is named by its id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HomeAction {
    /// Leave the home screen.
    Quit,
    /// Start a new thread.
    New,
    /// Resume the thread.
    Resume(String),
    /// Land the thread, confirmed.
    Land(String),
    /// End the thread, confirmed.
    End(String),
    /// Invite a teammate to the thread.
    Invite(String),
    /// Join a thread with a pairing code.
    Join,
}

/// The home screen: which thread is selected, and an action waiting for its `y`.
#[derive(Debug, Default)]
pub struct Home {
    selected: usize,
    confirming: Option<HomeAction>,
    note: Option<&'static str>,
}

impl Home {
    /// Returns the selected row.
    #[must_use]
    pub fn selected(&self) -> usize {
        self.selected
    }

    /// Keeps the selection on a row that exists after the thread list was read again, and
    /// drops a confirmation whose thread is no longer the selected one.
    pub fn fit(&mut self, rows: &[HomeRow]) {
        self.selected = self.selected.min(rows.len().saturating_sub(1));
        let selected = rows.get(self.selected).map(|row| row.thread.as_str());
        if let Some(HomeAction::Land(thread) | HomeAction::End(thread)) = &self.confirming
            && selected != Some(thread.as_str())
        {
            self.confirming = None;
        }
    }

    /// Reads one key and returns the action it completes, if any. Landing and ending wait for
    /// `y`; any other key cancels them, and Escape quits even then. Pasted text is never a key.
    pub fn key(&mut self, input: PaletteInput, rows: &[HomeRow]) -> Option<HomeAction> {
        self.fit(rows);
        self.note = None;
        if input == PaletteInput::Escape {
            self.confirming = None;
            return Some(HomeAction::Quit);
        }
        if let Some(waiting) = self.confirming.take() {
            return matches!(input, PaletteInput::Text('y' | 'Y')).then_some(waiting);
        }
        let selected = rows.get(self.selected);
        let thread = || selected.map(|row| row.thread.clone());
        match input {
            PaletteInput::Up => self.selected = self.selected.saturating_sub(1),
            PaletteInput::Down if self.selected + 1 < rows.len() => self.selected += 1,
            PaletteInput::Text('q') => return Some(HomeAction::Quit),
            PaletteInput::Text('n') => return Some(HomeAction::New),
            PaletteInput::Text('j') => return Some(HomeAction::Join),
            PaletteInput::Text('r') => match selected {
                Some(row) if row.owned => return Some(HomeAction::Resume(row.thread.clone())),
                Some(_) => self.note = Some("only the thread's owner resumes it"),
                None => {}
            },
            PaletteInput::Text('i') => return thread().map(HomeAction::Invite),
            PaletteInput::Text('l') => self.confirming = thread().map(HomeAction::Land),
            PaletteInput::Text('e') => self.confirming = thread().map(HomeAction::End),
            _ => {}
        }
        None
    }

    /// Draws the home screen for `repository`'s `rows` into `area`, with `status`, the outcome
    /// of the last action, in the footer.
    pub fn render(
        &self,
        repository: &str,
        rows: &[HomeRow],
        status: &str,
        area: Rect,
        buffer: &mut Buffer,
    ) {
        let [list, footer] =
            Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).areas(area);
        let title = format!(" mahi · {} ", shown(repository));
        let block = Block::bordered().title(Line::from(title).style(bold()));
        if rows.is_empty() {
            let inner = block.inner(list);
            block.render(list, buffer);
            Line::from("No threads yet: press n to start one with an agent.").render(inner, buffer);
        } else {
            let table = Table::new(
                rows.iter().map(row),
                [
                    Constraint::Length(36),
                    Constraint::Fill(1),
                    Constraint::Length(11),
                    Constraint::Length(9),
                ],
            )
            .header(Row::new(["thread", "agents", "worktree", "owner"]).style(bold()))
            .block(block)
            .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED))
            .highlight_symbol("› ");
            let mut state = TableState::new().with_selected(self.selected);
            StatefulWidget::render(table, list, buffer, &mut state);
        }
        let [message, keys] =
            Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(footer);
        let asked;
        let line = match (&self.confirming, self.note) {
            (Some(HomeAction::Land(thread)), _) => {
                asked = format!("Land thread {thread}? [y/N]");
                asked.as_str()
            }
            (Some(HomeAction::End(thread)), _) => {
                asked = format!("End thread {thread}? [y/N]");
                asked.as_str()
            }
            (_, Some(note)) => note,
            _ => status,
        };
        Line::from(shown(line))
            .style(Style::new().fg(Color::Yellow))
            .render(message, buffer);
        Line::from("n new · r resume · l land · e end · i invite · j join · ↑↓ select · q quit")
            .style(Style::new().add_modifier(Modifier::DIM))
            .render(keys, buffer);
    }
}

fn bold() -> Style {
    Style::new().add_modifier(Modifier::BOLD)
}

fn row(row: &HomeRow) -> Row<'_> {
    Row::new([
        shown(&row.thread),
        shown(&row.agents),
        Cow::Borrowed(if row.worktree { "here" } else { "gone" }),
        Cow::Borrowed(if row.owned { "you" } else { "teammate" }),
    ])
}

fn shown(text: &str) -> Cow<'_, str> {
    if text.chars().any(hidden) {
        Cow::Owned(
            text.chars()
                .map(|c| if hidden(c) { '?' } else { c })
                .collect(),
        )
    } else {
        Cow::Borrowed(text)
    }
}

fn hidden(c: char) -> bool {
    c.is_control() || is_invisible(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows() -> Vec<HomeRow> {
        vec![
            HomeRow {
                thread: "t1".to_owned(),
                agents: "you.claude".to_owned(),
                worktree: true,
                owned: true,
            },
            HomeRow {
                thread: "t2".to_owned(),
                agents: "bob.codex".to_owned(),
                worktree: false,
                owned: false,
            },
        ]
    }

    fn keys(home: &mut Home, rows: &[HomeRow], typed: &str) -> Vec<HomeAction> {
        typed
            .chars()
            .filter_map(|c| home.key(PaletteInput::Text(c), rows))
            .collect()
    }

    fn screen(home: &Home, rows: &[HomeRow], status: &str) -> String {
        let area = Rect::new(0, 0, 90, 10);
        let mut buffer = Buffer::empty(area);
        home.render("repo\u{202e}", rows, status, area, &mut buffer);
        (0..area.height)
            .map(|y| {
                (0..area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
                    + "\n"
            })
            .collect()
    }

    #[test]
    fn arrows_move_the_selection_within_the_list() {
        let rows = rows();
        let mut home = Home::default();
        home.key(PaletteInput::Up, &rows);
        assert_eq!(home.selected(), 0);
        home.key(PaletteInput::Down, &rows);
        home.key(PaletteInput::Down, &rows);
        assert_eq!(home.selected(), 1);
        home.fit(&rows[..1]);
        assert_eq!(home.selected(), 0);
        home.fit(&[]);
        assert_eq!(home.selected(), 0);
        home.key(PaletteInput::Down, &rows);
        assert_eq!(home.selected(), 1);
        assert!(keys(&mut home, &rows[..1], "r").contains(&HomeAction::Resume("t1".to_owned())));
    }

    #[test]
    fn keys_choose_actions_on_the_selected_thread() {
        let rows = rows();
        let mut home = Home::default();
        assert_eq!(
            keys(&mut home, &rows, "nrijq"),
            [
                HomeAction::New,
                HomeAction::Resume("t1".to_owned()),
                HomeAction::Invite("t1".to_owned()),
                HomeAction::Join,
                HomeAction::Quit,
            ]
        );
        assert_eq!(
            home.key(PaletteInput::Escape, &rows),
            Some(HomeAction::Quit)
        );
        assert!(keys(&mut home, &[], "rile").is_empty());
    }

    #[test]
    fn only_the_owner_resumes_and_is_told_otherwise() {
        let rows = rows();
        let mut home = Home::default();
        home.key(PaletteInput::Down, &rows);
        assert!(keys(&mut home, &rows, "r").is_empty());
        assert!(screen(&home, &rows, "").contains("only the thread's owner resumes it"));
    }

    #[test]
    fn landing_and_ending_wait_for_y_and_anything_else_cancels() {
        let rows = rows();
        let mut home = Home::default();
        assert!(keys(&mut home, &rows, "l").is_empty());
        assert!(screen(&home, &rows, "").contains("Land thread t1? [y/N]"));
        assert_eq!(
            keys(&mut home, &rows, "y"),
            [HomeAction::Land("t1".to_owned())]
        );
        assert!(keys(&mut home, &rows, "en").is_empty());
        assert!(keys(&mut home, &rows, "y").is_empty());
        home.key(PaletteInput::Down, &rows);
        assert_eq!(
            keys(&mut home, &rows, "eY"),
            [HomeAction::End("t2".to_owned())]
        );
        assert!(keys(&mut home, &rows, "e").is_empty());
        assert_eq!(home.key(PaletteInput::Pasted('y'), &rows), None);
        assert!(keys(&mut home, &rows, "y").is_empty());
    }

    #[test]
    fn escape_quits_even_while_a_confirmation_waits() {
        let rows = rows();
        let mut home = Home::default();
        assert!(keys(&mut home, &rows, "e").is_empty());
        assert_eq!(
            home.key(PaletteInput::Escape, &rows),
            Some(HomeAction::Quit)
        );
        assert!(keys(&mut home, &rows, "y").is_empty());
    }

    #[test]
    fn a_confirmation_is_dropped_when_its_thread_moves_away() {
        let rows = rows();
        let mut home = Home::default();
        home.key(PaletteInput::Down, &rows);
        assert!(keys(&mut home, &rows, "l").is_empty());
        let reread = vec![rows[0].clone()];
        home.fit(&reread);
        assert!(keys(&mut home, &reread, "y").is_empty());
        let swapped = vec![rows[1].clone(), rows[0].clone()];
        assert!(keys(&mut home, &rows, "e").is_empty());
        assert!(keys(&mut home, &swapped, "y").is_empty());
    }

    #[test]
    fn pasted_text_is_never_a_key() {
        let rows = rows();
        let mut home = Home::default();
        for c in "nrleijq".chars() {
            assert_eq!(home.key(PaletteInput::Pasted(c), &rows), None);
        }
    }

    #[test]
    fn the_screen_lists_threads_with_their_state_and_shows_hidden_characters_as_marks() {
        let rows = rows();
        let home = Home::default();
        let drawn = screen(&home, &rows, "resumed t1\u{1b}[2J");
        assert!(drawn.contains("mahi · repo?"), "{drawn}");
        assert!(drawn.contains("› t1"), "{drawn}");
        assert!(drawn.contains("you.claude"), "{drawn}");
        assert!(drawn.contains("gone"), "{drawn}");
        assert!(drawn.contains("teammate"), "{drawn}");
        assert!(drawn.contains("resumed t1?[2J"), "{drawn}");
        assert!(drawn.contains("q quit"), "{drawn}");
        let empty = screen(&home, &[], "");
        assert!(empty.contains("press n to start one"), "{empty}");
    }
}
