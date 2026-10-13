use std::borrow::Cow;

use ratatui_core::{
    buffer::Buffer,
    layout::{
        Constraint,
        Layout,
        Rect,
    },
    style::{
        Modifier,
        Style,
    },
    text::{
        Line,
        Span,
    },
    widgets::{
        StatefulWidget,
        Widget,
    },
};
use ratatui_widgets::{
    block::Block,
    borders::BorderType,
    list::{
        List,
        ListItem,
        ListState,
    },
    paragraph::{
        Paragraph,
        Wrap,
    },
    table::{
        Row,
        Table,
        TableState,
    },
};

use crate::{
    Answer,
    Dialog,
    PaletteInput,
    Theme,
    dialog::shown,
    key_hints,
};

const MENU: [(&str, &str); 8] = [
    ("Threads", "t"),
    ("New thread", "n"),
    ("Join with a code", "c"),
    ("Remote", "m"),
    ("Credentials", "s"),
    ("Your card", "u"),
    ("Help", "?"),
    ("Quit", "q"),
];
const SIDEBAR_WIDTH: u16 = 24;
const DETAILS_HEIGHT: u16 = 5;
const ACTIVITY_HEIGHT: u16 = 8;

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

/// What the home screen shows besides its threads: the repository, the remote threads go to,
/// who the user is, and what the last actions printed.
#[derive(Debug, Clone, Copy)]
pub struct HomeView<'a> {
    /// The repository's name.
    pub repository: &'a str,
    /// The remote threads are pushed to, or that none is chosen.
    pub remote: &'a str,
    /// The user's participant name.
    pub identity: &'a str,
    /// The repository's threads.
    pub rows: &'a [HomeRow],
    /// What mahi's commands printed, oldest first.
    pub activity: &'a [String],
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
    /// Purge the thread here and on the remote; the purge asks first.
    Purge(String),
    /// Run another of the user's agents in the thread.
    AddAgent(String),
    /// Start the user's agent on another agent's work in the thread.
    Handoff(String),
    /// Merge another agent's work into one of the user's agents in the thread.
    Merge(String),
    /// Push the thread's landed commits, with its trailers.
    Push(String),
    /// Join a thread with a pairing code.
    Join,
    /// Choose the remote threads are pushed to.
    Remote,
    /// Show the user's participant card, which a thread's owner invites them with.
    Card,
    /// Add or remove the tokens agents and remotes sign in with.
    Credentials,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Focus {
    Menu,
    #[default]
    Threads,
}

#[derive(Debug)]
enum Pending {
    ThreadMenu(String, Vec<ThreadChoice>),
    Confirm(HomeAction),
    Help,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ThreadChoice {
    Resume,
    AddAgent,
    Handoff,
    Merge,
    Land,
    Push,
    End,
    Purge,
    Invite,
}

impl ThreadChoice {
    fn label(self) -> &'static str {
        match self {
            Self::Resume => "Resume: start your agent again where it stopped",
            Self::AddAgent => "Add an agent: run another of yours in it, in its own worktree",
            Self::Handoff => "Hand off: start your agent on another agent's latest work",
            Self::Merge => "Merge: bring another agent's work into one of yours",
            Self::Land => "Land: merge its agents' work onto a branch to commit",
            Self::Push => "Push: add the thread's trailers to your commits and push the branch",
            Self::End => "End: save its work in a last snapshot and remove its worktrees",
            Self::Purge => "Purge: delete it here and on the remote, for good",
            Self::Invite => {
                "Invite: show a pairing code so a teammate can watch and prompt it live"
            }
        }
    }
}

/// The home screen's state: where the focus is, what is selected, and a dialog of its own
/// that waits for an answer.
#[derive(Debug, Default)]
pub struct Home {
    focus: Focus,
    menu: usize,
    selected: usize,
    dialog: Option<(Dialog, Pending)>,
    note: Option<&'static str>,
}

impl Home {
    /// Returns the selected row.
    #[must_use]
    pub fn selected(&self) -> usize {
        self.selected
    }

    /// Returns whether one of the home screen's own dialogs is open.
    #[must_use]
    pub fn has_dialog(&self) -> bool {
        self.dialog.is_some()
    }

    /// Keeps the selection on a row that exists after the thread list was read again, and
    /// drops a dialog whose thread is no longer the selected one.
    pub fn fit(&mut self, rows: &[HomeRow]) {
        self.selected = self.selected.min(rows.len().saturating_sub(1));
        let selected = rows.get(self.selected).map(|row| row.thread.as_str());
        let thread = match &self.dialog {
            Some((
                _,
                Pending::ThreadMenu(thread, _)
                | Pending::Confirm(
                    HomeAction::Land(thread) | HomeAction::End(thread) | HomeAction::Resume(thread),
                ),
            )) => Some(thread),
            _ => None,
        };
        let stale = thread.is_some_and(|thread| selected != Some(thread.as_str()));
        if stale {
            self.dialog = None;
        }
    }

    /// Reads one key and returns the action it completes, if any. Landing and ending ask
    /// first; Escape closes a dialog, and quits otherwise. Pasted text is never a key.
    pub fn key(&mut self, input: PaletteInput, rows: &[HomeRow]) -> Option<HomeAction> {
        self.fit(rows);
        self.note = None;
        if let Some((mut dialog, pending)) = self.dialog.take() {
            return match dialog.key(input) {
                None => {
                    self.dialog = Some((dialog, pending));
                    None
                }
                Some(answer) => self.answered(answer, pending),
            };
        }
        let selected = rows.get(self.selected);
        match input {
            PaletteInput::Escape | PaletteInput::Text('q') => return Some(HomeAction::Quit),
            PaletteInput::Tab => {
                self.focus = match self.focus {
                    Focus::Menu => Focus::Threads,
                    Focus::Threads => Focus::Menu,
                };
            }
            PaletteInput::Up | PaletteInput::Text('k') => self.move_by(false, rows.len()),
            PaletteInput::Down | PaletteInput::Text('j') => self.move_by(true, rows.len()),
            PaletteInput::Enter => {
                return match self.focus {
                    Focus::Menu => self.activate(self.menu, rows),
                    Focus::Threads => {
                        self.open_thread_menu(selected);
                        None
                    }
                };
            }
            PaletteInput::Text('t') => self.focus = Focus::Threads,
            PaletteInput::Text('n') => return Some(HomeAction::New),
            PaletteInput::Text('c') => return Some(HomeAction::Join),
            PaletteInput::Text('m') => return Some(HomeAction::Remote),
            PaletteInput::Text('u') => return Some(HomeAction::Card),
            PaletteInput::Text('s') => return Some(HomeAction::Credentials),
            PaletteInput::Text('?') => self.open_help(),
            PaletteInput::Text('r') => match selected {
                Some(row) if row.owned => return Some(HomeAction::Resume(row.thread.clone())),
                Some(_) => self.note = Some("only the thread's owner resumes it"),
                None => {}
            },
            PaletteInput::Text('i') => {
                return selected.map(|row| HomeAction::Invite(row.thread.clone()));
            }
            PaletteInput::Text('l') => self.ask(selected, HomeAction::Land),
            PaletteInput::Text('e') => self.ask(selected, HomeAction::End),
            PaletteInput::Text('p') => {
                return selected.map(|row| HomeAction::Purge(row.thread.clone()));
            }
            PaletteInput::Text('a') => {
                return selected.map(|row| HomeAction::AddAgent(row.thread.clone()));
            }
            PaletteInput::Text('h') => {
                return selected.map(|row| HomeAction::Handoff(row.thread.clone()));
            }
            PaletteInput::Text('g') => {
                return selected.map(|row| HomeAction::Merge(row.thread.clone()));
            }
            _ => {}
        }
        None
    }

    fn move_by(&mut self, down: bool, rows: usize) {
        match (self.focus, down) {
            (Focus::Menu, false) => self.menu = self.menu.saturating_sub(1),
            (Focus::Menu, true) => self.menu = (self.menu + 1).min(MENU.len() - 1),
            (Focus::Threads, false) => self.selected = self.selected.saturating_sub(1),
            (Focus::Threads, true) if self.selected + 1 < rows => self.selected += 1,
            (Focus::Threads, true) => {}
        }
    }

    fn activate(&mut self, item: usize, rows: &[HomeRow]) -> Option<HomeAction> {
        match item {
            0 => {
                self.focus = Focus::Threads;
                if rows.is_empty() {
                    self.note = Some("no threads yet: press n to start one");
                }
                None
            }
            1 => Some(HomeAction::New),
            2 => Some(HomeAction::Join),
            3 => Some(HomeAction::Remote),
            4 => Some(HomeAction::Credentials),
            5 => Some(HomeAction::Card),
            6 => {
                self.open_help();
                None
            }
            _ => Some(HomeAction::Quit),
        }
    }

    fn open_thread_menu(&mut self, selected: Option<&HomeRow>) {
        let Some(row) = selected else {
            self.note = Some("no thread is selected");
            return;
        };
        let mut choices = Vec::with_capacity(9);
        if row.owned {
            choices.push(ThreadChoice::Resume);
        }
        choices.extend([
            ThreadChoice::AddAgent,
            ThreadChoice::Handoff,
            ThreadChoice::Merge,
            ThreadChoice::Land,
            ThreadChoice::Push,
            ThreadChoice::End,
            ThreadChoice::Invite,
            ThreadChoice::Purge,
        ]);
        let labels = choices
            .iter()
            .map(|choice| choice.label().to_owned())
            .collect();
        let dialog = Dialog::choose(
            "Thread",
            vec![format!("{} · {}", row.thread, row.agents)],
            labels,
        );
        self.dialog = Some((dialog, Pending::ThreadMenu(row.thread.clone(), choices)));
    }

    fn ask(&mut self, selected: Option<&HomeRow>, action: fn(String) -> HomeAction) {
        let Some(row) = selected else {
            return;
        };
        let action = action(row.thread.clone());
        let question = match &action {
            HomeAction::Land(thread) => format!(
                "Land thread {thread}? Its agents' work is merged into a landing worktree on a \
                 branch, where you turn it into commits with git, then push them with Push in \
                 the thread's menu."
            ),
            HomeAction::End(thread) => format!(
                "End thread {thread}? Its worktrees are recorded in a last snapshot, then removed. \
                 Its history stays, and resuming it brings the worktrees back."
            ),
            _ => return,
        };
        self.dialog = Some((
            Dialog::confirm("Confirm", vec![question]),
            Pending::Confirm(action),
        ));
    }

    fn open_help(&mut self) {
        let lines = [
            "mahi runs coding agents in a sandbox. A thread is one piece of work: its agents, \
             each in its own worktree, and the history of what they did.",
            "Ending a thread keeps its history; resuming brings its worktrees back. Purging \
             deletes it.",
        ];
        let rows = [
            ["tab", "switch", "move between the menu and the threads"],
            ["↑↓ j k", "move", "go up and down the focused list"],
            ["enter", "open", "open the menu of what is selected"],
            ["n", "new", "start a thread with an agent"],
            ["r", "resume", "start your agent again where it stopped"],
            ["a", "add agent", "run another of your agents in the thread"],
            [
                "h",
                "hand off",
                "start your agent on another agent's latest work",
            ],
            ["g", "merge", "bring another agent's work into one of yours"],
            [
                "l",
                "land",
                "merge its agents' work onto a branch to commit",
            ],
            ["e", "end", "snapshot its work and remove its worktrees"],
            [
                "p",
                "purge",
                "delete the thread here and on the remote, for good",
            ],
            [
                "i",
                "invite",
                "show a code so a teammate can watch and prompt it",
            ],
            ["c", "join", "type a teammate's code to join their thread"],
            [
                "m",
                "remote",
                "choose or add where threads are pushed to be shared",
            ],
            [
                "s",
                "credentials",
                "keep the tokens agents and remotes sign in with",
            ],
            [
                "u",
                "card",
                "show the line a thread's owner invites you with",
            ],
            ["q esc", "quit", "leave mahi"],
        ];
        let dialog = Dialog::table(
            "Help",
            lines.iter().map(|line| (*line).to_owned()).collect(),
            ["key", "action", "what it does"].map(str::to_owned),
            rows.iter().map(|row| row.map(str::to_owned)).collect(),
        );
        self.dialog = Some((dialog, Pending::Help));
    }

    fn answered(&mut self, answer: Answer, pending: Pending) -> Option<HomeAction> {
        match (answer, pending) {
            (Answer::Choice(index), Pending::ThreadMenu(thread, choices)) => {
                match choices.get(index)? {
                    ThreadChoice::Resume => Some(HomeAction::Resume(thread)),
                    ThreadChoice::AddAgent => Some(HomeAction::AddAgent(thread)),
                    ThreadChoice::Handoff => Some(HomeAction::Handoff(thread)),
                    ThreadChoice::Merge => Some(HomeAction::Merge(thread)),
                    ThreadChoice::Push => Some(HomeAction::Push(thread)),
                    ThreadChoice::Invite => Some(HomeAction::Invite(thread)),
                    ThreadChoice::Purge => Some(HomeAction::Purge(thread)),
                    ThreadChoice::Land => {
                        self.ask_for(thread, HomeAction::Land);
                        None
                    }
                    ThreadChoice::End => {
                        self.ask_for(thread, HomeAction::End);
                        None
                    }
                }
            }
            (Answer::Confirmed(true), Pending::Confirm(action)) => Some(action),
            _ => None,
        }
    }

    fn ask_for(&mut self, thread: String, make: fn(String) -> HomeAction) {
        let row = HomeRow {
            thread,
            agents: String::new(),
            worktree: true,
            owned: true,
        };
        self.ask(Some(&row), make);
    }

    /// Draws the home screen into `area`, with `status`, the outcome of the last action, above
    /// the keys.
    pub fn render(&self, view: &HomeView<'_>, status: &str, area: Rect, buffer: &mut Buffer) {
        let [header, body, message, footer] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(area);
        Self::render_header(view, header, buffer);
        let [sidebar, main] =
            Layout::horizontal([Constraint::Length(SIDEBAR_WIDTH), Constraint::Fill(1)])
                .areas(body);
        self.render_menu(sidebar, buffer);
        let [threads, details, activity] = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(DETAILS_HEIGHT),
            Constraint::Length(ACTIVITY_HEIGHT),
        ])
        .areas(main);
        self.render_threads(view.rows, threads, buffer);
        self.render_details(view.rows, details, buffer);
        Self::render_activity(view.activity, activity, buffer);
        let line = self.note.unwrap_or(status);
        Line::from(shown(line).into_owned())
            .style(Style::new().fg(Theme::WARN))
            .render(message, buffer);
        Line::from(self.footer_hints()).render(footer, buffer);
        if let Some((dialog, _)) = &self.dialog {
            dialog.render(area, buffer);
        }
    }

    fn render_header(view: &HomeView<'_>, area: Rect, buffer: &mut Buffer) {
        let bar = Style::new().bg(ratatui_core::style::Color::Indexed(236));
        buffer.set_style(area, bar);
        Line::from(vec![
            Span::styled(" mahi ", Theme::selected()),
            Span::styled(
                format!(" {} ", shown(view.repository)),
                Theme::title().patch(bar),
            ),
            Span::styled("· remote ", Theme::muted().patch(bar)),
            Span::styled(shown(view.remote).into_owned(), bar),
            Span::styled("  · you ", Theme::muted().patch(bar)),
            Span::styled(shown(view.identity).into_owned(), bar),
        ])
        .render(area, buffer);
    }

    fn render_menu(&self, area: Rect, buffer: &mut Buffer) {
        let focused = self.focus == Focus::Menu;
        let items: Vec<ListItem<'_>> = MENU
            .iter()
            .map(|(label, key)| {
                ListItem::new(Line::from(vec![
                    Span::raw(format!(" {label}")),
                    Span::styled(format!("  {key}"), Theme::muted()),
                ]))
            })
            .collect();
        let list = List::new(items)
            .block(panel("Menu", focused))
            .highlight_style(if focused {
                Theme::selected()
            } else {
                Style::new().add_modifier(Modifier::BOLD)
            });
        let mut state = ListState::default().with_selected(Some(self.menu));
        StatefulWidget::render(list, area, buffer, &mut state);
    }

    fn render_threads(&self, rows: &[HomeRow], area: Rect, buffer: &mut Buffer) {
        let focused = self.focus == Focus::Threads;
        let block = panel(&format!("Threads · {}", rows.len()), focused);
        if rows.is_empty() {
            let inner = block.inner(area);
            block.render(area, buffer);
            Paragraph::new(vec![
                Line::default(),
                Line::from(vec![
                    Span::raw("  No threads yet. Press "),
                    Span::styled("n", Theme::title()),
                    Span::raw(" to start one with an agent, or "),
                    Span::styled("c", Theme::title()),
                    Span::raw(" to join a teammate's."),
                ]),
            ])
            .render(inner, buffer);
            return;
        }
        let table = Table::new(
            rows.iter().map(row),
            [
                Constraint::Length(34),
                Constraint::Fill(1),
                Constraint::Length(9),
                Constraint::Length(9),
            ],
        )
        .header(
            Row::new(["thread", "agents", "worktree", "owner"])
                .style(Theme::muted().add_modifier(Modifier::BOLD)),
        )
        .block(block)
        .row_highlight_style(if focused {
            Theme::selected()
        } else {
            Style::new().add_modifier(Modifier::REVERSED)
        })
        .highlight_symbol("› ");
        let mut state = TableState::new().with_selected(self.selected);
        StatefulWidget::render(table, area, buffer, &mut state);
    }

    fn render_details(&self, rows: &[HomeRow], area: Rect, buffer: &mut Buffer) {
        let block = panel("Selected", false);
        let inner = block.inner(area);
        block.render(area, buffer);
        let Some(row) = rows.get(self.selected) else {
            Line::styled("  nothing selected", Theme::muted()).render(inner, buffer);
            return;
        };
        let worktree = if row.worktree {
            "its worktree is here"
        } else {
            "its worktree is gone; resuming rebuilds it"
        };
        let owner = if row.owned {
            "you own it"
        } else {
            "a teammate owns it"
        };
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(format!(" {}", shown(&row.thread)), Theme::title()),
                Span::styled(format!("  {}", shown(&row.agents)), Style::new()),
            ]),
            Line::styled(format!(" {owner} · {worktree}"), Theme::muted()),
            Line::from(key_hints(&[
                ("enter", "actions"),
                ("r", "resume"),
                ("l", "land"),
                ("e", "end"),
                ("p", "purge"),
                ("i", "invite"),
            ])),
        ])
        .render(inner, buffer);
    }

    fn render_activity(activity: &[String], area: Rect, buffer: &mut Buffer) {
        let block = panel("Activity", false);
        let inner = block.inner(area);
        block.render(area, buffer);
        let shown_lines = usize::from(inner.height);
        let start = activity.len().saturating_sub(shown_lines);
        let lines: Vec<Line<'_>> = activity
            .get(start..)
            .unwrap_or_default()
            .iter()
            .map(|line| {
                let style = if line.contains("failed") || line.contains("cannot") {
                    Style::new().fg(Theme::ERROR)
                } else {
                    Theme::muted()
                };
                Line::styled(format!(" {}", shown(line)), style)
            })
            .collect();
        if lines.is_empty() {
            Line::styled(" what mahi does shows here", Theme::muted()).render(inner, buffer);
        } else {
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .render(inner, buffer);
        }
    }

    fn footer_hints(&self) -> Vec<Span<'static>> {
        if self.dialog.is_some() {
            return Vec::new();
        }
        match self.focus {
            Focus::Menu => key_hints(&[
                ("↑↓ jk", "move"),
                ("enter", "open"),
                ("tab", "threads"),
                ("?", "help"),
                ("q", "quit"),
            ]),
            Focus::Threads => key_hints(&[
                ("↑↓ jk", "move"),
                ("enter", "actions"),
                ("n", "new"),
                ("c", "join"),
                ("tab", "menu"),
                ("?", "help"),
                ("q", "quit"),
            ]),
        }
    }
}

fn panel<'a>(title: &str, focused: bool) -> Block<'a> {
    let border = if focused {
        Style::new().fg(Theme::ACCENT)
    } else {
        Theme::muted()
    };
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(border)
        .title(Line::from(format!(" {title} ")).style(if focused {
            Theme::title()
        } else {
            Style::new().add_modifier(Modifier::BOLD)
        }))
}

fn row(row: &HomeRow) -> Row<'_> {
    Row::new([
        shown(&row.thread),
        shown(&row.agents),
        Cow::Borrowed(if row.worktree { "here" } else { "gone" }),
        Cow::Borrowed(if row.owned { "you" } else { "teammate" }),
    ])
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
        screen_in(home, rows, status, Rect::new(0, 0, 110, 32))
    }

    fn screen_in(home: &Home, rows: &[HomeRow], status: &str, area: Rect) -> String {
        let mut buffer = Buffer::empty(area);
        let activity = vec![
            "mahi: ended t0".to_owned(),
            "mahi: cannot reach the remote".to_owned(),
        ];
        let view = HomeView {
            repository: "repo\u{202e}",
            remote: "origin (private)",
            identity: "davy",
            rows,
            activity: &activity,
        };
        home.render(&view, status, area, &mut buffer);
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
    fn arrows_move_the_selection_within_the_focused_list() {
        let rows = rows();
        let mut home = Home::default();
        home.key(PaletteInput::Up, &rows);
        assert_eq!(home.selected(), 0);
        home.key(PaletteInput::Down, &rows);
        home.key(PaletteInput::Down, &rows);
        assert_eq!(home.selected(), 1);
        home.fit(&rows[..1]);
        assert_eq!(home.selected(), 0);
        home.key(PaletteInput::Tab, &rows);
        home.key(PaletteInput::Down, &rows);
        assert_eq!(home.selected(), 0);
        assert!(screen(&home, &rows, "").contains("enter open"));
    }

    #[test]
    fn vim_keys_move_the_selection_and_c_joins() {
        let rows = rows();
        let mut home = Home::default();
        assert_eq!(home.key(PaletteInput::Text('j'), &rows), None);
        assert_eq!(home.selected(), 1);
        home.key(PaletteInput::Text('j'), &rows);
        assert_eq!(home.selected(), 1);
        home.key(PaletteInput::Text('k'), &rows);
        assert_eq!(home.selected(), 0);
        home.key(PaletteInput::Tab, &rows);
        home.key(PaletteInput::Text('j'), &rows);
        home.key(PaletteInput::Text('j'), &rows);
        home.key(PaletteInput::Text('k'), &rows);
        assert_eq!(home.key(PaletteInput::Enter, &rows), Some(HomeAction::New));
        assert_eq!(
            home.key(PaletteInput::Text('c'), &rows),
            Some(HomeAction::Join)
        );
        assert!(screen(&home, &rows, "").contains("↑↓ jk move"));
    }

    #[test]
    fn keys_choose_actions_on_the_selected_thread() {
        let rows = rows();
        let mut home = Home::default();
        assert_eq!(
            keys(&mut home, &rows, "nricmsuq"),
            [
                HomeAction::New,
                HomeAction::Resume("t1".to_owned()),
                HomeAction::Invite("t1".to_owned()),
                HomeAction::Join,
                HomeAction::Remote,
                HomeAction::Credentials,
                HomeAction::Card,
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
    fn the_menu_opens_what_it_names() {
        let rows = rows();
        let mut home = Home::default();
        home.key(PaletteInput::Tab, &rows);
        home.key(PaletteInput::Down, &rows);
        assert_eq!(home.key(PaletteInput::Enter, &rows), Some(HomeAction::New));
        home.key(PaletteInput::Down, &rows);
        home.key(PaletteInput::Down, &rows);
        assert_eq!(
            home.key(PaletteInput::Enter, &rows),
            Some(HomeAction::Remote)
        );
        home.key(PaletteInput::Down, &rows);
        assert_eq!(
            home.key(PaletteInput::Enter, &rows),
            Some(HomeAction::Credentials)
        );
        home.key(PaletteInput::Down, &rows);
        assert_eq!(home.key(PaletteInput::Enter, &rows), Some(HomeAction::Card));
        home.key(PaletteInput::Down, &rows);
        assert_eq!(home.key(PaletteInput::Enter, &rows), None);
        assert!(home.has_dialog());
        let help = screen(&home, &rows, "");
        assert!(help.contains("Help"), "{help}");
        for row in [
            "key     action       what it does",
            "l       land         merge its agents' work onto a branch to commit",
            "e       end          snapshot its work and remove its worktrees",
            "q esc   quit         leave mahi",
        ] {
            assert!(help.contains(row), "{help}");
        }
        let narrow = screen_in(&home, &rows, "", Rect::new(0, 0, 80, 24));
        for row in [
            "r       resume       start your agent again where it stopped",
            "i       invite       show a code so a teammate can watch and prompt it",
            "↑↓ jk scroll",
        ] {
            assert!(narrow.contains(row), "{narrow}");
        }
        for _ in 0..20 {
            assert_eq!(home.key(PaletteInput::Text('j'), &rows), None);
        }
        let scrolled = screen_in(&home, &rows, "", Rect::new(0, 0, 80, 24));
        for row in [
            "s       credentials  keep the tokens agents and remotes sign in with",
            "u       card         show the line a thread's owner invites you with",
            "p       purge        delete the thread here and on the remote, for good",
            "q esc   quit         leave mahi",
        ] {
            assert!(scrolled.contains(row), "{scrolled}");
        }
        assert_eq!(home.key(PaletteInput::Enter, &rows), None);
        assert!(!home.has_dialog());
        home.key(PaletteInput::Tab, &rows);
        assert_eq!(home.key(PaletteInput::Enter, &rows), None);
        let menu = screen_in(&home, &rows, "", Rect::new(0, 0, 80, 24));
        assert!(
            menu.contains("Invite: show a pairing code so a teammate can watch and prompt it "),
            "{menu}"
        );
    }

    #[test]
    fn enter_on_a_thread_opens_its_actions_and_landing_asks_first() {
        let rows = rows();
        let mut home = Home::default();
        assert_eq!(home.key(PaletteInput::Enter, &rows), None);
        let menu = screen(&home, &rows, "");
        assert!(
            menu.contains("Resume: start")
                && menu.contains(
                    "Invite: show a pairing code so a teammate can watch and prompt it live"
                ),
            "{menu}"
        );
        for (digit, action) in [
            ('2', HomeAction::AddAgent("t1".to_owned())),
            ('3', HomeAction::Handoff("t1".to_owned())),
            ('4', HomeAction::Merge("t1".to_owned())),
            ('6', HomeAction::Push("t1".to_owned())),
        ] {
            assert_eq!(home.key(PaletteInput::Text(digit), &rows), Some(action));
            home.key(PaletteInput::Enter, &rows);
        }
        assert_eq!(home.key(PaletteInput::Text('5'), &rows), None);
        assert!(screen(&home, &rows, "").contains("Land thread t1?"));
        assert_eq!(
            home.key(PaletteInput::Text('y'), &rows),
            Some(HomeAction::Land("t1".to_owned()))
        );
        home.key(PaletteInput::Down, &rows);
        home.key(PaletteInput::Enter, &rows);
        let teammate = screen(&home, &rows, "");
        assert!(!teammate.contains("Resume:"), "{teammate}");
        assert_eq!(
            home.key(PaletteInput::Text('7'), &rows),
            Some(HomeAction::Invite("t2".to_owned()))
        );
        home.key(PaletteInput::Enter, &rows);
        assert_eq!(
            home.key(PaletteInput::Text('8'), &rows),
            Some(HomeAction::Purge("t2".to_owned()))
        );
        assert_eq!(
            home.key(PaletteInput::Text('p'), &rows),
            Some(HomeAction::Purge("t2".to_owned()))
        );
        assert!(keys(&mut Home::default(), &[], "p").is_empty());
        assert_eq!(
            keys(&mut home, &rows, "ahg"),
            [
                HomeAction::AddAgent("t2".to_owned()),
                HomeAction::Handoff("t2".to_owned()),
                HomeAction::Merge("t2".to_owned()),
            ]
        );
        assert!(keys(&mut Home::default(), &[], "ahg").is_empty());
    }

    #[test]
    fn landing_and_ending_wait_for_yes_and_anything_else_cancels() {
        let rows = rows();
        let mut home = Home::default();
        assert!(keys(&mut home, &rows, "l").is_empty());
        assert_eq!(
            keys(&mut home, &rows, "y"),
            [HomeAction::Land("t1".to_owned())]
        );
        assert!(keys(&mut home, &rows, "en").is_empty());
        assert!(!home.has_dialog());
        home.key(PaletteInput::Down, &rows);
        assert_eq!(
            keys(&mut home, &rows, "eY"),
            [HomeAction::End("t2".to_owned())]
        );
        assert!(keys(&mut home, &rows, "e").is_empty());
        assert_eq!(home.key(PaletteInput::Pasted('y'), &rows), None);
        assert!(home.has_dialog());
        assert_eq!(home.key(PaletteInput::Escape, &rows), None);
        assert!(!home.has_dialog());
    }

    #[test]
    fn a_dialog_is_dropped_when_its_thread_moves_away() {
        let rows = rows();
        let mut home = Home::default();
        home.key(PaletteInput::Down, &rows);
        assert!(keys(&mut home, &rows, "l").is_empty());
        home.fit(&[rows[0].clone()]);
        assert!(!home.has_dialog());
        assert!(keys(&mut home, &rows, "y").is_empty());
    }

    #[test]
    fn pasted_text_is_never_a_key() {
        let rows = rows();
        let mut home = Home::default();
        for c in "nrleipahgjmsuq?".chars() {
            assert_eq!(home.key(PaletteInput::Pasted(c), &rows), None);
        }
        assert!(!home.has_dialog());
    }

    #[test]
    fn the_screen_shows_header_menu_threads_details_and_activity() {
        let rows = rows();
        let home = Home::default();
        let drawn = screen(&home, &rows, "resumed t1\u{1b}[2J");
        for wanted in [
            "mahi",
            "repo?",
            "origin (private)",
            "davy",
            "Menu",
            "New thread",
            "Threads · 2",
            "› t1",
            "you.claude",
            "teammate",
            "Selected",
            "you own it",
            "Activity",
            "cannot reach the remote",
            "resumed t1?[2J",
            "q quit",
        ] {
            assert!(drawn.contains(wanted), "{wanted:?} missing:\n{drawn}");
        }
        let empty = screen(&home, &[], "");
        assert!(empty.contains("No threads yet"), "{empty}");
        for (width, height) in [(0, 0), (1, 1), (20, 6), (60, 12)] {
            let area = Rect::new(0, 0, width, height);
            let mut buffer = Buffer::empty(area);
            let view = HomeView {
                repository: "r",
                remote: "none",
                identity: "me",
                rows: &rows,
                activity: &[],
            };
            home.render(&view, "", area, &mut buffer);
        }
    }

    #[test]
    fn only_the_owner_resumes_and_is_told_otherwise() {
        let rows = rows();
        let mut home = Home::default();
        home.key(PaletteInput::Down, &rows);
        assert!(keys(&mut home, &rows, "r").is_empty());
        assert!(screen(&home, &rows, "").contains("only the thread's owner resumes it"));
    }
}
