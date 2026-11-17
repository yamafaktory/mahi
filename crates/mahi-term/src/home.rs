use std::borrow::Cow;

use ratatui_core::{
    buffer::{
        Buffer,
        CellWidth as _,
    },
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
    Header,
    PaletteInput,
    PaletteKey,
    Preselected,
    Theme,
    dialog::shown,
    key_hints,
};

const NO_THREADS: &str = "no threads yet: press n to start one";
const ACTIVITY_HEIGHT: u16 = 8;
const ACTIVITY_LEAST: u16 = 3;
const THREADS_LEAST: u16 = 4;
const THREAD_WIDTH: u16 = 34;
const SHORT_THREAD: u16 = 8;
const AGENTS_LEAST: u16 = 16;
const LAST_ACTIVE: &str = "last active";

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
    /// When it was last active, such as `3m ago`, once mahi could read it.
    pub last_active: Option<String>,
}

/// What the home screen shows besides its threads: the repository, the remote threads go to,
/// who the user is, and what the last actions printed.
#[derive(Debug, Clone, Copy)]
pub struct HomeView<'a> {
    /// What the top row says on its right.
    pub header: Header<'a>,
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
    /// End the thread, confirmed.
    End(String),
    /// Invite a teammate to the thread.
    Invite(String),
    /// Purge the thread here and on the remote; the purge asks first.
    Purge(String),
    /// Join a thread with a pairing code.
    Join,
    /// Choose the remote threads are pushed to.
    Remote,
    /// Show the user's participant card, which a thread's owner invites them with.
    Card,
    /// Add or remove the tokens agents and remotes sign in with.
    Credentials,
}

#[derive(Debug)]
enum Pending {
    ThreadMenu(String, Vec<ThreadChoice>),
    Confirm(HomeAction),
    Help,
}

/// An action on a thread, as its menu lists it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadChoice {
    /// Start the user's agent again where it stopped.
    Resume,
    /// End the thread, confirmed.
    End,
    /// Purge the thread here and on the remote.
    Purge,
    /// Invite a teammate to the thread.
    Invite,
}

impl ThreadChoice {
    /// Returns what the menu says of the choice.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Resume => "Resume: start your agent again where it stopped",
            Self::End => "End: save its work in a last snapshot and remove its worktrees",
            Self::Purge => "Purge: delete it here and on the remote, for good",
            Self::Invite => {
                "Invite: show a pairing code so a teammate can watch and prompt it live"
            }
        }
    }

    /// Returns the action the choice takes on `thread`.
    #[must_use]
    pub fn action(self, thread: String) -> HomeAction {
        match self {
            Self::Resume => HomeAction::Resume(thread),
            Self::End => HomeAction::End(thread),
            Self::Purge => HomeAction::Purge(thread),
            Self::Invite => HomeAction::Invite(thread),
        }
    }
}

impl ThreadChoice {
    /// Returns the key that takes the choice on the selected thread.
    #[must_use]
    pub fn key(self) -> char {
        match self {
            Self::Resume => 'r',
            Self::End => 'e',
            Self::Purge => 'p',
            Self::Invite => 'i',
        }
    }
}

/// What the user can do on the home screen, each with the key that does it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomeCommand {
    /// Act on the selected thread.
    Thread(ThreadChoice),
    /// Start a new thread.
    New,
    /// Join a thread with a pairing code.
    Join,
    /// Choose the remote threads are pushed to.
    Remote,
    /// Add or remove the tokens agents and remotes sign in with.
    Credentials,
    /// Show the user's participant card.
    Card,
    /// Show the keys and what they do.
    Help,
    /// Leave mahi.
    Quit,
}

/// Every command of the home screen, in the order its palette and its help list them.
pub const HOME_COMMANDS: [HomeCommand; 11] = [
    HomeCommand::Thread(ThreadChoice::Resume),
    HomeCommand::Thread(ThreadChoice::End),
    HomeCommand::Thread(ThreadChoice::Invite),
    HomeCommand::Thread(ThreadChoice::Purge),
    HomeCommand::New,
    HomeCommand::Join,
    HomeCommand::Remote,
    HomeCommand::Credentials,
    HomeCommand::Card,
    HomeCommand::Help,
    HomeCommand::Quit,
];

impl HomeCommand {
    /// Returns the key that runs the command.
    #[must_use]
    pub fn key(self) -> char {
        match self {
            Self::Thread(choice) => choice.key(),
            Self::New => 'n',
            Self::Join => 'J',
            Self::Remote => 'm',
            Self::Credentials => 's',
            Self::Card => 'u',
            Self::Help => '?',
            Self::Quit => 'q',
        }
    }

    /// Returns the command `key` runs, if any.
    #[must_use]
    pub fn from_key(key: char) -> Option<Self> {
        HOME_COMMANDS
            .into_iter()
            .find(|command| command.key() == key)
    }

    /// Returns what a menu says of the command.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Thread(choice) => choice.label(),
            Self::New => "New thread",
            Self::Join => "Join with a code",
            Self::Remote => "Remote",
            Self::Credentials => "Credentials",
            Self::Card => "Your card",
            Self::Help => "Help",
            Self::Quit => "Quit mahi",
        }
    }

    fn help(self) -> Option<[&'static str; 2]> {
        Some(match self {
            Self::Thread(ThreadChoice::Resume) => {
                ["resume", "start your agent again where it stopped"]
            }
            Self::Thread(ThreadChoice::End) => {
                ["end", "snapshot its work and remove its worktrees"]
            }
            Self::Thread(ThreadChoice::Invite) => [
                "invite",
                "show a code so a teammate can watch and prompt it",
            ],
            Self::Thread(ThreadChoice::Purge) => [
                "purge",
                "delete the thread here and on the remote, for good",
            ],
            Self::New => ["new", "start a thread with an agent"],
            Self::Join => ["join", "type a teammate's code to join their thread"],
            Self::Remote => [
                "remote",
                "choose or add where threads are pushed to be shared",
            ],
            Self::Credentials => [
                "credentials",
                "keep the tokens agents and remotes sign in with",
            ],
            Self::Card => ["card", "show the line a thread's owner invites you with"],
            Self::Quit => ["quit", "leave mahi"],
            Self::Help => return None,
        })
    }
}

impl HomeAction {
    /// Returns the question asked before the action runs, for the actions confirmed first.
    #[must_use]
    pub fn question(&self) -> Option<String> {
        match self {
            Self::End(thread) => Some(format!(
                "End thread {thread}? Its worktrees are recorded in a last snapshot, then removed. \
                 Its history stays, and resuming it brings the worktrees back."
            )),
            _ => None,
        }
    }
}

/// The home screen's state: where the focus is, what is selected, and a dialog of its own
/// that waits for an answer.
#[derive(Debug, Default)]
pub struct Home {
    palette_key: PaletteKey,
    selected: usize,
    dialog: Option<(Dialog, Pending)>,
    note: Option<&'static str>,
}

impl Home {
    /// Returns the home screen whose palette opens with `palette_key`.
    #[must_use]
    pub fn new(palette_key: PaletteKey) -> Self {
        Self {
            palette_key,
            ..Self::default()
        }
    }

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
                | Pending::Confirm(HomeAction::End(thread) | HomeAction::Resume(thread)),
            )) => Some(thread),
            _ => None,
        };
        let stale = thread.is_some_and(|thread| selected != Some(thread.as_str()));
        if stale {
            self.dialog = None;
        }
    }

    /// Reads one key and returns the action it completes, if any. Ending asks first; Escape closes a dialog, and quits otherwise. Pasted text is never a key.
    pub fn key(&mut self, input: PaletteInput, rows: &[HomeRow]) -> Option<HomeAction> {
        self.fit(rows);
        self.note = None;
        if let Some((mut dialog, pending)) = self.dialog.take() {
            if let (Pending::ThreadMenu(_, choices), PaletteInput::Text(typed)) = (&pending, input)
                && let Some(index) = choices.iter().position(|choice| choice.key() == typed)
            {
                return self.answered(Answer::Choice(index), pending);
            }
            return match dialog.key(input) {
                None => {
                    self.dialog = Some((dialog, pending));
                    None
                }
                Some(answer) => self.answered(answer, pending),
            };
        }
        match input {
            PaletteInput::Escape => return Some(HomeAction::Quit),
            PaletteInput::Up | PaletteInput::Text('k') => {
                self.selected = self.selected.saturating_sub(1);
            }
            PaletteInput::Down | PaletteInput::Text('j') if self.selected + 1 < rows.len() => {
                self.selected += 1;
            }
            PaletteInput::Enter => self.open_thread_menu(rows.get(self.selected)),
            PaletteInput::Text(typed) => {
                return HomeCommand::from_key(typed).and_then(|command| self.run(command, rows));
            }
            _ => {}
        }
        None
    }

    /// Runs `command` as its key does on the thread list of `rows`, and returns the action it
    /// completes, if any: a thread's command acts on the selected one, ending asks first.
    pub fn run(&mut self, command: HomeCommand, rows: &[HomeRow]) -> Option<HomeAction> {
        self.fit(rows);
        self.note = None;
        let choice = match command {
            HomeCommand::Thread(choice) => choice,
            HomeCommand::New => return Some(HomeAction::New),
            HomeCommand::Join => return Some(HomeAction::Join),
            HomeCommand::Remote => return Some(HomeAction::Remote),
            HomeCommand::Credentials => return Some(HomeAction::Credentials),
            HomeCommand::Card => return Some(HomeAction::Card),
            HomeCommand::Quit => return Some(HomeAction::Quit),
            HomeCommand::Help => {
                self.open_help();
                return None;
            }
        };
        let Some(row) = rows.get(self.selected) else {
            self.note = Some(NO_THREADS);
            return None;
        };
        if choice == ThreadChoice::Resume && !row.owned {
            self.note = Some("only the thread's owner resumes it");
            return None;
        }
        self.confirm(choice.action(row.thread.clone()))
    }

    fn open_thread_menu(&mut self, selected: Option<&HomeRow>) {
        let Some(row) = selected else {
            self.note = Some(NO_THREADS);
            return;
        };
        let mut choices = Vec::with_capacity(4);
        if row.owned {
            choices.push(ThreadChoice::Resume);
        }
        choices.extend([ThreadChoice::End, ThreadChoice::Invite, ThreadChoice::Purge]);
        let items = choices
            .iter()
            .map(|choice| (choice.label().to_owned(), choice.key().to_string()))
            .collect();
        let mut dialog = Dialog::menu("Thread", items);
        dialog.push_line(&format!("{} · {}", row.thread, row.agents));
        self.dialog = Some((dialog, Pending::ThreadMenu(row.thread.clone(), choices)));
    }

    fn confirm(&mut self, action: HomeAction) -> Option<HomeAction> {
        let Some(question) = action.question() else {
            return Some(action);
        };
        self.dialog = Some((
            Dialog::confirm("Confirm", vec![question], Preselected::No),
            Pending::Confirm(action),
        ));
        None
    }

    fn open_help(&mut self) {
        let lines = vec![
            "mahi runs coding agents in a sandbox. A thread is one piece of work: its agents, \
             each in its own worktree, and the history of what they did."
                .to_owned(),
            "Ending a thread keeps its history; resuming brings its worktrees back. Purging \
             deletes it."
                .to_owned(),
            format!(
                "{} opens the palette, which lists every action with its key.",
                self.palette_key
            ),
        ];
        let mut rows = vec![
            ["↑↓ j k", "move", "go up and down the threads"].map(str::to_owned),
            ["enter", "open", "open the menu of what is selected"].map(str::to_owned),
        ];
        let commands = HOME_COMMANDS.into_iter().filter_map(|command| {
            let [action, what] = command.help()?;
            let mut key = command.key().to_string();
            if command == HomeCommand::Quit {
                key.push_str(" esc");
            }
            Some([key, action.to_owned(), what.to_owned()])
        });
        rows.extend(commands);
        let dialog = Dialog::table(
            "Help",
            lines,
            ["key", "action", "what it does"].map(str::to_owned),
            rows,
        );
        self.dialog = Some((dialog, Pending::Help));
    }

    fn answered(&mut self, answer: Answer, pending: Pending) -> Option<HomeAction> {
        match (answer, pending) {
            (Answer::Choice(index), Pending::ThreadMenu(thread, choices)) => {
                self.confirm(choices.get(index)?.action(thread))
            }
            (Answer::Confirmed(true), Pending::Confirm(action)) => Some(action),
            _ => None,
        }
    }

    /// Draws the home screen into `area`, with `status`, the outcome of the last action, on the
    /// Activity panel's last rows.
    pub fn render(&self, view: &HomeView<'_>, status: &str, area: Rect, buffer: &mut Buffer) {
        let [body, footer] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(1)]).areas(area);
        let main = body;
        let activity_rows = ACTIVITY_HEIGHT
            .min(main.height.saturating_sub(THREADS_LEAST))
            .max(ACTIVITY_LEAST)
            .min(main.height);
        let [threads, activity] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(activity_rows)]).areas(main);
        self.render_threads(view.rows, threads, buffer);
        Self::render_activity(view.activity, self.note.unwrap_or(status), activity, buffer);
        Line::from(self.footer_hints()).render(footer, buffer);
        if let Some((dialog, _)) = &self.dialog {
            dialog.render(area, buffer);
        }
    }

    fn render_threads(&self, rows: &[HomeRow], area: Rect, buffer: &mut Buffer) {
        let block = panel(&format!("Threads · {}", rows.len()), true);
        if rows.is_empty() {
            let inner = block.inner(area);
            block.render(area, buffer);
            Paragraph::new(vec![
                Line::default(),
                Line::from(vec![
                    Span::raw("  No threads yet. Press "),
                    Span::styled("n", Theme::title()),
                    Span::raw(" to start one with an agent, or "),
                    Span::styled("J", Theme::title()),
                    Span::raw(" to join a teammate's."),
                ]),
            ])
            .render(inner, buffer);
            return;
        }
        let wanted = rows
            .iter()
            .filter_map(|row| row.last_active.as_deref())
            .map(|text| shown(text).chars().count())
            .max()
            .map(|width| u16::try_from(width.max(LAST_ACTIVE.len())).unwrap_or(u16::MAX));
        let (full, active) = columns(block.inner(area).width, wanted);
        let mut widths = vec![
            Constraint::Length(if full { THREAD_WIDTH } else { SHORT_THREAD }),
            Constraint::Fill(1),
            Constraint::Length(9),
        ];
        let mut header = vec!["thread", "agents", "worktree"];
        if let Some(width) = active {
            widths.push(Constraint::Length(width));
            header.push(LAST_ACTIVE);
        }
        widths.push(Constraint::Length(9));
        header.push("owner");
        let table = Table::new(rows.iter().map(|thread| row(thread, full, active)), widths)
            .header(Row::new(header).style(Theme::muted().add_modifier(Modifier::BOLD)))
            .block(block)
            .row_highlight_style(Theme::selected())
            .highlight_symbol("› ");
        let mut state = TableState::new().with_selected(self.selected);
        StatefulWidget::render(table, area, buffer, &mut state);
    }

    /// Draws what mahi's commands printed, oldest first, with `status`, the outcome of the last
    /// action, on the last row below them.
    fn render_activity(activity: &[String], status: &str, area: Rect, buffer: &mut Buffer) {
        let block = panel("Activity", false);
        let inner = block.inner(area);
        block.render(area, buffer);
        let status = format!(" {}", shown(status));
        let mut lines = if status.trim().is_empty() {
            Vec::new()
        } else {
            status_lines(&status, usize::from(inner.width))
        };
        let kept = lines.len().min(usize::from(inner.height));
        lines.drain(..lines.len() - kept);
        let told = u16::try_from(kept).unwrap_or(u16::MAX);
        let [printed, last] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(told)]).areas(inner);
        for (line, row) in lines.into_iter().zip(last.rows()) {
            Line::styled(line, Style::new().fg(Theme::palette().warn)).render(row, buffer);
        }
        let shown_lines = usize::from(printed.height);
        let start = activity.len().saturating_sub(shown_lines);
        let lines: Vec<Line<'_>> = activity
            .get(start..)
            .unwrap_or_default()
            .iter()
            .map(|line| {
                let style = if line.contains("failed") || line.contains("cannot") {
                    Style::new().fg(Theme::palette().removed)
                } else {
                    Theme::muted()
                };
                Line::styled(format!(" {}", shown(line)), style)
            })
            .collect();
        if lines.is_empty() && told == 0 {
            Line::styled(" what mahi does shows here", Theme::muted()).render(printed, buffer);
        } else {
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .render(printed, buffer);
        }
    }

    /// Returns the keys the footer names: the palette's, which lists every action, help and
    /// quitting; none while a dialog shows.
    fn footer_hints(&self) -> Vec<Span<'static>> {
        if self.dialog.is_some() {
            return Vec::new();
        }
        let palette = self.palette_key.to_string();
        key_hints(&[(palette.as_str(), "palette"), ("?", "help"), ("q", "quit")])
    }
}

/// Cuts `text` into lines at most `width` columns wide as the screen draws them, breaking at
/// the last space that fits, which is left out, or, in a word longer than a line, before the
/// character that does not fit.
fn status_lines(text: &str, width: usize) -> Vec<&str> {
    let columns =
        |from: usize, to: usize| usize::from(text.get(from..to).unwrap_or_default().cell_width());
    let mut lines = Vec::new();
    let mut start = 0;
    let mut space = None;
    for (at, c) in text.char_indices() {
        let end = at + c.len_utf8();
        while at > start && columns(start, end) > width {
            if let Some(gap) = space.filter(|&gap| gap > start && c != ' ') {
                lines.push(text.get(start..gap).unwrap_or_default());
                start = gap + 1;
                space = None;
                continue;
            }
            lines.push(text.get(start..at).unwrap_or_default());
            start = if c == ' ' { end } else { at };
            space = None;
        }
        if c == ' ' && start <= at {
            space = Some(at);
        }
    }
    if start < text.len() || lines.is_empty() {
        lines.push(text.get(start..).unwrap_or_default());
    }
    lines
}

fn panel<'a>(title: &str, focused: bool) -> Block<'a> {
    let border = Style::new().fg(if focused {
        Theme::palette().accent
    } else {
        Theme::palette().border
    });
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(border)
        .title(Line::from(format!(" {title} ")).style(if focused {
            Theme::title()
        } else {
            Style::new().add_modifier(Modifier::BOLD)
        }))
}

/// Returns the thread list's columns that fit in `width` cells: whether the whole thread id
/// shows, and the last active column of `wanted` cells, kept only while the agents still get
/// [`AGENTS_LEAST`] cells, before the whole id.
fn columns(width: u16, wanted: Option<u16>) -> (bool, Option<u16>) {
    let fits = |id: u16, active: Option<u16>| {
        width >= id + 9 + 9 + 5 + AGENTS_LEAST + active.map_or(0, |active| active + 1)
    };
    match wanted {
        Some(active) if fits(THREAD_WIDTH, Some(active)) => (true, Some(active)),
        Some(active) if fits(SHORT_THREAD, Some(active)) => (false, Some(active)),
        Some(_) | None => (fits(THREAD_WIDTH, None), None),
    }
}

fn row(row: &HomeRow, full: bool, active: Option<u16>) -> Row<'_> {
    let thread = if full {
        shown(&row.thread)
    } else {
        Cow::Owned(
            shown(&row.thread)
                .chars()
                .take(usize::from(SHORT_THREAD))
                .collect(),
        )
    };
    let last_active = active.map(|_| row.last_active.as_deref().map_or(Cow::Borrowed(""), shown));
    let cells = [
        thread,
        shown(&row.agents),
        Cow::Borrowed(if row.worktree { "here" } else { "gone" }),
    ]
    .into_iter()
    .chain(last_active)
    .chain([Cow::Borrowed(if row.owned { "you" } else { "teammate" })]);
    Row::new(cells)
}

#[cfg(test)]
mod tests {
    use unicode_width::UnicodeWidthStr as _;

    use super::*;

    fn rows() -> Vec<HomeRow> {
        vec![
            HomeRow {
                thread: "t1".to_owned(),
                agents: "you.claude".to_owned(),
                worktree: true,
                owned: true,
                last_active: None,
            },
            HomeRow {
                thread: "t2".to_owned(),
                agents: "bob.codex".to_owned(),
                worktree: false,
                owned: false,
                last_active: None,
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
            header: Header {
                repository: "repo\u{202e}",
                remote: "origin (private)",
                remote_chosen: true,
                remote_key: true,
                identity: "davy",
            },
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
    fn arrows_move_the_selection_within_the_thread_list() {
        let rows = rows();
        let mut home = Home::default();
        home.key(PaletteInput::Up, &rows);
        assert_eq!(home.selected(), 0);
        home.key(PaletteInput::Down, &rows);
        home.key(PaletteInput::Down, &rows);
        assert_eq!(home.selected(), 1);
        home.fit(&rows[..1]);
        assert_eq!(home.selected(), 0);
        home.key(PaletteInput::Down, &rows[..1]);
        assert_eq!(home.selected(), 0);
    }

    #[test]
    fn vim_keys_move_the_selection_and_shift_j_joins() {
        let rows = rows();
        let mut home = Home::default();
        assert_eq!(home.key(PaletteInput::Text('j'), &rows), None);
        assert_eq!(home.selected(), 1);
        home.key(PaletteInput::Text('j'), &rows);
        assert_eq!(home.selected(), 1);
        home.key(PaletteInput::Text('k'), &rows);
        assert_eq!(home.selected(), 0);
        assert_eq!(home.key(PaletteInput::Text('c'), &rows), None);
        assert_eq!(
            home.key(PaletteInput::Text('J'), &rows),
            Some(HomeAction::Join)
        );
    }

    #[test]
    fn keys_choose_actions_on_the_selected_thread() {
        let rows = rows();
        let mut home = Home::default();
        assert_eq!(
            keys(&mut home, &rows, "nriJmsuq"),
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
    fn each_home_command_has_a_key_of_its_own_that_runs_it() {
        let rows = rows();
        let keys: std::collections::BTreeSet<char> =
            HOME_COMMANDS.iter().map(|command| command.key()).collect();
        assert_eq!(keys.len(), HOME_COMMANDS.len());
        for command in HOME_COMMANDS {
            assert_eq!(HomeCommand::from_key(command.key()), Some(command));
            let (mut typed, mut run) = (Home::default(), Home::default());
            assert_eq!(
                typed.key(PaletteInput::Text(command.key()), &rows),
                run.run(command, &rows),
                "{command:?}"
            );
            assert_eq!(typed.has_dialog(), run.has_dialog(), "{command:?}");
        }
    }

    #[test]
    fn help_lists_the_palette_key_and_each_action_with_its_key() {
        let rows = rows();
        let mut home = Home::new(PaletteKey::default());
        assert_eq!(home.key(PaletteInput::Text('?'), &rows), None);
        assert!(home.has_dialog());
        let help = screen(&home, &rows, "");
        assert!(help.contains("Help"), "{help}");
        for row in [
            "Ctrl-Space opens the palette, which lists every action with its key.",
            "key     action       what it does",
            "e       end          snapshot its work and remove its worktrees",
            "q esc   quit         leave mahi",
        ] {
            assert!(help.contains(row), "{help}");
        }
        assert!(!help.contains("tab "), "{help}");
        let narrow = screen_in(&home, &rows, "", Rect::new(0, 0, 80, 23));
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
        let scrolled = screen_in(&home, &rows, "", Rect::new(0, 0, 80, 23));
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
    }

    #[test]
    fn enter_on_a_thread_opens_its_actions_with_their_keys_and_ending_asks_first() {
        let rows = rows();
        let mut home = Home::default();
        assert_eq!(home.key(PaletteInput::Enter, &rows), None);
        let menu = screen(&home, &rows, "");
        for (label, key) in [
            ("Resume: start", " r"),
            ("End: save", " e"),
            (
                "Invite: show a pairing code so a teammate can watch and prompt it live",
                " i",
            ),
            ("Purge: delete", " p"),
        ] {
            let line = menu
                .lines()
                .find(|line| line.contains(label))
                .unwrap_or_else(|| panic!("{label} missing: {menu}"));
            assert!(line.trim_end_matches(['│', ' ']).ends_with(key), "{menu}");
        }
        assert_eq!(home.key(PaletteInput::Text('3'), &rows), None);
        assert_eq!(
            home.key(PaletteInput::Text('i'), &rows),
            Some(HomeAction::Invite("t1".to_owned()))
        );
        home.key(PaletteInput::Enter, &rows);
        assert_eq!(home.key(PaletteInput::Text('e'), &rows), None);
        assert!(screen(&home, &rows, "").contains("End thread t1?"));
        assert_eq!(
            home.key(PaletteInput::Text('y'), &rows),
            Some(HomeAction::End("t1".to_owned()))
        );
        home.key(PaletteInput::Down, &rows);
        home.key(PaletteInput::Enter, &rows);
        let teammate = screen(&home, &rows, "");
        assert!(!teammate.contains("Resume:"), "{teammate}");
        assert_eq!(home.key(PaletteInput::Text('r'), &rows), None);
        assert_eq!(home.key(PaletteInput::Down, &rows), None);
        assert_eq!(
            home.key(PaletteInput::Enter, &rows),
            Some(HomeAction::Invite("t2".to_owned()))
        );
        home.key(PaletteInput::Enter, &rows);
        assert_eq!(
            home.key(PaletteInput::Text('p'), &rows),
            Some(HomeAction::Purge("t2".to_owned()))
        );
        assert_eq!(
            home.key(PaletteInput::Text('p'), &rows),
            Some(HomeAction::Purge("t2".to_owned()))
        );
        assert!(keys(&mut Home::default(), &[], "p").is_empty());
        assert!(keys(&mut home, &rows, "ahg").is_empty());
    }

    #[test]
    fn ending_waits_for_yes_and_anything_else_cancels() {
        let rows = rows();
        let mut home = Home::default();
        assert!(keys(&mut home, &rows, "ly").is_empty());
        assert!(!home.has_dialog());
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
        assert!(keys(&mut home, &rows, "e").is_empty());
        assert!(home.has_dialog());
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
    fn the_last_actions_outcome_is_the_newest_line_of_the_activity_panel() {
        let rows = rows();
        let drawn = screen(&Home::default(), &rows, "mahi join failed with exit code 1");
        let lines: Vec<&str> = drawn.lines().collect();
        let told = lines
            .iter()
            .position(|line| line.contains("mahi join failed with exit code 1"))
            .unwrap();
        let printed = lines
            .iter()
            .position(|line| line.contains("mahi: cannot reach the remote"))
            .unwrap();
        assert!(printed < told, "{drawn}");
        assert!(lines[told].trim_end().ends_with('│'), "{drawn}");
        assert!(lines[told + 1].contains('╰'), "{drawn}");
        assert!(lines[told + 2].contains("? help"), "{drawn}");
    }

    #[test]
    fn a_long_outcome_wraps_in_the_activity_panel_and_a_short_screen_still_shows_it() {
        let rows = rows();
        let outcome =
            "mahi invite 0123456789abcdef0123456789abcdef failed with exit code 1".to_owned();
        let drawn = screen_in(&Home::default(), &rows, &outcome, Rect::new(0, 0, 80, 24));
        let joined: String = drawn
            .lines()
            .map(|line| line.trim_end().trim_matches('│').trim().to_owned())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(joined.contains("failed with exit code 1"), "{drawn}");
        assert!(
            joined.contains("0123456789abcdef0123456789abcdef"),
            "{drawn}"
        );
        let short = screen_in(
            &Home::default(),
            &rows,
            "resumed t1",
            Rect::new(0, 0, 80, 6),
        );
        assert!(short.contains("resumed t1"), "{short}");
        let cramped = screen_in(&Home::default(), &rows, &outcome, Rect::new(0, 0, 80, 6));
        assert!(cramped.contains("with exit code 1"), "{cramped}");
    }

    #[test]
    fn the_status_wraps_into_rows_no_wider_than_the_panel_breaking_at_spaces() {
        let status = format!(" {} {}", "a".repeat(20), "b".repeat(33));
        assert_eq!(status.width(), 55);
        let aaaa = format!(" {}", "a".repeat(20));
        let bbbb = "b".repeat(33);
        assert_eq!(status_lines(&status, 54), [aaaa.as_str(), bbbb.as_str()]);
        let wide = " \u{65e5}\u{65e5}\u{e9}\u{e9}\u{65e5}";
        let lines = status_lines(wide, 4);
        assert!(lines.iter().all(|line| line.cell_width() <= 4), "{lines:?}");
        assert_eq!(lines.concat(), wide);
        assert_eq!(status_lines(&"c".repeat(9), 4), ["cccc", "cccc", "c"]);
        let marked = status_lines("ab\u{263a}\u{fe0f}\u{ff76}\u{ff9e}", 3);
        assert!(
            marked.iter().all(|line| line.cell_width() <= 3),
            "{marked:?}"
        );
    }

    #[test]
    fn a_narrow_screen_keeps_the_footer_and_the_agents_and_a_short_one_a_thread() {
        let rows = vec![HomeRow {
            thread: "0123456789abcdef0123456789abcdef".to_owned(),
            agents: "you.claude, bob.codex".to_owned(),
            worktree: true,
            owned: true,
            last_active: None,
        }];
        let home = Home::default();
        let drawn = screen_in(&home, &rows, "", Rect::new(0, 0, 56, 24));
        let keys = drawn.lines().last().unwrap();
        assert!(
            keys.contains("Ctrl-Space palette  ? help  q quit"),
            "{drawn}"
        );
        assert!(drawn.contains("you.claude, bob.codex"), "{drawn}");
        assert!(drawn.contains("› 01234567 "), "{drawn}");
        let wide = screen_in(&home, &rows, "", Rect::new(0, 0, 75, 24));
        assert!(
            wide.contains("› 0123456789abcdef0123456789abcdef"),
            "{wide}"
        );
        assert!(wide.contains("you.claude"), "{wide}");
        let narrower = screen_in(&home, &rows, "", Rect::new(0, 0, 74, 24));
        assert!(narrower.contains("› 01234567 "), "{narrower}");
        let short = screen_in(&home, &rows, "", Rect::new(0, 0, 56, 13));
        assert!(short.contains("› 01234567"), "{short}");
    }

    #[test]
    fn the_last_active_column_goes_before_the_whole_id_and_never_squeezes_the_agents() {
        let base = 9 + 9 + 5 + AGENTS_LEAST;
        assert_eq!(columns(THREAD_WIDTH + base, None), (true, None));
        assert_eq!(columns(THREAD_WIDTH + base - 1, None), (false, None));
        assert_eq!(
            columns(THREAD_WIDTH + base + 12, Some(11)),
            (true, Some(11))
        );
        assert_eq!(
            columns(THREAD_WIDTH + base + 11, Some(11)),
            (false, Some(11))
        );
        assert_eq!(
            columns(SHORT_THREAD + base + 12, Some(11)),
            (false, Some(11))
        );
        assert_eq!(columns(SHORT_THREAD + base + 11, Some(11)), (false, None));
    }

    #[test]
    fn a_narrow_screen_leaves_the_last_active_column_out_so_the_agents_show() {
        let rows = vec![HomeRow {
            thread: "0123456789abcdef0123456789abcdef".to_owned(),
            agents: "you.claude, bob.codex".to_owned(),
            worktree: true,
            owned: true,
            last_active: Some("Nov 4 2025 09:30 UTC".to_owned()),
        }];
        let drawn = screen_in(&Home::default(), &rows, "", Rect::new(0, 0, 56, 24));
        assert!(drawn.contains("you.claude, bob.codex"), "{drawn}");
        assert!(!drawn.contains("last active"), "{drawn}");
    }

    #[test]
    fn a_last_active_column_shows_only_once_a_thread_has_a_time() {
        let mut rows = rows();
        let home = Home::default();
        let drawn = screen(&home, &rows, "");
        assert!(!drawn.contains("last active"), "{drawn}");
        rows[1].last_active = Some("Nov 4 09:30".to_owned());
        let drawn = screen(&home, &rows, "");
        let header = drawn
            .lines()
            .find(|line| line.contains("worktree"))
            .unwrap_or_else(|| panic!("{drawn}"));
        let (worktree, active, owner) = (
            header.find("worktree").unwrap(),
            header
                .find("last active")
                .unwrap_or_else(|| panic!("{drawn}")),
            header.find("owner").unwrap(),
        );
        assert!(worktree < active && active < owner, "{drawn}");
        let t2 = drawn.lines().find(|line| line.contains(" t2 ")).unwrap();
        assert!(
            t2.contains(" gone ") && t2.contains(" Nov 4 09:30 teammate "),
            "{drawn}"
        );
    }

    #[test]
    fn the_screen_shows_threads_activity_and_the_palette_key_without_a_menu() {
        let rows = rows();
        let home = Home::default();
        let drawn = screen(&home, &rows, "resumed t1\u{1b}[2J");
        for wanted in [
            "Threads · 2",
            "› t1",
            "you.claude",
            "teammate",
            "Activity",
            "cannot reach the remote",
            "resumed t1?[2J",
            "q quit",
        ] {
            assert!(drawn.contains(wanted), "{wanted:?} missing:\n{drawn}");
        }
        assert!(!drawn.contains("Selected"), "{drawn}");
        assert!(!drawn.contains("Menu"), "{drawn}");
        assert!(!drawn.contains("New thread"), "{drawn}");
        let keys = screen(&home, &rows, "");
        let footer = keys.lines().last().unwrap().trim_end();
        assert_eq!(footer, "Ctrl-Space palette  ? help  q quit", "{keys}");
        assert!(keys.starts_with("╭ Threads"), "{keys}");
        let empty = screen(&home, &[], "");
        assert!(empty.contains("No threads yet"), "{empty}");
        for (width, height) in [(0, 0), (1, 1), (20, 6), (60, 12)] {
            let area = Rect::new(0, 0, width, height);
            let mut buffer = Buffer::empty(area);
            let view = HomeView {
                header: Header {
                    repository: "r",
                    remote: "none",
                    remote_chosen: false,
                    remote_key: true,
                    identity: "me",
                },
                rows: &rows,
                activity: &[],
            };
            home.render(&view, "", area, &mut buffer);
        }
    }

    #[test]
    fn a_thread_key_without_threads_says_how_to_start_one() {
        let thread_keys = HOME_COMMANDS
            .into_iter()
            .filter_map(|command| match command {
                HomeCommand::Thread(choice) => Some(PaletteInput::Text(choice.key())),
                _ => None,
            });
        for input in thread_keys.chain([PaletteInput::Enter]) {
            let mut home = Home::default();
            assert_eq!(home.key(input, &[]), None, "{input:?}");
            assert!(
                screen(&home, &[], "").contains("no threads yet: press n to start one"),
                "{input:?}"
            );
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
