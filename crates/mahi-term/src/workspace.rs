use std::borrow::Cow;

use ratatui_core::{
    buffer::Buffer,
    layout::{
        Constraint,
        Layout,
        Position,
        Rect,
    },
    style::Style,
    text::{
        Line,
        Span,
    },
    widgets::Widget,
};
use ratatui_widgets::{
    block::Block,
    borders::BorderType,
    clear::Clear,
};

use crate::{
    Theme,
    dialog::shown,
    key_hints,
    pane::draw_screen,
};

const LIST_COLUMNS: u16 = 24;
const NARROW_COLUMNS: u16 = 100;
const TOP_ROWS: u16 = 1;
const HINT_ROWS: u16 = 1;
const STATUS_ROWS: u16 = 1;
const STATUS_GAP: &str = "  ";
const BORDER: u16 = 2;
const SMALLEST: u16 = 2;

/// What an agent in a thread's tab is doing, as the workspace's list shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentState {
    /// A turn is open.
    Working,
    /// Its turn ended: it waits for its next prompt.
    Done,
    /// It waits on a question of its own for the user.
    AsksYou,
    /// A teammate's agent waits on a question for its own user.
    Asks,
    /// A teammate's agent whose host is connected but tells no state, or has not told one
    /// yet.
    Live,
    /// A teammate's agent whose host is not connected.
    Offline,
    /// The command that ran it failed; its last screen stays until the user closes it.
    Failed,
}

impl AgentState {
    /// Returns how the list shows the state, such as `✓ done`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Working => "● working",
            Self::Done => "✓ done",
            Self::AsksYou => "! asks you",
            Self::Asks => "! asks",
            Self::Live => "◉ live",
            Self::Offline => "○ offline",
            Self::Failed => "✗ failed",
        }
    }

    fn mark(self) -> Span<'static> {
        let style = match self {
            Self::Working | Self::Asks | Self::Live => Style::new().fg(Theme::ACCENT),
            Self::Done => Style::new().fg(Theme::OK),
            Self::AsksYou => Theme::code(),
            Self::Offline => Theme::muted(),
            Self::Failed => Style::new().fg(Theme::ERROR),
        };
        Span::styled(self.symbol(), style)
    }

    fn symbol(self) -> &'static str {
        match self {
            Self::Working => "●",
            Self::Done => "✓",
            Self::AsksYou | Self::Asks => "!",
            Self::Live => "◉",
            Self::Offline => "○",
            Self::Failed => "✗",
        }
    }
}

/// An agent of a thread, as the workspace's list shows it.
#[derive(Debug, Clone, Copy)]
pub struct WorkspaceAgent<'a> {
    /// Whose agent it is: `None` for the user's own, otherwise the participant's name.
    pub owner: Option<&'a str>,
    /// The agent's name in its participant's slot, such as `claude`.
    pub name: &'a str,
    /// What it is doing.
    pub state: AgentState,
}

/// A tab of the workspace, after the thread list's.
#[derive(Debug, Clone, Copy)]
pub struct WorkspaceTab<'a> {
    /// What the tab shows, such as the thread's short id.
    pub title: &'a str,
    /// Whether one of its agents asks the user something.
    pub asks: bool,
}

/// Where the list of a thread's agents is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListPlace {
    /// Beside the agent's pane, which is narrower for it.
    Beside,
    /// Over the right of the agent's pane, which keeps its size.
    Over,
    /// Not shown.
    Hidden,
    /// Not shown: a status line under the pane names the teammates' agents instead.
    StatusLine,
}

impl ListPlace {
    /// Returns where the list goes on a terminal `columns` wide when the user has it shown:
    /// beside the pane, or over it when the terminal is narrower than 100 columns.
    #[must_use]
    pub fn shown_at(columns: u16) -> Self {
        if columns < NARROW_COLUMNS {
            Self::Over
        } else {
            Self::Beside
        }
    }
}

/// What a teammate's agent is doing, as the status line names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeammateState {
    /// A turn is open.
    Working,
    /// Its turn ended.
    Done,
    /// It waits on a question for its own user.
    Asks,
    /// Its host is connected but tells no state, or has not told one yet.
    Live,
    /// Its host is not connected.
    Offline,
}

impl TeammateState {
    /// Returns the state's name, such as `done`.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Self::Working => "working",
            Self::Done => "done",
            Self::Asks => "asks",
            Self::Live => "live",
            Self::Offline => "offline",
        }
    }
}

/// A teammate's agent as the status line names it.
#[derive(Debug, Clone, Copy)]
pub struct StatusAgent<'a> {
    /// Its slot, such as `bob.claude`.
    pub slot: &'a str,
    /// What it is doing.
    pub state: TeammateState,
    /// What a turn of it that waits for the user's keypress changes, such as `changes agent
    /// settings`.
    pub waits: Option<&'a str>,
    /// The files the last merge of its work into the user's worktree brought.
    pub brought: &'a [&'a str],
}

/// The paths a merge of a teammate's agent's work left with conflict markers.
#[derive(Debug, Clone, Copy)]
pub struct StatusConflicts<'a> {
    /// The slot of the teammate's agent, such as `bob.claude`.
    pub from: &'a str,
    /// The paths still holding its markers.
    pub paths: &'a [&'a str],
}

/// The row under the pane in the one view: the conflicts to resolve first, then each
/// teammate's agent.
#[derive(Debug, Clone, Copy, Default)]
pub struct StatusLine<'a> {
    /// The conflicts left in the user's worktree, by the agent they came from.
    pub conflicts: &'a [StatusConflicts<'a>],
    /// The teammates' agents.
    pub agents: &'a [StatusAgent<'a>],
}

/// One item of the status line, and how wide it is.
#[derive(Debug, Clone)]
struct Item<'a> {
    spans: Vec<Span<'a>>,
    width: usize,
}

impl<'a> Item<'a> {
    fn new(spans: Vec<Span<'a>>) -> Self {
        let width = spans.iter().map(Span::width).sum();
        Self { spans, width }
    }
}

impl<'a> StatusLine<'a> {
    /// Returns the line for a row `width` columns wide: whole when it fits, otherwise
    /// without the files merges brought, then with the last agents left out and counted as
    /// `+N more`, then with the conflicts' paths cut short, each list ending with `and N
    /// more`.
    #[must_use]
    pub fn line(&self, width: u16) -> Line<'a> {
        let width = usize::from(width);
        let whole: Vec<Item<'a>> = self
            .agents
            .iter()
            .map(|agent| agent_item(agent, Brought::Shown))
            .collect();
        let short: Vec<Item<'a>> = self
            .agents
            .iter()
            .map(|agent| agent_item(agent, Brought::Left))
            .collect();
        let most_paths = self
            .conflicts
            .iter()
            .map(|conflicts| conflicts.paths.len())
            .max()
            .unwrap_or(0);
        let mut listed = most_paths;
        loop {
            let conflicts: Vec<Item<'a>> = self
                .conflicts
                .iter()
                .map(|conflicts| conflicts_item(conflicts, listed))
                .collect();
            if let Some(line) = fitting(&conflicts, (&whole, &short), width) {
                return line;
            }
            if listed <= 1 {
                return joined(conflicts.iter().chain(&more(self.agents.len())));
            }
            listed -= 1;
        }
    }
}

/// Returns the line of the `conflicts` and the agents, `whole` or `short`, that fits in
/// `width`, as the line leaves things out; `None` when even the conflicts and the count of
/// every agent do not fit.
fn fitting<'a>(
    conflicts: &[Item<'a>],
    (whole, short): (&[Item<'a>], &[Item<'a>]),
    width: usize,
) -> Option<Line<'a>> {
    let wide = |items: &[&Item<'_>]| -> usize {
        let gaps = items.len().saturating_sub(1) * STATUS_GAP.len();
        items.iter().map(|item| item.width).sum::<usize>() + gaps
    };
    for agents in [whole, short] {
        let items: Vec<&Item<'a>> = conflicts.iter().chain(agents).collect();
        if wide(&items) <= width {
            return Some(joined(items));
        }
    }
    let shown = (0..short.len()).rev();
    for kept in shown {
        let more = more(short.len() - kept);
        let items: Vec<&Item<'a>> = conflicts
            .iter()
            .chain(short.iter().take(kept))
            .chain(&more)
            .collect();
        if wide(&items) <= width {
            return Some(joined(items));
        }
    }
    None
}

/// Joins `items` into one line, two spaces apart.
fn joined<'a, 'item>(items: impl IntoIterator<Item = &'item Item<'a>>) -> Line<'a>
where
    'a: 'item,
{
    let mut spans = Vec::new();
    for item in items {
        if !spans.is_empty() {
            spans.push(Span::raw(STATUS_GAP));
        }
        spans.extend(item.spans.iter().cloned());
    }
    Line::from(spans)
}

/// Returns the count of `left` agents left out, as `+N more`, or nothing when none is.
fn more(left: usize) -> Option<Item<'static>> {
    (left > 0).then(|| Item::new(vec![Span::styled(format!("+{left} more"), Theme::muted())]))
}

fn agent_item<'a>(agent: &StatusAgent<'a>, brought: Brought) -> Item<'a> {
    let mut spans = vec![
        Span::styled(shown(agent.slot), Theme::title()),
        Span::raw(" "),
        Span::raw(agent.state.word()),
    ];
    if let Some(waits) = agent.waits {
        let warn = Style::new().fg(Theme::WARN);
        spans.push(Span::styled(" · ", Theme::muted()));
        spans.push(Span::styled("a turn waits for you: ", warn));
        spans.push(Span::styled(shown(waits), warn));
    }
    if brought == Brought::Shown && !agent.brought.is_empty() {
        spans.push(Span::styled(" · ", Theme::muted()));
        push_paths(&mut spans, agent.brought, Style::new());
    }
    Item::new(spans)
}

/// Returns the item of `conflicts`, listing at most `listed` of its paths, at least one.
fn conflicts_item<'a>(conflicts: &StatusConflicts<'a>, listed: usize) -> Item<'a> {
    let warn = Style::new().fg(Theme::WARN);
    let mut spans = vec![
        Span::styled("conflicts from ", warn),
        Span::styled(shown(conflicts.from), warn),
        Span::styled(": ", warn),
    ];
    let listed = listed.max(1).min(conflicts.paths.len());
    push_paths(
        &mut spans,
        conflicts.paths.get(..listed).unwrap_or_default(),
        warn,
    );
    let left = conflicts.paths.len() - listed;
    if left > 0 {
        spans.push(Span::styled(format!(" and {left} more"), warn));
    }
    Item::new(spans)
}

fn push_paths<'a>(spans: &mut Vec<Span<'a>>, paths: &[&'a str], style: Style) {
    for (index, path) in paths.iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled(", ", style));
        }
        spans.push(Span::styled(shown(path), style));
    }
}

/// Whether the status line names the files merges brought.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Brought {
    Shown,
    Left,
}

/// What a click on the top row is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TabHit {
    /// A tab: 0 for the thread list, `n` for the `n`th thread's.
    Tab(usize),
    /// `+`, which opens another thread.
    New,
    /// A separator, or the row past its tabs.
    Nothing,
}

/// What a click on the list of a thread's agents is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListHit {
    /// An agent's line, as its index in the thread's agents.
    Agent(usize),
    /// Its border, a line naming whose agents follow, or a line without an agent.
    Elsewhere,
}

/// What the top row says on its right: the repository, the remote threads are pushed to and
/// the user.
#[derive(Debug, Clone, Copy)]
pub struct Header<'a> {
    /// The repository's name.
    pub repository: &'a str,
    /// The remote threads are pushed to, or that none is chosen.
    pub remote: &'a str,
    /// Whether a remote, or not pushing, was chosen; when not, the remote reads as a warning.
    pub remote_chosen: bool,
    /// Whether `m` chooses the remote where the row is drawn, so it is named beside a remote
    /// not chosen.
    pub remote_key: bool,
    /// The user's participant name.
    pub identity: &'a str,
}

impl<'a> Header<'a> {
    fn spans(&self) -> Vec<Span<'a>> {
        let mut spans = Vec::with_capacity(8);
        spans.push(Span::styled(shown(self.repository), Theme::title()));
        spans.push(Span::styled(" · ", Theme::muted()));
        spans.push(Span::styled("remote ", Theme::muted()));
        if self.remote_chosen {
            spans.push(Span::raw(shown(self.remote)));
        } else {
            spans.push(Span::styled(
                shown(self.remote),
                Style::new().fg(Theme::WARN),
            ));
            if self.remote_key {
                spans.push(Span::styled(" (m)", Theme::muted()));
            }
        }
        spans.push(Span::styled(" · ", Theme::muted()));
        spans.push(Span::raw(shown(self.identity)));
        spans.push(Span::raw(" "));
        spans
    }
}

/// The screen's top row: mahi's badge, the workspace's tabs when it has any, and the header on
/// the right, left out, the repository first, when the row is too narrow for it.
#[derive(Debug, Clone, Copy)]
pub struct TopBar<'a> {
    /// The workspace's tabs, when one is open.
    pub tabs: Option<TabBar<'a>>,
    /// What the row says on its right.
    pub header: Header<'a>,
}

impl TopBar<'_> {
    /// Splits a terminal's `area` into the top row and what lies below it.
    #[must_use]
    pub fn split(area: Rect) -> (Rect, Rect) {
        let [top, body] =
            Layout::vertical([Constraint::Length(TOP_ROWS), Constraint::Fill(1)]).areas(area);
        (top, body)
    }

    /// Draws the row into `area`.
    pub fn render(&self, area: Rect, buffer: &mut Buffer) {
        let left = match &self.tabs {
            Some(tabs) => Line::from(tabs.spans().map(|(span, _)| span).collect::<Vec<_>>()),
            None => Line::from(badge()),
        };
        let room = usize::from(area.width).saturating_sub(left.width() + 1);
        left.render(area, buffer);
        let mut right = Line::from(self.header.spans());
        if right.width() > room {
            right.spans.drain(..2);
        }
        if right.width() <= room {
            let width = u16::try_from(right.width()).unwrap_or(u16::MAX);
            let at = Rect {
                x: area.right().saturating_sub(width),
                width,
                ..area
            };
            right.render(at, buffer);
        }
    }
}

/// The workspace's tabs, after mahi's badge on the top row: the thread list, each open thread,
/// and `+` to open another.
#[derive(Debug, Clone, Copy)]
pub struct TabBar<'a> {
    /// The open threads' tabs.
    pub tabs: &'a [WorkspaceTab<'a>],
    /// The selected tab: 0 for the thread list, `n` for `tabs[n - 1]`.
    pub selected: usize,
}

impl<'a> TabBar<'a> {
    /// Returns what is drawn at `column` of the top row, counted from the row's left.
    #[must_use]
    pub fn tab_at(&self, column: u16) -> TabHit {
        let mut right = 0_usize;
        for (span, hit) in self.spans() {
            right += span.width();
            if usize::from(column) < right {
                return hit;
            }
        }
        TabHit::Nothing
    }

    fn spans(&self) -> impl Iterator<Item = (Span<'a>, TabHit)> + '_ {
        let threads = self.tab(0, "⌂ threads".into(), "");
        let tabs = self.tabs.iter().enumerate().flat_map(move |(index, tab)| {
            let mark = if tab.asks { " !" } else { "" };
            std::iter::once((Span::raw(" "), TabHit::Nothing)).chain(self.tab(
                index + 1,
                shown(tab.title),
                mark,
            ))
        });
        [
            (badge(), TabHit::Nothing),
            (Span::raw(" "), TabHit::Nothing),
        ]
        .into_iter()
        .chain(threads)
        .chain(tabs)
        .chain([
            (Span::raw(" "), TabHit::Nothing),
            (Span::styled(" + ", Theme::title()), TabHit::New),
        ])
    }

    fn tab(
        &self,
        index: usize,
        label: Cow<'a, str>,
        mark: &'static str,
    ) -> [(Span<'a>, TabHit); 4] {
        let style = if index == self.selected {
            Theme::selected()
        } else {
            Theme::title()
        };
        let hit = TabHit::Tab(index);
        [
            (Span::styled(" ", style), hit),
            (Span::styled(label, style), hit),
            (Span::styled(mark, style), hit),
            (Span::styled(" ", style), hit),
        ]
    }
}

fn badge() -> Span<'static> {
    Span::styled(" mahi ", Theme::selected())
}

/// A thread's tab: one of its agents at full size, the list of its agents, and the keys that
/// reach mahi.
#[derive(Debug, Clone, Copy)]
pub struct ThreadView<'a> {
    /// The thread's agents: the user's own first, then each teammate's.
    pub agents: &'a [WorkspaceAgent<'a>],
    /// The agent shown at full size, as an index in `agents`.
    pub selected: usize,
    /// Where the list goes.
    pub list: ListPlace,
    /// The keys that reach mahi, and what they do.
    pub hints: &'a [(&'a str, &'a str)],
    /// The spinner's frame and what the pane waits for, drawn in its middle while it has no
    /// screen.
    pub waiting: Option<(&'a str, &'a str)>,
    /// What the status line says, drawn under the pane when `list` is
    /// [`ListPlace::StatusLine`].
    pub status: StatusLine<'a>,
}

impl<'a> ThreadView<'a> {
    /// Returns the rows and columns of an agent's terminal in a thread's tab on a terminal of
    /// `rows` and `columns`, at least two of each, with the list `list`.
    #[must_use]
    pub fn agent_size(rows: u16, columns: u16, list: ListPlace) -> (u16, u16) {
        let beside = if list == ListPlace::Beside {
            LIST_COLUMNS
        } else {
            0
        };
        let status = if list == ListPlace::StatusLine {
            STATUS_ROWS
        } else {
            0
        };
        (
            rows.saturating_sub(TOP_ROWS + HINT_ROWS + BORDER + status)
                .max(SMALLEST),
            columns.saturating_sub(BORDER + beside).max(SMALLEST),
        )
    }

    /// Draws the tab into `area`, below the top row, with the selected agent's `screen`
    /// in its pane; returns where the agent's cursor is when it shows it and nothing lies over
    /// it.
    pub fn render(
        &self,
        screen: Option<&vt100::Screen>,
        area: Rect,
        buffer: &mut Buffer,
    ) -> Option<Position> {
        let (body, status, footer) = self.rows(area);
        let (pane, list) = self.areas(body);
        let title = self
            .agents
            .get(self.selected)
            .map_or_else(String::new, |agent| format!(" {} ", agent.label()));
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(Theme::ACCENT))
            .title(Span::styled(title, Theme::title()));
        let inner = block.inner(pane);
        block.render(pane, buffer);
        if let Some(screen) = screen {
            draw_screen(screen, inner, buffer, false);
        } else if let Some((frame, text)) = self.waiting {
            let middle = Rect {
                y: inner.y.saturating_add(inner.height / 2),
                height: inner.height.min(1),
                ..inner
            };
            Line::from(vec![Span::raw(frame), Span::raw(" "), Span::raw(text)])
                .centered()
                .render(middle, buffer);
        }
        if let Some(list) = list {
            Clear.render(list, buffer);
            self.render_list(list, buffer);
        }
        if let Some(status) = status {
            self.status.line(status.width).render(status, buffer);
        }
        Line::from(key_hints(self.hints)).render(footer, buffer);
        let screen = screen?;
        let (row, column) = screen.cursor_position();
        let cursor = Position::new(inner.x.saturating_add(column), inner.y.saturating_add(row));
        let covered = list.is_some_and(|list| list.contains(cursor));
        (!screen.hide_cursor() && inner.contains(cursor) && !covered).then_some(cursor)
    }

    /// Returns what of the list is at `position`, when the tab is drawn in `area`, below the
    /// top row: nothing when the list is not there, so the click is the agent's.
    #[must_use]
    pub fn list_at(&self, area: Rect, position: Position) -> Option<ListHit> {
        let (body, _, _) = self.rows(area);
        let (_, list) = self.areas(body);
        let list = list?;
        if !list.contains(position) {
            return None;
        }
        let inner = Block::bordered().inner(list);
        let agent = inner
            .contains(position)
            .then(|| self.lines().nth(usize::from(position.y - inner.y)))
            .flatten()
            .and_then(|row| match row {
                ListRow::Agent(index) => Some(index),
                ListRow::Blank | ListRow::Group(_) => None,
            });
        Some(agent.map_or(ListHit::Elsewhere, ListHit::Agent))
    }

    /// Returns the cell of the agent's screen at `position`, when the tab is drawn in `area`,
    /// below the top row; a position past the pane gives its nearest cell when `clamp`,
    /// as a drag that leaves it does, and nothing otherwise.
    #[must_use]
    pub fn pane_point(&self, area: Rect, position: Position, clamp: bool) -> Option<(u16, u16)> {
        let (body, _, _) = self.rows(area);
        let (pane, _) = self.areas(body);
        let inner = Block::bordered().inner(pane);
        if inner.is_empty() || (!clamp && !inner.contains(position)) {
            return None;
        }
        let column = position.x.clamp(inner.x, inner.right() - 1) - inner.x;
        let row = position.y.clamp(inner.y, inner.bottom() - 1) - inner.y;
        Some((column, row))
    }

    /// Splits `area` into the pane's and the list's body, the status line's row when the
    /// view has one, and the hints' row.
    fn rows(&self, area: Rect) -> (Rect, Option<Rect>, Rect) {
        let shown = self.list == ListPlace::StatusLine;
        let [body, status, footer] = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(if shown { STATUS_ROWS } else { 0 }),
            Constraint::Length(HINT_ROWS),
        ])
        .areas(area);
        (body, shown.then_some(status), footer)
    }

    fn areas(&self, body: Rect) -> (Rect, Option<Rect>) {
        match self.list {
            ListPlace::Beside => {
                let [pane, list] =
                    Layout::horizontal([Constraint::Fill(1), Constraint::Length(LIST_COLUMNS)])
                        .areas(body);
                (pane, Some(list))
            }
            ListPlace::Over => {
                let width = LIST_COLUMNS.min(body.width);
                let list = Rect::new(body.right() - width, body.y, width, body.height);
                (body, Some(list))
            }
            ListPlace::Hidden | ListPlace::StatusLine => (body, None),
        }
    }

    /// Returns the rows of the list's agents: each group's heading, after a blank row but for
    /// the first, then its agents.
    fn lines(&self) -> impl Iterator<Item = ListRow<'a>> + '_ {
        self.agents.iter().enumerate().flat_map(|(index, agent)| {
            let starts_group = index == 0
                || self
                    .agents
                    .get(index - 1)
                    .is_some_and(|before| before.owner != agent.owner);
            let blank = (starts_group && index > 0).then_some(ListRow::Blank);
            let group = starts_group.then_some(ListRow::Group(agent.owner));
            blank
                .into_iter()
                .chain(group)
                .chain(std::iter::once(ListRow::Agent(index)))
        })
    }

    fn agent_line(&self, index: usize) -> Line<'a> {
        let Some(agent) = self.agents.get(index) else {
            return Line::default();
        };
        if index != self.selected {
            return Line::from(vec![
                Span::raw(" "),
                agent.state.mark(),
                Span::raw(" "),
                Span::raw(shown(agent.name)),
            ]);
        }
        Line::from(vec![
            Span::raw(" "),
            Span::raw(agent.state.symbol()),
            Span::raw(" "),
            Span::raw(shown(agent.name)),
        ])
        .style(Theme::selected())
    }

    fn render_list(&self, area: Rect, buffer: &mut Buffer) {
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(Theme::ACCENT))
            .title(Span::styled(" Agents ", Theme::title()));
        let inner = block.inner(area);
        block.render(area, buffer);
        let mut lines = Vec::with_capacity(self.agents.len() * 3 + 2);
        for row in self.lines() {
            lines.push(match row {
                ListRow::Blank => Line::default(),
                ListRow::Group(None) => Line::from(Span::styled("Yours", Theme::muted())),
                ListRow::Group(Some(owner)) => Line::from(vec![
                    Span::styled(shown(owner), Theme::muted()),
                    Span::styled("'s", Theme::muted()),
                ]),
                ListRow::Agent(index) => self.agent_line(index),
            });
        }
        for (line, row) in lines.into_iter().zip(inner.rows()) {
            line.render(row, buffer);
        }
    }
}

/// A row of the agents' list.
#[derive(Debug, Clone, Copy)]
enum ListRow<'a> {
    Blank,
    Group(Option<&'a str>),
    Agent(usize),
}

impl WorkspaceAgent<'_> {
    /// Returns how the list names the agent: its name, or a teammate's slot marked read-only.
    #[must_use]
    pub fn label(&self) -> String {
        match self.owner {
            Some(owner) => format!("{}.{} (read-only)", shown(owner), shown(self.name)),
            None => shown(self.name).into_owned(),
        }
    }

    /// Returns how the workspace's palette offers to show the agent: its name and state, or a
    /// teammate's named after its owner and marked read-only.
    #[must_use]
    pub fn palette_label(&self) -> String {
        let state = self.state.as_str();
        match self.owner {
            Some(owner) => format!(
                "Show {}'s agent {} (read-only, {state})",
                shown(owner),
                shown(self.name)
            ),
            None => format!("Show agent {} ({state})", shown(self.name)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(buffer: &Buffer) -> Vec<String> {
        let area = buffer.area;
        (area.top()..area.bottom())
            .map(|y| {
                (area.left()..area.right())
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect()
    }

    const AGENTS: [WorkspaceAgent<'static>; 3] = [
        WorkspaceAgent {
            owner: None,
            name: "claude",
            state: AgentState::Working,
        },
        WorkspaceAgent {
            owner: Some("alice"),
            name: "claude",
            state: AgentState::Done,
        },
        WorkspaceAgent {
            owner: Some("bob"),
            name: "codex",
            state: AgentState::Offline,
        },
    ];

    #[test]
    fn the_tab_bar_marks_the_selected_tab_and_a_thread_that_asks() {
        let tabs = [
            WorkspaceTab {
                title: "7f3a",
                asks: false,
            },
            WorkspaceTab {
                title: "9a48",
                asks: true,
            },
        ];
        let area = Rect::new(0, 0, 60, 1);
        let mut buffer = Buffer::empty(area);
        TopBar {
            tabs: Some(TabBar {
                tabs: &tabs,
                selected: 1,
            }),
            header: HEADER,
        }
        .render(area, &mut buffer);
        let row = rows(&buffer).remove(0);
        assert!(
            row.starts_with(" mahi   ⌂ threads   7f3a   9a48 !   + "),
            "{row}"
        );
        assert_eq!(buffer[(20, 0)].style().bg, Theme::selected().bg);
        assert_ne!(buffer[(8, 0)].style().bg, Theme::selected().bg);
        for column in [6, 18, 59] {
            assert_eq!(
                buffer[(column, 0)].style().bg,
                Some(ratatui_core::style::Color::Reset),
                "{column}"
            );
        }
    }

    const HEADER: Header<'static> = Header {
        repository: "project",
        remote: "none chosen",
        remote_chosen: false,
        remote_key: true,
        identity: "davy",
    };

    fn top_row(top: TopBar<'_>, width: u16) -> (String, Buffer) {
        let area = Rect::new(0, 0, width, 1);
        let mut buffer = Buffer::empty(area);
        top.render(area, &mut buffer);
        (rows(&buffer).remove(0), buffer)
    }

    #[test]
    fn the_top_row_ends_with_the_repository_the_remote_and_the_user() {
        let (row, buffer) = top_row(
            TopBar {
                tabs: None,
                header: HEADER,
            },
            80,
        );
        assert!(row.starts_with(" mahi "), "{row}");
        assert!(
            row.ends_with("project · remote none chosen (m) · davy "),
            "{row}"
        );
        let remote = row.find("none chosen").unwrap();
        let column = u16::try_from(row[..remote].chars().count()).unwrap();
        assert_eq!(buffer[(column, 0)].style().fg, Some(Theme::WARN));
        let chosen = Header {
            remote: "origin (private)",
            remote_chosen: true,
            ..HEADER
        };
        let (row, _) = top_row(
            TopBar {
                tabs: None,
                header: chosen,
            },
            80,
        );
        assert!(row.ends_with("remote origin (private) · davy "), "{row}");
        let elsewhere = Header {
            remote_key: false,
            ..HEADER
        };
        let (row, _) = top_row(
            TopBar {
                tabs: None,
                header: elsewhere,
            },
            80,
        );
        assert!(row.ends_with("remote none chosen · davy "), "{row}");
        let hidden = Header {
            repository: "repo\u{202e}",
            ..HEADER
        };
        let (row, _) = top_row(
            TopBar {
                tabs: None,
                header: hidden,
            },
            80,
        );
        assert!(row.contains("repo? · remote"), "{row}");
    }

    #[test]
    fn a_narrow_top_row_leaves_out_the_repository_then_the_whole_header_but_never_a_tab() {
        let tabs = [WorkspaceTab {
            title: "7f3a",
            asks: false,
        }];
        let top = TopBar {
            tabs: Some(TabBar {
                tabs: &tabs,
                selected: 0,
            }),
            header: HEADER,
        };
        let (row, _) = top_row(top, 90);
        assert!(row.contains("project · remote"), "{row}");
        let (row, _) = top_row(top, 60);
        assert!(!row.contains("project"), "{row}");
        assert!(row.ends_with("remote none chosen (m) · davy "), "{row}");
        let (row, _) = top_row(top, 40);
        assert_eq!(row.trim_end(), " mahi   ⌂ threads   7f3a   +", "{row}");
        for width in [0, 1, 5] {
            top_row(top, width);
        }
    }

    #[test]
    fn a_thread_shows_its_agents_grouped_by_owner_beside_the_selected_one() {
        let mut parser = vt100::Parser::new(5, 20, 0);
        parser.process(b"hello from claude");
        let area = Rect::new(0, 0, 100, 14);
        let mut buffer = Buffer::empty(area);
        let cursor = ThreadView {
            agents: &AGENTS,
            selected: 0,
            list: ListPlace::Beside,
            hints: &[("ctrl-space", "workspace")],
            waiting: None,
            status: StatusLine::default(),
        }
        .render(Some(parser.screen()), area, &mut buffer);
        let rows = rows(&buffer);
        assert!(rows[1].contains("hello from claude"), "{rows:#?}");
        let list: Vec<String> = rows
            .iter()
            .map(|row| row.chars().skip(76).collect())
            .collect();
        let shown = list.join("\n");
        let in_list: Vec<String> = list
            .iter()
            .skip(1)
            .take(10)
            .map(|row| {
                row.trim_start_matches('│')
                    .trim_end_matches([' ', '│'])
                    .to_owned()
            })
            .collect();
        assert_eq!(
            in_list,
            [
                "Yours",
                " ● claude",
                "",
                "alice's",
                " ✓ claude",
                "",
                "bob's",
                " ○ codex",
                "",
                "",
            ],
            "{shown}"
        );
        let selected = Theme::selected().bg;
        let claude_row = 2;
        assert!(
            (77..99).all(|x| buffer[(x, claude_row)].style().bg == selected),
            "{shown}"
        );
        assert_ne!(buffer[(78, 5)].style().bg, selected);
        assert_eq!(buffer[(78, claude_row)].symbol(), "●");
        assert_eq!(buffer[(78, claude_row)].style().fg, Theme::selected().fg);
        assert_eq!(buffer[(78, 5)].symbol(), "✓");
        assert_eq!(buffer[(78, 5)].style().fg, Some(Theme::OK));
        assert!(rows[13].contains("ctrl-space workspace"), "{rows:#?}");
        assert_eq!(cursor, Some(Position::new(18, 1)));
    }

    #[test]
    fn a_list_of_teammates_agents_only_starts_with_the_first_owners_group() {
        let agents = [AGENTS[1], AGENTS[2]];
        let view = ThreadView {
            agents: &agents,
            selected: 1,
            list: ListPlace::Beside,
            hints: &[],
            waiting: None,
            status: StatusLine::default(),
        };
        let area = Rect::new(0, 0, 100, 10);
        let mut buffer = Buffer::empty(area);
        view.render(None, area, &mut buffer);
        let in_list: Vec<String> = rows(&buffer)
            .iter()
            .skip(1)
            .take(5)
            .map(|row| {
                row.chars()
                    .skip(76)
                    .collect::<String>()
                    .trim_start_matches('│')
                    .trim_end_matches([' ', '│'])
                    .to_owned()
            })
            .collect();
        assert_eq!(in_list, ["alice's", " ✓ claude", "", "bob's", " ○ codex"]);
        let at = |y| view.list_at(area, Position::new(80, y));
        assert_eq!(at(1), Some(ListHit::Elsewhere));
        assert_eq!(at(2), Some(ListHit::Agent(0)));
        assert_eq!(at(3), Some(ListHit::Elsewhere));
        assert_eq!(at(4), Some(ListHit::Elsewhere));
        assert_eq!(at(5), Some(ListHit::Agent(1)));
    }

    #[test]
    fn a_pane_without_a_screen_shows_what_it_waits_for_in_its_middle() {
        let area = Rect::new(0, 0, 80, 12);
        let view = ThreadView {
            agents: &[],
            selected: 0,
            list: ListPlace::Hidden,
            hints: &[],
            waiting: Some(("⠋", "waiting for the thread's host")),
            status: StatusLine::default(),
        };
        let mut buffer = Buffer::empty(area);
        view.render(None, area, &mut buffer);
        let drawn = rows(&buffer);
        let text = "⠋ waiting for the thread's host";
        let at = drawn.iter().position(|row| row.contains(text));
        assert_eq!(at, Some(5), "{drawn:#?}");
        let middle: Vec<char> = drawn[5].chars().collect();
        let left = middle.iter().position(|&cell| cell == '⠋').unwrap();
        let right = middle.len() - left - text.chars().count();
        assert!(left.abs_diff(right) <= 1, "{middle:?}");
        let parser = vt100::Parser::new(9, 78, 0);
        let mut buffer = Buffer::empty(area);
        view.render(Some(parser.screen()), area, &mut buffer);
        assert!(!rows(&buffer).iter().any(|row| row.contains("waiting")));
    }

    #[test]
    fn a_teammates_agent_is_named_read_only_and_the_list_over_the_pane_hides_the_cursor() {
        let mut parser = vt100::Parser::new(5, 78, 0);
        parser.process("\x1b[1;70Hx".as_bytes());
        let area = Rect::new(0, 0, 80, 10);
        let mut buffer = Buffer::empty(area);
        let cursor = ThreadView {
            agents: &AGENTS,
            selected: 1,
            list: ListPlace::Over,
            hints: &[],
            waiting: None,
            status: StatusLine::default(),
        }
        .render(Some(parser.screen()), area, &mut buffer);
        let rows = rows(&buffer);
        assert!(rows[0].contains("alice.claude (read-only)"), "{rows:#?}");
        assert!(!rows.iter().any(|row| row.contains("waiting")), "{rows:#?}");
        assert_eq!(cursor, None);
        let mut buffer = Buffer::empty(area);
        let cursor = ThreadView {
            agents: &AGENTS,
            selected: 1,
            list: ListPlace::Hidden,
            hints: &[],
            waiting: None,
            status: StatusLine::default(),
        }
        .render(Some(parser.screen()), area, &mut buffer);
        assert_eq!(cursor, Some(Position::new(71, 1)));
    }

    #[test]
    fn the_palette_offers_an_agent_by_its_name_and_a_teammates_by_its_owner_read_only() {
        let own = WorkspaceAgent {
            owner: None,
            name: "claude",
            state: AgentState::Done,
        };
        assert_eq!(own.palette_label(), "Show agent claude (✓ done)");
        let teammates = WorkspaceAgent {
            owner: Some("bob\x1b[2J"),
            name: "claude\n",
            state: AgentState::Live,
        };
        assert_eq!(
            teammates.palette_label(),
            "Show bob?[2J's agent claude? (read-only, ◉ live)"
        );
    }

    fn status_text(status: &StatusLine<'_>, width: u16) -> String {
        status
            .line(width)
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn the_status_line_names_conflicts_first_then_each_teammates_agent() {
        let conflicts = [StatusConflicts {
            from: "bob.claude",
            paths: &["src/a.rs", "src/b.rs"],
        }];
        let agents = [
            StatusAgent {
                slot: "bob.claude",
                state: TeammateState::Done,
                waits: Some("changes agent settings"),
                brought: &[],
            },
            StatusAgent {
                slot: "carol.codex",
                state: TeammateState::Working,
                waits: None,
                brought: &["src/client.rs", "src/lib.rs"],
            },
            StatusAgent {
                slot: "dan.claude",
                state: TeammateState::Asks,
                waits: None,
                brought: &[],
            },
        ];
        let status = StatusLine {
            conflicts: &conflicts,
            agents: &agents,
        };
        let whole = "conflicts from bob.claude: src/a.rs, src/b.rs  bob.claude done · a turn \
                     waits for you: changes agent settings  carol.codex working · src/client.rs, \
                     src/lib.rs  dan.claude asks";
        assert_eq!(status_text(&status, 200), whole);
        let narrower = u16::try_from(whole.chars().count() - 1).unwrap();
        assert_eq!(
            status_text(&status, narrower),
            "conflicts from bob.claude: src/a.rs, src/b.rs  bob.claude done · a turn waits for \
             you: changes agent settings  carol.codex working  dan.claude asks"
        );
        assert_eq!(
            status_text(&status, 120),
            "conflicts from bob.claude: src/a.rs, src/b.rs  bob.claude done · a turn waits for \
             you: changes agent settings  +2 more"
        );
        assert_eq!(
            status_text(&status, 50),
            "conflicts from bob.claude: src/a.rs and 1 more  +3 more"
        );
        assert_eq!(
            status_text(&status, 10),
            "conflicts from bob.claude: src/a.rs and 1 more  +3 more"
        );
        assert_eq!(status_text(&StatusLine::default(), 80), "");
    }

    #[test]
    fn the_status_line_shows_a_teammates_text_without_control_characters() {
        let agents = [StatusAgent {
            slot: "bob\x1b[2J.claude",
            state: TeammateState::Live,
            waits: None,
            brought: &["src/\u{202e}evil.rs"],
        }];
        let status = StatusLine {
            conflicts: &[],
            agents: &agents,
        };
        assert_eq!(
            status_text(&status, 80),
            "bob?[2J.claude live · src/?evil.rs"
        );
    }

    #[test]
    fn the_one_view_draws_the_status_line_between_the_pane_and_the_hints() {
        let (rows, columns) = ThreadView::agent_size(30, 120, ListPlace::StatusLine);
        assert_eq!(
            (rows + 1, columns),
            ThreadView::agent_size(30, 120, ListPlace::Hidden)
        );
        let agents = [StatusAgent {
            slot: "bob.claude",
            state: TeammateState::Working,
            waits: None,
            brought: &[],
        }];
        let screen = Rect::new(0, 0, 120, 30);
        let (_, body) = TopBar::split(screen);
        let mut buffer = Buffer::empty(screen);
        ThreadView {
            agents: &AGENTS,
            selected: 0,
            list: ListPlace::StatusLine,
            hints: &[("q", "quit")],
            waiting: None,
            status: StatusLine {
                conflicts: &[],
                agents: &agents,
            },
        }
        .render(None, body, &mut buffer);
        let row = |y: u16| -> String {
            (0..120)
                .map(|x| buffer[(x, y)].symbol().to_owned())
                .collect::<String>()
        };
        assert!(row(28).starts_with("bob.claude working"), "{:?}", row(28));
        assert!(row(29).contains("quit"), "{:?}", row(29));
        assert!(row(27).starts_with('╰'), "{:?}", row(27));
    }

    #[test]
    fn a_screen_of_the_agents_size_fills_the_pane_exactly() {
        assert_eq!(
            ThreadView::agent_size(30, 120, ListPlace::Over),
            ThreadView::agent_size(30, 120, ListPlace::Hidden)
        );
        for list in [ListPlace::Beside, ListPlace::Hidden] {
            let (rows, columns) = ThreadView::agent_size(30, 120, list);
            let mut parser = vt100::Parser::new(rows, columns, 0);
            let corner = format!("\x1b[{rows};{columns}H#");
            parser.process(corner.as_bytes());
            let screen = Rect::new(0, 0, 120, 30);
            let (_, body) = TopBar::split(screen);
            let mut buffer = Buffer::empty(screen);
            ThreadView {
                agents: &AGENTS,
                selected: 0,
                list,
                hints: &[],
                waiting: None,
                status: StatusLine::default(),
            }
            .render(Some(parser.screen()), body, &mut buffer);
            let bottom = rows + 1;
            assert_eq!(buffer[(columns, bottom)].symbol(), "#", "{list:?}");
            assert_eq!(buffer[(columns + 1, bottom)].symbol(), "│", "{list:?}");
            assert_eq!(buffer[(columns, bottom + 1)].symbol(), "─", "{list:?}");
        }
    }

    #[test]
    fn a_click_finds_the_tab_and_the_agent_drawn_under_it() {
        let tabs = [
            WorkspaceTab {
                title: "7f3a",
                asks: false,
            },
            WorkspaceTab {
                title: "9a48",
                asks: true,
            },
        ];
        let bar = TabBar {
            tabs: &tabs,
            selected: 1,
        };
        assert_eq!(bar.tab_at(0), TabHit::Nothing);
        assert_eq!(bar.tab_at(6), TabHit::Nothing);
        assert_eq!(bar.tab_at(7), TabHit::Tab(0));
        assert_eq!(bar.tab_at(17), TabHit::Tab(0));
        assert_eq!(bar.tab_at(18), TabHit::Nothing);
        assert_eq!(bar.tab_at(19), TabHit::Tab(1));
        assert_eq!(bar.tab_at(26), TabHit::Tab(2));
        assert_eq!(bar.tab_at(34), TabHit::Nothing);
        assert_eq!(bar.tab_at(35), TabHit::New);
        assert_eq!(bar.tab_at(47), TabHit::Nothing);
        let view = ThreadView {
            agents: &AGENTS,
            selected: 0,
            list: ListPlace::Beside,
            hints: &[],
            waiting: None,
            status: StatusLine::default(),
        };
        let area = Rect::new(0, 1, 100, 12);
        let at = |view: &ThreadView<'_>, x, y| view.list_at(area, Position::new(x, y));
        assert_eq!(at(&view, 80, 1), Some(ListHit::Elsewhere));
        assert_eq!(at(&view, 80, 2), Some(ListHit::Elsewhere));
        assert_eq!(at(&view, 80, 3), Some(ListHit::Agent(0)));
        assert_eq!(at(&view, 80, 4), Some(ListHit::Elsewhere));
        assert_eq!(at(&view, 80, 5), Some(ListHit::Elsewhere));
        assert_eq!(at(&view, 80, 6), Some(ListHit::Agent(1)));
        assert_eq!(at(&view, 80, 9), Some(ListHit::Agent(2)));
        assert_eq!(at(&view, 80, 10), Some(ListHit::Elsewhere));
        assert_eq!(at(&view, 10, 3), None);
        let over = ThreadView {
            list: ListPlace::Over,
            ..view
        };
        assert_eq!(at(&over, 90, 3), Some(ListHit::Agent(0)));
        assert_eq!(at(&over, 99, 3), Some(ListHit::Elsewhere));
        assert_eq!(at(&over, 50, 3), None);
        let hidden = ThreadView {
            list: ListPlace::Hidden,
            ..view
        };
        assert_eq!(at(&hidden, 80, 3), None);
    }

    #[test]
    fn a_position_in_the_pane_is_a_cell_of_the_agents_screen() {
        let view = ThreadView {
            agents: &AGENTS,
            selected: 0,
            list: ListPlace::Beside,
            hints: &[],
            waiting: None,
            status: StatusLine::default(),
        };
        let area = Rect::new(0, 1, 100, 12);
        assert_eq!(
            view.pane_point(area, Position::new(1, 2), false),
            Some((0, 0))
        );
        assert_eq!(
            view.pane_point(area, Position::new(5, 4), false),
            Some((4, 2))
        );
        assert_eq!(view.pane_point(area, Position::new(0, 2), false), None);
        assert_eq!(
            view.pane_point(area, Position::new(90, 30), true),
            Some((73, 8))
        );
        assert_eq!(
            view.pane_point(area, Position::new(0, 0), true),
            Some((0, 0))
        );
    }

    #[test]
    fn drawing_into_a_tiny_area_does_not_fail() {
        let parser = vt100::Parser::new(5, 20, 0);
        for (width, height) in [(0, 0), (1, 1), (3, 2)] {
            let area = Rect::new(0, 0, width, height);
            let mut buffer = Buffer::empty(area);
            for list in [ListPlace::Beside, ListPlace::Over, ListPlace::Hidden] {
                ThreadView {
                    agents: &AGENTS,
                    selected: 5,
                    list,
                    hints: &[("q", "quit")],
                    waiting: None,
                    status: StatusLine::default(),
                }
                .render(Some(parser.screen()), area, &mut buffer);
            }
            TopBar {
                tabs: Some(TabBar {
                    tabs: &[],
                    selected: 0,
                }),
                header: HEADER,
            }
            .render(area, &mut buffer);
        }
    }

    #[test]
    fn the_agent_gets_what_the_tab_bar_the_borders_the_hints_and_the_list_leave() {
        assert_eq!(ThreadView::agent_size(40, 120, ListPlace::Beside), (36, 94));
        assert_eq!(ThreadView::agent_size(40, 120, ListPlace::Over), (36, 118));
        assert_eq!(
            ThreadView::agent_size(40, 120, ListPlace::Hidden),
            (36, 118)
        );
        assert_eq!(ThreadView::agent_size(3, 10, ListPlace::Beside), (2, 2));
        assert_eq!(ListPlace::shown_at(99), ListPlace::Over);
        assert_eq!(ListPlace::shown_at(100), ListPlace::Beside);
    }
}
