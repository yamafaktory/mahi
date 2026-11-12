use std::borrow::Cow;

use mahi_core::LineCounts;
use ratatui_core::{
    buffer::Buffer,
    layout::{
        Constraint,
        Layout,
        Position,
        Rect,
    },
    style::{
        Color,
        Modifier,
        Style,
    },
    text::{
        Line,
        Span,
    },
    widgets::Widget,
};
use ratatui_widgets::{
    block::{
        Block,
        Padding,
    },
    borders::BorderType,
    paragraph::{
        Paragraph,
        Wrap,
    },
};
use unicode_width::UnicodeWidthStr;

use crate::{
    Theme,
    dialog::{
        shown,
        tail,
    },
    key_hints,
};

const TOP_ROWS: u16 = 1;
const HINT_ROWS: u16 = 1;
const STATUS_ROWS: u16 = 1;
const STATUS_GAP: &str = "  ";
const SMALLEST: u16 = 2;
const PANEL_COLUMNS: u16 = 36;
const PANEL_FROM: u16 = 100;
const PANEL_TITLE: &str = " Thread ";
const CHANGES_TITLE: &str = "Changes since base";

/// What an agent in a thread's tab is doing, as the workspace shows it.
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
    /// Returns how the workspace shows the state, such as `✓ done`.
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
}

/// An agent of a thread, as the workspace shows it.
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

impl From<TeammateState> for AgentState {
    fn from(state: TeammateState) -> Self {
        match state {
            TeammateState::Working => Self::Working,
            TeammateState::Done => Self::Done,
            TeammateState::Asks => Self::Asks,
            TeammateState::Live => Self::Live,
            TeammateState::Offline => Self::Offline,
        }
    }
}

/// A teammate's agent as the status line names it.
#[derive(Debug, Clone, Copy)]
pub struct StatusAgent<'a> {
    /// Its slot, such as `bob.claude`.
    pub slot: &'a str,
    /// Its participant's place in the thread's `meta`, which picks their colour.
    pub place: usize,
    /// What it is doing.
    pub state: TeammateState,
    /// What a turn of it that waits for the user's keypress changes, such as `changes agent
    /// settings`.
    pub waits: Option<&'a str>,
    /// The files the last merge of its work into the user's worktree brought.
    pub brought: &'a [String],
}

/// The paths a merge of a teammate's agent's work left with conflict markers.
#[derive(Debug, Clone, Copy)]
pub struct StatusConflicts<'a> {
    /// The slot of the teammate's agent, such as `bob.claude`.
    pub from: &'a str,
    /// The first paths kept with its markers.
    pub paths: &'a [String],
    /// How many more paths are kept with its markers.
    pub more: usize,
}

/// A merge of the landing branch into the user's worktree that waits for the user's keypress.
#[derive(Debug, Clone, Copy)]
pub struct StatusLanding<'a> {
    /// The landing branch, such as `main`.
    pub branch: &'a str,
    /// What the merge changes, such as `changes agent settings`.
    pub waits: &'a str,
}

/// The row under the pane in the one view: a held merge of the landing branch, the conflicts
/// to resolve, then each teammate's agent.
#[derive(Debug, Clone, Copy, Default)]
pub struct StatusLine<'a> {
    /// The merge of the landing branch that waits for the user's keypress, when one does.
    pub landing: Option<StatusLanding<'a>>,
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
    /// Returns the line for a row `width` columns wide, the held merge of the landing branch
    /// always first: whole when it fits, otherwise without the files merges brought, then
    /// with the last agents left out and counted as `+N more`, then with the conflicts' paths
    /// cut short, each list ending with `and N more`.
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
        let mut kept: Vec<Item<'a>> = self
            .landing
            .as_ref()
            .map(landing_item)
            .into_iter()
            .collect();
        let landing = kept.len();
        let mut listed = most_paths;
        loop {
            kept.truncate(landing);
            kept.extend(
                self.conflicts
                    .iter()
                    .map(|conflicts| conflicts_item(conflicts, listed)),
            );
            if let Some(line) = fitting(&kept, (&whole, &short), width) {
                return line;
            }
            if listed <= 1 {
                return joined(kept.iter().chain(&more(self.agents.len())));
            }
            listed -= 1;
        }
    }
}

/// Returns the line of the `kept` items, the held landing merge and the conflicts, and the
/// agents, `whole` or `short`, that fits in `width`, as the line leaves things out; `None` when
/// even the kept items and the count of every agent do not fit.
fn fitting<'a>(
    kept: &[Item<'a>],
    (whole, short): (&[Item<'a>], &[Item<'a>]),
    width: usize,
) -> Option<Line<'a>> {
    let wide = |items: &[&Item<'_>]| -> usize {
        let gaps = items.len().saturating_sub(1) * STATUS_GAP.len();
        items.iter().map(|item| item.width).sum::<usize>() + gaps
    };
    for agents in [whole, short] {
        let items: Vec<&Item<'a>> = kept.iter().chain(agents).collect();
        if wide(&items) <= width {
            return Some(joined(items));
        }
    }
    let shown = (0..short.len()).rev();
    for listed_agents in shown {
        let more = more(short.len() - listed_agents);
        let items: Vec<&Item<'a>> = kept
            .iter()
            .chain(short.iter().take(listed_agents))
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
        Span::styled(
            shown(agent.slot),
            Style::new()
                .fg(Theme::participant(agent.place))
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::raw(agent.state.word()),
    ];
    if let Some(waits) = agent.waits {
        spans.push(Span::styled(" · ", Theme::muted()));
        spans.extend(turn_waits(waits));
    }
    if brought == Brought::Shown && !agent.brought.is_empty() {
        spans.push(Span::styled(" · ", Theme::muted()));
        push_paths(&mut spans, agent.brought, Style::new());
    }
    Item::new(spans)
}

/// Returns the spans that say a turn waits for the user's keypress, and what it changes.
fn turn_waits(waits: &str) -> [Span<'_>; 2] {
    let warn = Style::new().fg(Theme::WARN);
    [
        Span::styled("a turn waits for you: ", warn),
        Span::styled(shown(waits), warn),
    ]
}

fn landing_item<'a>(landing: &StatusLanding<'a>) -> Item<'a> {
    let warn = Style::new().fg(Theme::WARN);
    Item::new(vec![
        Span::styled(shown(landing.branch), Theme::title()),
        Span::styled(" · ", Theme::muted()),
        Span::styled("a merge waits for you: ", warn),
        Span::styled(shown(landing.waits), warn),
    ])
}

/// Returns the item of `conflicts`, listing at most `listed` of its paths, at least one.
fn conflicts_item<'a>(conflicts: &StatusConflicts<'a>, listed: usize) -> Item<'a> {
    let warn = Style::new().fg(Theme::CONFLICT);
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
    let left = conflicts.paths.len() - listed + conflicts.more;
    if left > 0 {
        spans.push(Span::styled(format!(" and {left} more"), warn));
    }
    Item::new(spans)
}

fn push_paths<'a>(spans: &mut Vec<Span<'a>>, paths: &'a [String], style: Style) {
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
        buffer.set_style(area, Theme::surface());
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

/// The user's own agent, as the panel names it first.
#[derive(Debug, Clone, Copy)]
pub struct OwnAgent<'a> {
    /// Its slot, such as `davy.claude`.
    pub slot: &'a str,
    /// The user's place in the thread's `meta`, which picks their colour.
    pub place: usize,
    /// What it is doing.
    pub state: AgentState,
}

/// The files of the user's worktree that changed since the base or the last landing, and
/// whether more changed than are listed.
#[derive(Debug, Clone, Copy, Default)]
pub struct PanelChanges<'a> {
    /// The changed files, `/`-separated, each with the lines it adds and removes.
    pub files: &'a [(String, LineCounts)],
    /// Whether more files changed than are listed.
    pub more: bool,
}

/// The panel at the right of a thread's pane: what waits for the user, the conflicts, each
/// agent of the thread, the user's own first, and the worktree's changes since the base or
/// the last landing. On a terminal too narrow for it, its status line shows under the pane.
#[derive(Debug, Clone, Copy, Default)]
pub struct Panel<'a> {
    /// The user's own agent, when one runs in the tab.
    pub own: Option<OwnAgent<'a>>,
    /// The held merge of the landing branch, the conflicts and the teammates' agents.
    pub status: StatusLine<'a>,
    /// The worktree's changes, once they were read.
    pub changes: Option<PanelChanges<'a>>,
}

impl<'a> Panel<'a> {
    /// Returns the panel's lines for a panel `width` columns wide inside its borders.
    fn lines(&self, width: u16) -> Vec<Line<'a>> {
        let width = usize::from(width);
        let mut lines: Vec<Line<'a>> = Vec::new();
        lines.extend(
            self.status
                .landing
                .as_ref()
                .map(|landing| Line::from(landing_item(landing).spans)),
        );
        lines.extend(
            self.status
                .conflicts
                .iter()
                .map(|conflicts| Line::from(conflicts_item(conflicts, usize::MAX).spans)),
        );
        if !lines.is_empty() {
            lines.push(Line::default());
        }
        if let Some(own) = self.own {
            lines.push(agent_row(own.slot, own.place, own.state));
            lines.push(Line::styled("  you", Theme::muted()));
        }
        for agent in self.status.agents {
            lines.push(agent_row(agent.slot, agent.place, agent.state.into()));
            if let Some(waits) = agent.waits {
                let mut spans = vec![Span::raw("  ")];
                spans.extend(turn_waits(waits));
                lines.push(Line::from(spans));
            }
            if !agent.brought.is_empty() {
                let mut spans = vec![Span::raw("  "), Span::styled("merged: ", Theme::muted())];
                push_paths(&mut spans, agent.brought, Style::new());
                lines.push(Line::from(spans));
            }
        }
        let Some(changes) = self.changes else {
            return lines;
        };
        lines.push(Line::default());
        lines.push(Line::styled(
            CHANGES_TITLE,
            Style::new().add_modifier(Modifier::BOLD),
        ));
        if changes.files.is_empty() && !changes.more {
            lines.push(Line::styled("  none", Theme::muted()));
        }
        lines.extend(
            changes
                .files
                .iter()
                .map(|(path, counts)| file_row(path, *counts, width)),
        );
        if changes.more {
            lines.push(Line::styled(
                "  more changed than are listed",
                Theme::muted(),
            ));
        }
        lines
    }

    fn render(&self, area: Rect, buffer: &mut Buffer) {
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(Theme::BORDER))
            .style(Theme::surface())
            .padding(Padding::horizontal(1))
            .title(Span::styled(PANEL_TITLE, Theme::title()));
        let inner = block.inner(area);
        block.render(area, buffer);
        Paragraph::new(self.lines(inner.width))
            .wrap(Wrap { trim: false })
            .render(inner, buffer);
    }
}

/// Returns the row that names an agent in its participant's colour, with its state.
fn agent_row(slot: &str, place: usize, state: AgentState) -> Line<'_> {
    let colour = Style::new().fg(Theme::participant(place));
    Line::from(vec![
        Span::styled("● ", colour),
        Span::styled(shown(slot), colour.add_modifier(Modifier::BOLD)),
        Span::raw("  "),
        Span::styled(state.as_str(), Theme::muted()),
    ])
}

/// Returns the row of a changed file, its path cut from the left to leave room for its line
/// counts at the right of a row `width` columns wide.
fn file_row(path: &str, lines: LineCounts, width: usize) -> Line<'_> {
    let counts = counts_spans(lines);
    let counts_width: usize = counts.iter().map(Span::width).sum();
    let room = width.saturating_sub(2 + counts_width + usize::from(counts_width > 0));
    let path = shown(path);
    let path = if path.width() > room {
        Cow::Owned(format!("…{}", tail(&path, room.saturating_sub(1))))
    } else {
        path
    };
    let gap = width.saturating_sub(2 + path.width() + counts_width);
    let mut spans = Vec::with_capacity(counts.len() + 3);
    spans.push(Span::raw("  "));
    spans.push(Span::raw(path));
    spans.push(Span::raw(" ".repeat(gap)));
    spans.extend(counts);
    Line::from(spans)
}

/// Returns the line counts of a changed file: `+12` in the colour of added lines and `−3` in
/// that of removed ones, or why they were not counted.
fn counts_spans(lines: LineCounts) -> Vec<Span<'static>> {
    match lines {
        LineCounts::Counted { added, removed } => {
            let mut spans = Vec::with_capacity(3);
            if added > 0 {
                spans.push(Span::styled(
                    format!("+{added}"),
                    Style::new().fg(Theme::ADDED),
                ));
            }
            if added > 0 && removed > 0 {
                spans.push(Span::raw(" "));
            }
            if removed > 0 {
                spans.push(Span::styled(
                    format!("−{removed}"),
                    Style::new().fg(Theme::REMOVED),
                ));
            }
            spans
        }
        LineCounts::Binary => vec![Span::styled("binary", Theme::muted())],
        LineCounts::TooLarge => vec![Span::styled("too large", Theme::muted())],
        LineCounts::NotAFile => Vec::new(),
    }
}

/// A thread's tab: one of its agents at full size, the panel at its right, or its status line
/// under it on a narrow terminal, and the keys that reach mahi.
#[derive(Debug, Clone, Copy)]
pub struct ThreadView<'a> {
    /// The agent shown at full size, when there is one.
    pub shown: Option<WorkspaceAgent<'a>>,
    /// The keys that reach mahi, and what they do.
    pub hints: &'a [(&'a str, &'a str)],
    /// The spinner's frame and what the pane waits for, drawn in its middle while it has no
    /// screen.
    pub waiting: Option<(&'a str, &'a str)>,
    /// What the panel shows.
    pub panel: Panel<'a>,
}

impl ThreadView<'_> {
    /// Returns the rows and columns of an agent's terminal in a thread's tab on a terminal of
    /// `rows` and `columns`, at least two of each.
    #[must_use]
    pub fn agent_size(rows: u16, columns: u16) -> (u16, u16) {
        let area = Rect::new(0, 0, columns, rows.saturating_sub(TOP_ROWS));
        let inner = Block::bordered().inner(Self::areas(area).pane);
        (inner.height.max(SMALLEST), inner.width.max(SMALLEST))
    }

    /// Draws the tab into `area`, below the top row, with the shown agent's `screen` in its
    /// pane; returns where the agent's cursor is when it shows it.
    pub fn render(
        &self,
        screen: Option<&vt100::Screen>,
        area: Rect,
        buffer: &mut Buffer,
    ) -> Option<Position> {
        let TabAreas {
            pane,
            beside,
            footer,
        } = Self::areas(area);
        let title = self
            .shown
            .map_or_else(String::new, |agent| format!(" {} ", agent.label()));
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(Theme::BORDER))
            .title(Span::styled(title, Theme::title()));
        let inner = block.inner(pane);
        block.render(pane, buffer);
        if let Some(screen) = screen {
            draw_screen(screen, inner, buffer);
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
        match beside {
            Beside::Panel(panel) => self.panel.render(panel, buffer),
            Beside::Status(status) => self.panel.status.line(status.width).render(status, buffer),
        }
        Line::from(key_hints(self.hints)).render(footer, buffer);
        let screen = screen?;
        let (row, column) = screen.cursor_position();
        let cursor = Position::new(inner.x.saturating_add(column), inner.y.saturating_add(row));
        (!screen.hide_cursor() && inner.contains(cursor)).then_some(cursor)
    }

    /// Returns the cell of the agent's screen at `position`, when the tab is drawn in `area`,
    /// below the top row; a position past the pane gives its nearest cell when `clamp`,
    /// as a drag that leaves it does, and nothing otherwise.
    #[must_use]
    pub fn pane_point(area: Rect, position: Position, clamp: bool) -> Option<(u16, u16)> {
        let inner = Block::bordered().inner(Self::areas(area).pane);
        if inner.is_empty() || (!clamp && !inner.contains(position)) {
            return None;
        }
        let column = position.x.clamp(inner.x, inner.right() - 1) - inner.x;
        let row = position.y.clamp(inner.y, inner.bottom() - 1) - inner.y;
        Some((column, row))
    }

    /// Splits `area` into the pane, the panel at its right when `area` is wide enough for it,
    /// or else the status line's row under it, and the hints' row.
    fn areas(area: Rect) -> TabAreas {
        let wide = area.width >= PANEL_FROM;
        let [body, status, footer] = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(if wide { 0 } else { STATUS_ROWS }),
            Constraint::Length(HINT_ROWS),
        ])
        .areas(area);
        if !wide {
            return TabAreas {
                pane: body,
                beside: Beside::Status(status),
                footer,
            };
        }
        let [pane, panel] =
            Layout::horizontal([Constraint::Fill(1), Constraint::Length(PANEL_COLUMNS)])
                .areas(body);
        TabAreas {
            pane,
            beside: Beside::Panel(panel),
            footer,
        }
    }
}

/// Where a thread's tab draws its parts.
#[derive(Debug, Clone, Copy)]
struct TabAreas {
    pane: Rect,
    beside: Beside,
    footer: Rect,
}

/// What a thread's tab draws beside its pane: the panel at its right, or the status line's
/// row under it.
#[derive(Debug, Clone, Copy)]
enum Beside {
    Panel(Rect),
    Status(Rect),
}

impl WorkspaceAgent<'_> {
    /// Returns how the pane's title names the agent: its name and state, or a teammate's slot
    /// marked read-only, then its state.
    #[must_use]
    pub fn label(&self) -> String {
        let state = self.state.as_str();
        match self.owner {
            Some(owner) => format!("{}.{} (read-only, {state})", shown(owner), shown(self.name)),
            None => format!("{} ({state})", shown(self.name)),
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

fn draw_screen(screen: &vt100::Screen, area: Rect, buffer: &mut Buffer) {
    let (rows, columns) = screen.size();
    for row in 0..rows.min(area.height) {
        for column in 0..columns.min(area.width) {
            let Some(cell) = screen.cell(row, column) else {
                continue;
            };
            let Some(target) = buffer.cell_mut((area.x + column, area.y + row)) else {
                continue;
            };
            if cell.is_wide_continuation() {
                target.reset();
                continue;
            }
            let wide_at_edge = cell.is_wide() && column + 1 >= area.width;
            let symbol = cell.contents();
            if symbol.is_empty() || wide_at_edge {
                target.set_symbol(" ");
            } else {
                target.set_symbol(symbol);
            }
            target.set_style(style_of(cell));
        }
    }
}

fn style_of(cell: &vt100::Cell) -> Style {
    let mut modifier = Modifier::empty();
    for (on, flag) in [
        (cell.bold(), Modifier::BOLD),
        (cell.dim(), Modifier::DIM),
        (cell.italic(), Modifier::ITALIC),
        (cell.underline(), Modifier::UNDERLINED),
        (cell.inverse(), Modifier::REVERSED),
    ] {
        if on {
            modifier |= flag;
        }
    }
    Style::new()
        .fg(color_of(cell.fgcolor()))
        .bg(color_of(cell.bgcolor()))
        .add_modifier(modifier)
}

fn color_of(color: vt100::Color) -> Color {
    match color {
        vt100::Color::Default => Color::Reset,
        vt100::Color::Idx(index) => Color::Indexed(index),
        vt100::Color::Rgb(red, green, blue) => Color::Rgb(red, green, blue),
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
                Some(Theme::SURFACE),
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
    fn a_teammate_is_named_in_the_colour_of_their_place() {
        let agents = [
            StatusAgent {
                place: 0,
                slot: "alice.claude",
                state: TeammateState::Done,
                waits: None,
                brought: &[],
            },
            StatusAgent {
                place: 8,
                slot: "carol.codex",
                state: TeammateState::Working,
                waits: None,
                brought: &[],
            },
        ];
        let line = StatusLine {
            landing: None,
            conflicts: &[],
            agents: &agents,
        }
        .line(80);
        let colour = |slot: &str| {
            line.spans
                .iter()
                .find(|span| span.content == slot)
                .and_then(|span| span.style.fg)
        };
        assert_eq!(colour("alice.claude"), Some(Theme::PARTICIPANTS[0]));
        assert_eq!(colour("carol.codex"), Some(Theme::PARTICIPANTS[2]));
        assert_eq!(Theme::participant(6), Theme::participant(0));
    }

    fn texts(lines: &[Line<'_>]) -> Vec<String> {
        lines
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect()
            })
            .collect()
    }

    #[test]
    fn the_panel_names_each_agent_then_the_changes_since_the_base() {
        let brought = ["README.md".to_owned()];
        let agents = [StatusAgent {
            place: 1,
            slot: "bob.claude",
            state: TeammateState::Done,
            waits: Some("changes agent settings"),
            brought: &brought,
        }];
        let files = [
            (
                "README.md".to_owned(),
                LineCounts::Counted {
                    added: 1,
                    removed: 0,
                },
            ),
            (
                "src/lib.rs".to_owned(),
                LineCounts::Counted {
                    added: 12,
                    removed: 3,
                },
            ),
            ("logo.png".to_owned(), LineCounts::Binary),
        ];
        let panel = Panel {
            own: Some(OwnAgent {
                slot: "davy.claude",
                place: 0,
                state: AgentState::Working,
            }),
            status: StatusLine {
                landing: None,
                conflicts: &[],
                agents: &agents,
            },
            changes: Some(PanelChanges {
                files: &files,
                more: true,
            }),
        };
        let lines = panel.lines(30);
        assert_eq!(
            texts(&lines),
            [
                "● davy.claude  ● working",
                "  you",
                "● bob.claude  ✓ done",
                "  a turn waits for you: changes agent settings",
                "  merged: README.md",
                "",
                "Changes since base",
                "  README.md                 +1",
                "  src/lib.rs            +12 −3",
                "  logo.png              binary",
                "  more changed than are listed",
            ]
        );
        assert_eq!(lines[0].spans[1].style.fg, Some(Theme::PARTICIPANTS[0]));
        assert_eq!(lines[2].spans[1].style.fg, Some(Theme::PARTICIPANTS[1]));
        let counts = &lines[8].spans;
        assert_eq!(counts[counts.len() - 3].style.fg, Some(Theme::ADDED));
        assert_eq!(counts[counts.len() - 1].style.fg, Some(Theme::REMOVED));
    }

    #[test]
    fn the_panel_cuts_a_long_path_from_the_left_and_says_when_nothing_changed() {
        let files = [(
            "crates/mahi-term/src/workspace.rs".to_owned(),
            LineCounts::Counted {
                added: 120,
                removed: 4,
            },
        )];
        let panel = Panel {
            changes: Some(PanelChanges {
                files: &files,
                more: false,
            }),
            ..Panel::default()
        };
        let rows = texts(&panel.lines(24));
        assert_eq!(rows.last().unwrap(), "  …/workspace.rs +120 −4");
        assert_eq!(rows.last().unwrap().chars().count(), 24);
        let conflicts = [StatusConflicts {
            from: "bob.claude",
            paths: &["a.rs".to_owned(), "b.rs".to_owned()],
            more: 1,
        }];
        let empty = Panel {
            status: StatusLine {
                landing: Some(StatusLanding {
                    branch: "main",
                    waits: "changes agent settings",
                }),
                conflicts: &conflicts,
                agents: &[],
            },
            changes: Some(PanelChanges::default()),
            ..Panel::default()
        };
        assert_eq!(texts(&Panel::default().lines(40)), Vec::<String>::new());
        assert_eq!(
            texts(&empty.lines(40)),
            [
                "main · a merge waits for you: changes agent settings",
                "conflicts from bob.claude: a.rs, b.rs and 1 more",
                "",
                "",
                "Changes since base",
                "  none",
            ]
        );
    }

    #[test]
    fn a_wide_tab_draws_the_panel_at_the_right_and_no_status_line() {
        let agents = [StatusAgent {
            place: 1,
            slot: "bob.codex",
            state: TeammateState::Offline,
            waits: None,
            brought: &[],
        }];
        let area = Rect::new(0, 0, 120, 14);
        let mut buffer = Buffer::empty(area);
        ThreadView {
            shown: Some(AGENTS[0]),
            hints: &[("ctrl-space", "workspace")],
            waiting: None,
            panel: Panel {
                status: StatusLine {
                    landing: None,
                    conflicts: &[],
                    agents: &agents,
                },
                ..Panel::default()
            },
        }
        .render(None, area, &mut buffer);
        let rows = rows(&buffer);
        let panel: String = rows[0].chars().skip(84).collect();
        assert!(panel.starts_with("╭ Thread "), "{rows:#?}");
        assert!(rows[1].contains("│ ● bob.codex  ○ offline"), "{rows:#?}");
        assert!(rows[12].starts_with('╰'), "{rows:#?}");
        assert!(rows[13].contains("ctrl-space workspace"), "{rows:#?}");
        assert!(
            !rows.iter().any(|row| row.starts_with("bob.codex")),
            "{rows:#?}"
        );
        assert_eq!(buffer[(100, 5)].style().bg, Some(Theme::SURFACE));
    }

    #[test]
    fn a_thread_shows_its_agent_with_the_status_line_and_the_hints_under_it() {
        let mut parser = vt100::Parser::new(5, 20, 0);
        parser.process(b"hello from claude");
        let agents = [StatusAgent {
            place: 1,
            slot: "bob.codex",
            state: TeammateState::Offline,
            waits: None,
            brought: &[],
        }];
        let area = Rect::new(0, 0, 99, 14);
        let mut buffer = Buffer::empty(area);
        let cursor = ThreadView {
            shown: Some(AGENTS[0]),
            hints: &[("ctrl-space", "workspace")],
            waiting: None,
            panel: Panel {
                status: StatusLine {
                    landing: None,
                    conflicts: &[],
                    agents: &agents,
                },
                ..Panel::default()
            },
        }
        .render(Some(parser.screen()), area, &mut buffer);
        let rows = rows(&buffer);
        assert!(rows[0].contains(" claude (● working) "), "{rows:#?}");
        assert!(rows[1].contains("hello from claude"), "{rows:#?}");
        assert!(rows[11].starts_with('╰'), "{rows:#?}");
        assert!(rows[12].starts_with("bob.codex offline"), "{rows:#?}");
        assert!(rows[13].contains("ctrl-space workspace"), "{rows:#?}");
        assert_eq!(cursor, Some(Position::new(18, 1)));
    }

    #[test]
    fn a_pane_without_a_screen_shows_what_it_waits_for_in_its_middle() {
        let area = Rect::new(0, 0, 80, 13);
        let view = ThreadView {
            shown: None,
            hints: &[],
            waiting: Some(("⠋", "waiting for the thread's host")),
            panel: Panel::default(),
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
    fn a_teammates_agent_is_named_read_only() {
        let mut parser = vt100::Parser::new(5, 78, 0);
        parser.process("\x1b[1;70Hx".as_bytes());
        let area = Rect::new(0, 0, 80, 10);
        let mut buffer = Buffer::empty(area);
        let cursor = ThreadView {
            shown: Some(AGENTS[1]),
            hints: &[],
            waiting: None,
            panel: Panel::default(),
        }
        .render(Some(parser.screen()), area, &mut buffer);
        let rows = rows(&buffer);
        assert!(
            rows[0].contains("alice.claude (read-only, ✓ done)"),
            "{rows:#?}"
        );
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

    fn owned(paths: &[&str]) -> Vec<String> {
        paths.iter().map(|path| (*path).to_owned()).collect()
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
            paths: &owned(&["src/a.rs", "src/b.rs"]),
            more: 0,
        }];
        let agents = [
            StatusAgent {
                place: 1,
                slot: "bob.claude",
                state: TeammateState::Done,
                waits: Some("changes agent settings"),
                brought: &[],
            },
            StatusAgent {
                place: 1,
                slot: "carol.codex",
                state: TeammateState::Working,
                waits: None,
                brought: &owned(&["src/client.rs", "src/lib.rs"]),
            },
            StatusAgent {
                place: 1,
                slot: "dan.claude",
                state: TeammateState::Asks,
                waits: None,
                brought: &[],
            },
        ];
        let status = StatusLine {
            landing: None,
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
        let counted = [StatusConflicts {
            from: "bob.claude",
            paths: &owned(&["src/a.rs"]),
            more: 5,
        }];
        let status = StatusLine {
            landing: None,
            conflicts: &counted,
            agents: &[],
        };
        assert_eq!(
            status_text(&status, 80),
            "conflicts from bob.claude: src/a.rs and 5 more"
        );
    }

    #[test]
    fn the_status_line_names_a_held_landing_merge_first_and_never_leaves_it_out() {
        let conflicts = [StatusConflicts {
            from: "bob.claude",
            paths: &owned(&["src/a.rs", "src/b.rs"]),
            more: 0,
        }];
        let agents = [StatusAgent {
            place: 1,
            slot: "bob.claude",
            state: TeammateState::Done,
            waits: None,
            brought: &[],
        }];
        let status = StatusLine {
            landing: Some(StatusLanding {
                branch: "main",
                waits: "changes agent settings",
            }),
            conflicts: &conflicts,
            agents: &agents,
        };
        assert_eq!(
            status_text(&status, 200),
            "main · a merge waits for you: changes agent settings  conflicts from bob.claude: \
             src/a.rs, src/b.rs  bob.claude done"
        );
        assert_eq!(
            status_text(&status, 10),
            "main · a merge waits for you: changes agent settings  conflicts from bob.claude: \
             src/a.rs and 1 more  +1 more"
        );
        let status = StatusLine {
            landing: Some(StatusLanding {
                branch: "ma\x1b[2Jin",
                waits: "changes agent settings",
            }),
            ..StatusLine::default()
        };
        assert_eq!(
            status_text(&status, 80),
            "ma?[2Jin · a merge waits for you: changes agent settings"
        );
    }

    #[test]
    fn the_status_line_shows_a_teammates_text_without_control_characters() {
        let agents = [StatusAgent {
            place: 1,
            slot: "bob\x1b[2J.claude",
            state: TeammateState::Live,
            waits: None,
            brought: &owned(&["src/\u{202e}evil.rs"]),
        }];
        let status = StatusLine {
            landing: None,
            conflicts: &[],
            agents: &agents,
        };
        assert_eq!(
            status_text(&status, 80),
            "bob?[2J.claude live · src/?evil.rs"
        );
    }

    #[test]
    fn a_screen_of_the_agents_size_fills_the_pane_exactly() {
        let (rows, columns) = ThreadView::agent_size(30, 120);
        let mut parser = vt100::Parser::new(rows, columns, 0);
        let corner = format!("\x1b[{rows};{columns}H#");
        parser.process(corner.as_bytes());
        let screen = Rect::new(0, 0, 120, 30);
        let (_, body) = TopBar::split(screen);
        let mut buffer = Buffer::empty(screen);
        ThreadView {
            shown: Some(AGENTS[0]),
            hints: &[],
            waiting: None,
            panel: Panel::default(),
        }
        .render(Some(parser.screen()), body, &mut buffer);
        let bottom = rows + 1;
        assert_eq!(buffer[(columns, bottom)].symbol(), "#");
        assert_eq!(buffer[(columns + 1, bottom)].symbol(), "│");
        assert_eq!(buffer[(columns, bottom + 1)].symbol(), "─");
    }

    #[test]
    fn a_click_finds_the_tab_drawn_under_it() {
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
    }

    #[test]
    fn a_position_in_the_pane_is_a_cell_of_the_agents_screen() {
        let area = Rect::new(0, 1, 99, 13);
        let at = |x, y, clamp| ThreadView::pane_point(area, Position::new(x, y), clamp);
        assert_eq!(at(1, 2, false), Some((0, 0)));
        assert_eq!(at(5, 4, false), Some((4, 2)));
        assert_eq!(at(0, 2, false), None);
        assert_eq!(at(90, 30, true), Some((89, 8)));
        assert_eq!(at(0, 0, true), Some((0, 0)));
    }

    #[test]
    fn drawing_into_a_tiny_area_does_not_fail() {
        let parser = vt100::Parser::new(5, 20, 0);
        for (width, height) in [(0, 0), (1, 1), (3, 2)] {
            let area = Rect::new(0, 0, width, height);
            let mut buffer = Buffer::empty(area);
            ThreadView {
                shown: Some(AGENTS[2]),
                hints: &[("q", "quit")],
                waiting: None,
                panel: Panel::default(),
            }
            .render(Some(parser.screen()), area, &mut buffer);
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
    fn the_agent_gets_what_the_tab_bar_the_borders_the_panel_or_the_status_line_and_the_hints_leave()
     {
        assert_eq!(ThreadView::agent_size(40, 120), (36, 82));
        assert_eq!(ThreadView::agent_size(40, 99), (35, 97));
        assert_eq!(ThreadView::agent_size(3, 10), (2, 8));
    }

    fn drawn_screen(parser: &vt100::Parser, area: Rect) -> Buffer {
        let mut buffer = Buffer::empty(area);
        draw_screen(parser.screen(), area, &mut buffer);
        buffer
    }

    fn screen_row(buffer: &Buffer, y: u16) -> String {
        (0..buffer.area.width)
            .map(|x| buffer[(x, y)].symbol())
            .collect()
    }

    #[test]
    fn the_agents_screen_is_drawn_with_its_colours() {
        let area = Rect::new(0, 0, 10, 2);
        let mut parser = vt100::Parser::new(area.height, area.width, 0);
        parser.process(b"hello\r\n\x1b[1;31mred\x1b[0m \x1b[38;2;1;2;3mrgb\x1b[0m");
        let buffer = drawn_screen(&parser, area);
        assert_eq!(screen_row(&buffer, 0), "hello     ");
        assert_eq!(screen_row(&buffer, 1), "red rgb   ");
        let red = &buffer[(0, 1)];
        assert_eq!(red.fg, Color::Indexed(1));
        assert!(red.modifier.contains(Modifier::BOLD));
        assert_eq!(buffer[(4, 1)].fg, Color::Rgb(1, 2, 3));
    }

    #[test]
    fn wide_characters_take_two_cells_and_one_cut_at_the_edge_is_left_blank() {
        let area = Rect::new(0, 0, 6, 2);
        let mut parser = vt100::Parser::new(area.height, area.width, 0);
        parser.process("界a\r\n".as_bytes());
        let buffer = drawn_screen(&parser, area);
        assert_eq!(buffer[(0, 0)].symbol(), "界");
        assert_eq!(buffer[(2, 0)].symbol(), "a");
        let mut wider = vt100::Parser::new(area.height, area.width + 4, 0);
        wider.process("abcde界".as_bytes());
        assert_eq!(screen_row(&drawn_screen(&wider, area), 0), "abcde ");
    }

    #[test]
    fn a_screen_of_any_size_draws_into_an_area_of_any_size_without_panicking() {
        for (rows, columns) in [(2, 2), (4, 4)] {
            let mut parser = vt100::Parser::new(rows, columns, 0);
            parser.process(b"xxxx");
            for (width, height) in [(0, 0), (1, 1), (2, 3), (3, 5)] {
                drawn_screen(&parser, Rect::new(0, 0, width, height));
            }
        }
    }
}
