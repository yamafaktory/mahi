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
const TAB_ROWS: u16 = 1;
const HINT_ROWS: u16 = 1;
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
    /// A teammate's agent whose host is connected; its frames say nothing of its turns.
    Live,
    /// A teammate's agent whose host is not connected.
    Offline,
    /// The command that ran it failed; its last screen stays until the user closes it.
    Failed,
}

impl AgentState {
    fn mark(self) -> Span<'static> {
        match self {
            Self::Working => Span::styled("● working", Style::new().fg(Theme::ACCENT)),
            Self::Done => Span::styled("✓ done", Style::new().fg(Theme::OK)),
            Self::AsksYou => Span::styled("! asks you", Theme::code()),
            Self::Live => Span::styled("◉ live", Style::new().fg(Theme::ACCENT)),
            Self::Offline => Span::styled("○ offline", Theme::muted()),
            Self::Failed => Span::styled("✗ failed", Style::new().fg(Theme::ERROR)),
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

/// What a click on the row of tabs is on.
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

/// The workspace's row of tabs: the thread list, each open thread, and `+` to open another.
#[derive(Debug, Clone, Copy)]
pub struct TabBar<'a> {
    /// The open threads' tabs.
    pub tabs: &'a [WorkspaceTab<'a>],
    /// The selected tab: 0 for the thread list, `n` for `tabs[n - 1]`.
    pub selected: usize,
}

impl<'a> TabBar<'a> {
    /// Splits a terminal's `area` into the row of tabs and what lies below it.
    #[must_use]
    pub fn split(area: Rect) -> (Rect, Rect) {
        let [tabs, body] =
            Layout::vertical([Constraint::Length(TAB_ROWS), Constraint::Fill(1)]).areas(area);
        (tabs, body)
    }

    /// Draws the row of tabs into `area`.
    pub fn render(&self, area: Rect, buffer: &mut Buffer) {
        let spans: Vec<Span<'a>> = self.spans().map(|(span, _)| span).collect();
        Line::from(spans).render(area, buffer);
    }

    /// Returns what is drawn at `column` of the row of tabs, counted from the row's left.
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
        let tabs =
            self.tabs.iter().enumerate().flat_map(move |(index, tab)| {
                let mark = if tab.asks { " !" } else { "" };
                std::iter::once((Span::styled("│", Theme::muted()), TabHit::Nothing))
                    .chain(self.tab(index + 1, shown(tab.title), mark))
            });
        threads.into_iter().chain(tabs).chain([
            (Span::styled("│", Theme::muted()), TabHit::Nothing),
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

/// A thread's tab: one of its agents at full size, the list of its agents, the teammates'
/// prompts waiting, and the keys that reach mahi.
#[derive(Debug, Clone, Copy)]
pub struct ThreadView<'a> {
    /// The thread's agents: the user's own first, then each teammate's.
    pub agents: &'a [WorkspaceAgent<'a>],
    /// The agent shown at full size, as an index in `agents`.
    pub selected: usize,
    /// How many of the teammates' prompts wait for the user.
    pub prompts: usize,
    /// Where the list goes.
    pub list: ListPlace,
    /// The keys that reach mahi, and what they do.
    pub hints: &'a [(&'a str, &'a str)],
}

impl ThreadView<'_> {
    /// Returns the rows and columns of an agent's terminal in a thread's tab on a terminal of
    /// `rows` and `columns`, at least two of each, with the list `list`.
    #[must_use]
    pub fn agent_size(rows: u16, columns: u16, list: ListPlace) -> (u16, u16) {
        let beside = if list == ListPlace::Beside {
            LIST_COLUMNS
        } else {
            0
        };
        (
            rows.saturating_sub(TAB_ROWS + HINT_ROWS + BORDER)
                .max(SMALLEST),
            columns.saturating_sub(BORDER + beside).max(SMALLEST),
        )
    }

    /// Draws the tab into `area`, below the row of tabs, with the selected agent's `screen`
    /// in its pane; returns where the agent's cursor is when it shows it and nothing lies over
    /// it.
    pub fn render(
        &self,
        screen: Option<&vt100::Screen>,
        area: Rect,
        buffer: &mut Buffer,
    ) -> Option<Position> {
        let [body, footer] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(HINT_ROWS)]).areas(area);
        let (pane, list) = self.areas(body);
        let title = self
            .agents
            .get(self.selected)
            .map_or_else(String::new, |agent| format!(" {} ", label(agent)));
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(Theme::ACCENT))
            .title(Span::styled(title, Theme::title()));
        let inner = block.inner(pane);
        block.render(pane, buffer);
        if let Some(screen) = screen {
            draw_screen(screen, inner, buffer, false);
        }
        if let Some(list) = list {
            Clear.render(list, buffer);
            self.render_list(list, buffer);
        }
        Line::from(key_hints(self.hints)).render(footer, buffer);
        let screen = screen?;
        let (row, column) = screen.cursor_position();
        let cursor = Position::new(inner.x.saturating_add(column), inner.y.saturating_add(row));
        let covered = list.is_some_and(|list| list.contains(cursor));
        (!screen.hide_cursor() && inner.contains(cursor) && !covered).then_some(cursor)
    }

    /// Returns what of the list is at `position`, when the tab is drawn in `area`, below the
    /// row of tabs: nothing when the list is not there, so the click is the agent's.
    #[must_use]
    pub fn list_at(&self, area: Rect, position: Position) -> Option<ListHit> {
        let [body, _] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(HINT_ROWS)]).areas(area);
        let (_, list) = self.areas(body);
        let list = list?;
        if !list.contains(position) {
            return None;
        }
        let inner = Block::bordered().inner(list);
        let agent = inner
            .contains(position)
            .then(|| {
                self.lines()
                    .nth(usize::from(position.y - inner.y))
                    .flatten()
            })
            .flatten();
        Some(agent.map_or(ListHit::Elsewhere, ListHit::Agent))
    }

    /// Returns the cell of the agent's screen at `position`, when the tab is drawn in `area`,
    /// below the row of tabs; a position past the pane gives its nearest cell when `clamp`,
    /// as a drag that leaves it does, and nothing otherwise.
    #[must_use]
    pub fn pane_point(&self, area: Rect, position: Position, clamp: bool) -> Option<(u16, u16)> {
        let [body, _] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(HINT_ROWS)]).areas(area);
        let (pane, _) = self.areas(body);
        let inner = Block::bordered().inner(pane);
        if inner.is_empty() || (!clamp && !inner.contains(position)) {
            return None;
        }
        let column = position.x.clamp(inner.x, inner.right() - 1) - inner.x;
        let row = position.y.clamp(inner.y, inner.bottom() - 1) - inner.y;
        Some((column, row))
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
            ListPlace::Hidden => (body, None),
        }
    }

    /// Returns, for each line of the list's agents, the agent it shows, or nothing for the
    /// line naming whose agents follow.
    fn lines(&self) -> impl Iterator<Item = Option<usize>> + '_ {
        self.agents.iter().enumerate().flat_map(|(index, agent)| {
            let starts_group = index == 0
                || self
                    .agents
                    .get(index - 1)
                    .is_some_and(|before| before.owner != agent.owner);
            starts_group
                .then_some(None)
                .into_iter()
                .chain(std::iter::once(Some(index)))
        })
    }

    fn render_list(&self, area: Rect, buffer: &mut Buffer) {
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(Theme::ACCENT))
            .title(Span::styled(" Agents ", Theme::title()));
        let inner = block.inner(area);
        block.render(area, buffer);
        let mut lines = Vec::with_capacity(self.agents.len() * 2 + 2);
        let mut group = None;
        for (index, agent) in self.agents.iter().enumerate() {
            if index == 0 || agent.owner != group {
                group = agent.owner;
                lines.push(Line::from(Span::styled(
                    agent.owner.map_or("yours".into(), shown),
                    Theme::muted(),
                )));
            }
            let style = if index == self.selected {
                Theme::selected()
            } else {
                Style::new()
            };
            lines.push(Line::from(vec![
                Span::styled(format!(" {} ", shown(agent.name)), style),
                agent.state.mark(),
            ]));
        }
        if self.prompts > 0 {
            lines.push(Line::default());
            let plural = if self.prompts == 1 { "" } else { "s" };
            lines.push(Line::from(Span::styled(
                format!("✉ {} prompt{plural} waiting", self.prompts),
                Theme::code(),
            )));
        }
        for (line, row) in lines.into_iter().zip(inner.rows()) {
            line.render(row, buffer);
        }
    }
}

fn label(agent: &WorkspaceAgent<'_>) -> String {
    match agent.owner {
        Some(owner) => format!("{}.{} (read-only)", shown(owner), shown(agent.name)),
        None => shown(agent.name).into_owned(),
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
        TabBar {
            tabs: &tabs,
            selected: 1,
        }
        .render(area, &mut buffer);
        let row = rows(&buffer).remove(0);
        assert!(row.starts_with(" ⌂ threads │ 7f3a │ 9a48 ! │ + "), "{row}");
        assert_eq!(buffer[(13, 0)].style().bg, Theme::selected().bg);
        assert_ne!(buffer[(1, 0)].style().bg, Theme::selected().bg);
    }

    #[test]
    fn a_thread_shows_its_agents_grouped_by_owner_beside_the_selected_one() {
        let mut parser = vt100::Parser::new(5, 20, 0);
        parser.process(b"hello from claude");
        let area = Rect::new(0, 0, 100, 12);
        let mut buffer = Buffer::empty(area);
        let cursor = ThreadView {
            agents: &AGENTS,
            selected: 0,
            prompts: 2,
            list: ListPlace::Beside,
            hints: &[("ctrl-space", "workspace")],
        }
        .render(Some(parser.screen()), area, &mut buffer);
        let rows = rows(&buffer);
        assert!(rows[1].contains("hello from claude"), "{rows:#?}");
        let list: Vec<String> = rows
            .iter()
            .map(|row| row.chars().skip(76).collect())
            .collect();
        let shown = list.join("\n");
        for expected in [
            "yours",
            " claude ● working",
            "alice",
            " claude ✓ done",
            "bob",
            " codex ○ offline",
            "✉ 2 prompts waiting",
        ] {
            assert!(shown.contains(expected), "{expected} missing:\n{shown}");
        }
        assert!(rows[11].contains("ctrl-space workspace"), "{rows:#?}");
        assert_eq!(cursor, Some(Position::new(18, 1)));
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
            prompts: 0,
            list: ListPlace::Over,
            hints: &[],
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
            prompts: 0,
            list: ListPlace::Hidden,
            hints: &[],
        }
        .render(Some(parser.screen()), area, &mut buffer);
        assert_eq!(cursor, Some(Position::new(71, 1)));
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
            let (_, body) = TabBar::split(screen);
            let mut buffer = Buffer::empty(screen);
            ThreadView {
                agents: &AGENTS,
                selected: 0,
                prompts: 0,
                list,
                hints: &[],
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
        assert_eq!(bar.tab_at(0), TabHit::Tab(0));
        assert_eq!(bar.tab_at(10), TabHit::Tab(0));
        assert_eq!(bar.tab_at(11), TabHit::Nothing);
        assert_eq!(bar.tab_at(12), TabHit::Tab(1));
        assert_eq!(bar.tab_at(19), TabHit::Tab(2));
        assert_eq!(bar.tab_at(27), TabHit::Nothing);
        assert_eq!(bar.tab_at(28), TabHit::New);
        assert_eq!(bar.tab_at(40), TabHit::Nothing);
        let view = ThreadView {
            agents: &AGENTS,
            selected: 0,
            prompts: 0,
            list: ListPlace::Beside,
            hints: &[],
        };
        let area = Rect::new(0, 1, 100, 12);
        let at = |view: &ThreadView<'_>, x, y| view.list_at(area, Position::new(x, y));
        assert_eq!(at(&view, 80, 1), Some(ListHit::Elsewhere));
        assert_eq!(at(&view, 80, 2), Some(ListHit::Elsewhere));
        assert_eq!(at(&view, 80, 3), Some(ListHit::Agent(0)));
        assert_eq!(at(&view, 80, 5), Some(ListHit::Agent(1)));
        assert_eq!(at(&view, 80, 7), Some(ListHit::Agent(2)));
        assert_eq!(at(&view, 80, 8), Some(ListHit::Elsewhere));
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
            prompts: 0,
            list: ListPlace::Beside,
            hints: &[],
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
                    prompts: 1,
                    list,
                    hints: &[("q", "quit")],
                }
                .render(Some(parser.screen()), area, &mut buffer);
            }
            TabBar {
                tabs: &[],
                selected: 0,
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
