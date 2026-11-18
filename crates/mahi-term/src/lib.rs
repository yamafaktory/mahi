//! The terminal side of mahi's in-session UI: the key that opens the palette and finding it in
//! what the user types, the keys the open palette reads, where mahi may draw between the
//! agent's escape sequences, and drawing the palette.

mod agent_screen;
mod background;
mod dialog;
mod home;
mod input;
mod key;
mod mouse;
mod notify;
mod output;
mod report;
mod scan;
mod screen;
mod sequence;
mod view;
mod workspace;

pub use agent_screen::{
    AgentScreen,
    new_screen,
    resize_screen,
};
pub use background::{
    BACKGROUND_QUERY,
    Background,
    BackgroundReply,
    ReplySplit,
};
pub use dialog::{
    Answer,
    Dialog,
    MenuItem,
    Palette,
    Preselected,
    Theme,
    key_hints,
};
pub use home::{
    HOME_COMMANDS,
    Home,
    HomeAction,
    HomeCommand,
    HomeRow,
    HomeView,
    ThreadChoice,
};
pub use input::{
    PaletteInput,
    PaletteKeys,
};
pub use key::{
    PaletteKey,
    PaletteKeyError,
};
pub use mouse::{
    MouseEncoding,
    MouseEvent,
    MouseMode,
    Typed,
    agent_mouse,
    cut_report,
    split_mouse,
};
pub use notify::{
    Notice,
    Notifier,
    TerminalHints,
};
pub use output::OutputTracker;
pub use report::{
    Report,
    ReportReader,
};
pub use scan::{
    KeyScanner,
    Segment,
    Segments,
};
pub use screen::AnsiBackend;
pub use sequence::{
    Csi,
    PASTE_END,
    PASTE_START,
    PasteEnd,
    is_terminal_answer,
    starts_answer,
    string_end,
    terminal_answer_at,
};
pub use view::{
    Drawn,
    PaletteItem,
    PaletteView,
    Preview,
};
pub use workspace::{
    AgentState,
    Header,
    MergedFiles,
    OwnAgent,
    Panel,
    PanelChanges,
    StatusAgent,
    StatusConflicts,
    StatusLanding,
    StatusLine,
    TabBar,
    TabHit,
    TeammateState,
    ThreadView,
    TopBar,
    WorkspaceAgent,
    WorkspaceTab,
};
