//! The terminal side of mahi's in-session UI: the key that opens the palette and finding it in
//! what the user types, the keys the open palette reads, where mahi may draw between the
//! agent's escape sequences, and drawing the palette.

mod input;
mod key;
mod notify;
mod output;
mod scan;
mod view;

pub use input::{
    PaletteInput,
    PaletteKeys,
};
pub use key::{
    PaletteKey,
    PaletteKeyError,
};
pub use notify::{
    Notice,
    Notifier,
    TerminalHints,
};
pub use output::OutputTracker;
pub use scan::{
    KeyScanner,
    Segment,
    Segments,
};
pub use view::{
    Drawn,
    PaletteItem,
    PaletteView,
    Preview,
};
