//! The terminal side of mahi's in-session UI: the key that opens the palette, and finding it in
//! what the user types.

mod key;
mod scan;

pub use key::{
    PaletteKey,
    PaletteKeyError,
};
pub use scan::{
    KeyScanner,
    Segment,
    Segments,
};
