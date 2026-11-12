/// How many lines one file's change between two trees adds and removes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineCounts {
    /// The lines added and removed, both zero when the file is the same.
    Counted {
        /// The lines added.
        added: u32,
        /// The lines removed.
        removed: u32,
    },
    /// The file is not text in one of the trees.
    Binary,
    /// The file is larger than the diff reads in one of the trees.
    TooLarge,
    /// The path names something other than a file, or is not a valid path.
    NotAFile,
}
