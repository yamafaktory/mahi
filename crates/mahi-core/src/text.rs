/// Returns whether `c` is invisible when shown: a zero-width or filler character, a
/// text-direction mark or a tag, which could hide or reorder what a reader sees.
#[must_use]
pub fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{180B}'..='\u{180F}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{3164}'
            | '\u{FFA0}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_that_hide_or_reorder_text_are_invisible() {
        for c in [
            '\u{200B}',
            '\u{202E}',
            '\u{2066}',
            '\u{FEFF}',
            '\u{E0041}',
            '\u{00AD}',
        ] {
            assert!(is_invisible(c), "{c:?}");
        }
        for c in ['a', ' ', 'é', '\u{4E2D}', '\u{1F600}'] {
            assert!(!is_invisible(c), "{c:?}");
        }
    }
}
