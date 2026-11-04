use gix::bstr::{
    BStr,
    BString,
    ByteSlice,
};

const CHERRY_PICKED: &[u8] = b"(cherry picked from commit ";
const SIGNED_OFF_BY: &[u8] = b"Signed-off-by";

pub(crate) fn appended_trailers(message: &BStr, trailers: &str) -> BString {
    let body = message.trim_end();
    let eol: &[u8] = if body.find(b"\r\n").is_some() {
        b"\r\n"
    } else {
        b"\n"
    };
    let block = last_paragraph(body).filter(|block| is_trailer_block(block));
    let mut out = BString::from(Vec::with_capacity(
        body.len() + trailers.len() * 2 + 2 * eol.len(),
    ));
    out.extend_from_slice(body);
    out.extend_from_slice(eol);
    if block.is_none() {
        out.extend_from_slice(eol);
    }
    for line in trailers.as_bytes().lines() {
        out.extend_from_slice(line);
        out.extend_from_slice(eol);
    }
    out
}

fn last_paragraph(body: &[u8]) -> Option<&[u8]> {
    let mut start = None;
    let mut offset = 0;
    for line in body.lines_with_terminator() {
        offset += line.len();
        if line.trim().is_empty() {
            start = Some(offset);
        }
    }
    start.and_then(|at| body.get(at..))
}

fn is_trailer_block(block: &[u8]) -> bool {
    let mut trailers = 0_usize;
    let mut others = 0_usize;
    let mut generated = false;
    let mut after_trailer = false;
    for line in block.lines() {
        if after_trailer
            && line
                .first()
                .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
        {
            continue;
        }
        after_trailer = false;
        if line.starts_with(CHERRY_PICKED) {
            trailers += 1;
            generated = true;
        } else if let Some(key) = trailer_key(line) {
            trailers += 1;
            after_trailer = true;
            generated |= key.eq_ignore_ascii_case(SIGNED_OFF_BY);
        } else {
            others += 1;
        }
    }
    trailers > 0 && (others == 0 || (generated && trailers.saturating_mul(3) >= others))
}

fn trailer_key(line: &[u8]) -> Option<&[u8]> {
    let colon = line.find_byte(b':')?;
    let key = line.get(..colon)?.trim_end();
    let valid = !key.is_empty()
        && key
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-');
    valid.then_some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailers_join_an_existing_block_or_start_one() {
        let trailers = "Thread: t\nAgent: alice.claude\n";
        let cases: [(&str, &str); 11] = [
            ("subject", "subject\n\n{}"),
            ("subject\n", "subject\n\n{}"),
            ("subject\n\nbody text\n\n", "subject\n\nbody text\n\n{}"),
            (
                "subject\n\nbody\n\nSigned-off-by: a <a@b>\n",
                "subject\n\nbody\n\nSigned-off-by: a <a@b>\n{}",
            ),
            ("subject\n\nThread: other\n", "subject\n\nThread: other\n{}"),
            ("Thread: t\n", "Thread: t\n\n{}"),
            (
                "s\n\nSigned-off-by: a <a@b>\n(cherry picked from commit abc)\n",
                "s\n\nSigned-off-by: a <a@b>\n(cherry picked from commit abc)\n{}",
            ),
            (
                "s\n\nCo-authored-by: a\n  folded <a@b>\nReviewed-by:b\n",
                "s\n\nCo-authored-by: a\n  folded <a@b>\nReviewed-by:b\n{}",
            ),
            (
                "s\n\nsome prose\nmore prose\nSigned-off-by: a <a@b>\n",
                "s\n\nsome prose\nmore prose\nSigned-off-by: a <a@b>\n{}",
            ),
            (
                "s\n\nNote: this is prose\nthat goes on\n",
                "s\n\nNote: this is prose\nthat goes on\n\n{}",
            ),
            (
                "s\r\n\r\nSigned-off-by: a <a@b>\r\n",
                "s\r\n\r\nSigned-off-by: a <a@b>\r\nThread: t\r\nAgent: alice.claude\r\n",
            ),
        ];
        for (message, expected) in cases {
            assert_eq!(
                appended_trailers(message.into(), trailers),
                BString::from(expected.replace("{}", trailers)),
                "{message:?}"
            );
        }
    }
}
