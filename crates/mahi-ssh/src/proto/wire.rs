use thiserror::Error;

pub(crate) const MAX_NAME_BYTES: usize = 64;
pub(crate) const MAX_NAME_LIST_BYTES: usize = 64 << 10;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum WireError {
    #[error("a message ends early")]
    Truncated,
    #[error("a message has bytes after its last field")]
    Trailing,
    #[error("a name list is malformed or too long")]
    NameList,
    #[error("a field is too long")]
    TooLong,
    #[error("a message is empty")]
    Empty,
    #[error("a message cannot be encoded as given")]
    Unencodable,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub(crate) fn take(&mut self, count: usize) -> Result<&'a [u8], WireError> {
        let (taken, rest) = self
            .bytes
            .split_at_checked(count)
            .ok_or(WireError::Truncated)?;
        self.bytes = rest;
        Ok(taken)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let mut array = [0; N];
        array.copy_from_slice(self.take(N)?);
        Ok(array)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, WireError> {
        Ok(u8::from_be_bytes(self.array()?))
    }

    pub(crate) fn bool(&mut self) -> Result<bool, WireError> {
        Ok(self.u8()? != 0)
    }

    pub(crate) fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(crate) fn string(&mut self) -> Result<&'a [u8], WireError> {
        let length = usize::try_from(self.u32()?).map_err(|_| WireError::TooLong)?;
        self.take(length)
    }

    pub(crate) fn name_list(&mut self) -> Result<NameList<'a>, WireError> {
        NameList::parse(self.string()?)
    }

    pub(crate) fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.bytes)
    }

    pub(crate) fn finish(&self) -> Result<(), WireError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(WireError::Trailing)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NameList<'a>(&'a str);

impl<'a> NameList<'a> {
    pub(crate) fn parse(bytes: &'a [u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_NAME_LIST_BYTES {
            return Err(WireError::NameList);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| WireError::NameList)?;
        if !text.is_empty() && !text.split(',').all(valid_name) {
            return Err(WireError::NameList);
        }
        Ok(Self(text))
    }

    pub(crate) fn names(self) -> impl Iterator<Item = &'a str> {
        self.0.split(',').filter(|name| !name.is_empty())
    }

    pub(crate) fn contains(self, wanted: &str) -> bool {
        self.names().any(|name| name == wanted)
    }

    pub(crate) fn as_str(self) -> &'a str {
        self.0
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b',')
}

pub(crate) fn put_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

pub(crate) fn put_bool(out: &mut Vec<u8>, value: bool) {
    out.push(u8::from(value));
}

pub(crate) fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn put_string(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), WireError> {
    let length = u32::try_from(bytes.len()).map_err(|_| WireError::TooLong)?;
    put_u32(out, length);
    out.extend_from_slice(bytes);
    Ok(())
}

pub(crate) fn put_mpint(out: &mut Vec<u8>, magnitude: &[u8]) -> Result<(), WireError> {
    let first = magnitude
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(magnitude.len());
    let digits = magnitude.get(first..).unwrap_or_default();
    let sign_pad = digits.first().is_some_and(|&byte| byte & 0x80 != 0);
    let length =
        u32::try_from(digits.len() + usize::from(sign_pad)).map_err(|_| WireError::TooLong)?;
    put_u32(out, length);
    if sign_pad {
        out.push(0);
    }
    out.extend_from_slice(digits);
    Ok(())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn strings_and_integers_are_read_in_network_order() {
        let bytes = [0, 0, 0, 3, b'a', b'b', b'c', 0xde, 0xad, 0xbe, 0xef, 2];
        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.string(), Ok(&b"abc"[..]));
        assert_eq!(reader.u32(), Ok(0xdead_beef));
        assert_eq!(reader.bool(), Ok(true));
        assert_eq!(reader.finish(), Ok(()));
    }

    #[test]
    fn a_string_longer_than_what_is_left_is_truncated() {
        let mut reader = Reader::new(&[0xff, 0xff, 0xff, 0xff, 1, 2]);
        assert_eq!(reader.string(), Err(WireError::Truncated));
        assert_eq!(Reader::new(&[0, 0, 1]).u32(), Err(WireError::Truncated));
    }

    #[test]
    fn leftover_bytes_are_refused() {
        let mut reader = Reader::new(&[1, 2]);
        reader.u8().unwrap();
        assert_eq!(reader.finish(), Err(WireError::Trailing));
    }

    #[test]
    fn name_lists_refuse_empty_names_spaces_controls_and_long_names() {
        assert!(NameList::parse(b"").is_ok());
        assert_eq!(
            NameList::parse(b"a,b@openssh.com")
                .unwrap()
                .names()
                .collect::<Vec<_>>(),
            ["a", "b@openssh.com"]
        );
        for bad in [
            &b"a,,b"[..],
            b",a",
            b"a,",
            b"a b",
            b"a\x00",
            b"\xff",
            "é".as_bytes(),
        ] {
            assert_eq!(NameList::parse(bad), Err(WireError::NameList), "{bad:?}");
        }
        assert!(NameList::parse(&[b'a'; MAX_NAME_BYTES]).is_ok());
        assert!(NameList::parse(&[b'a'; MAX_NAME_BYTES + 1]).is_err());
    }

    #[test]
    fn a_name_list_may_fill_64_kib_but_not_more() {
        let of_length = |length: usize| {
            let mut list = "abcdefg,".repeat(length / 8);
            list.truncate(length.saturating_sub(10) / 8 * 8);
            list.push_str(&"z".repeat(length - list.len()));
            list
        };
        let full = of_length(MAX_NAME_LIST_BYTES);
        assert_eq!(full.len(), MAX_NAME_LIST_BYTES);
        assert!(NameList::parse(full.as_bytes()).is_ok());
        let over = of_length(MAX_NAME_LIST_BYTES + 1);
        assert_eq!(over.len(), MAX_NAME_LIST_BYTES + 1);
        assert_eq!(NameList::parse(over.as_bytes()), Err(WireError::NameList));
    }

    #[test]
    fn mpints_are_minimal_and_positive_as_rfc_4251_shows() {
        let encode = |magnitude: &[u8]| {
            let mut out = Vec::new();
            put_mpint(&mut out, magnitude).unwrap();
            out
        };
        assert_eq!(encode(&[]), [0, 0, 0, 0]);
        assert_eq!(encode(&[0, 0]), [0, 0, 0, 0]);
        assert_eq!(
            encode(&[0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7]),
            [0, 0, 0, 8, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7]
        );
        assert_eq!(encode(&[0x80]), [0, 0, 0, 2, 0, 0x80]);
        assert_eq!(encode(&[0, 0, 0x7f]), [0, 0, 0, 1, 0x7f]);
    }

    proptest! {
        #[test]
        fn reading_never_panics_on_any_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let mut reader = Reader::new(&bytes);
            let _ = reader.u8();
            let _ = reader.string();
            let _ = reader.name_list();
            let _ = reader.u32();
            let _ = reader.finish();
        }

        #[test]
        fn a_written_string_reads_back(bytes in proptest::collection::vec(any::<u8>(), 0..300), tail in any::<u32>()) {
            let mut out = Vec::new();
            put_string(&mut out, &bytes).unwrap();
            put_u32(&mut out, tail);
            let mut reader = Reader::new(&out);
            prop_assert_eq!(reader.string().unwrap(), &bytes[..]);
            prop_assert_eq!(reader.u32().unwrap(), tail);
            prop_assert!(reader.finish().is_ok());
        }

        #[test]
        fn a_written_mpint_has_no_redundant_leading_byte(magnitude in proptest::collection::vec(any::<u8>(), 0..40)) {
            let mut out = Vec::new();
            put_mpint(&mut out, &magnitude).unwrap();
            let mut reader = Reader::new(&out);
            let digits = reader.string().unwrap();
            prop_assert!(reader.finish().is_ok());
            match digits {
                [] => prop_assert!(magnitude.iter().all(|&b| b == 0)),
                [0, next, ..] => prop_assert!(next & 0x80 != 0),
                [0] => prop_assert!(false, "a lone zero byte"),
                [first, ..] => prop_assert!(first & 0x80 == 0),
            }
            let stripped: Vec<u8> = digits.iter().copied().skip_while(|&b| b == 0).collect();
            let expected: Vec<u8> = magnitude.iter().copied().skip_while(|&b| b == 0).collect();
            prop_assert_eq!(stripped, expected);
        }

        #[test]
        fn valid_name_lists_keep_their_names(names in proptest::collection::vec("[!-+--~]{1,64}", 0..8)) {
            let joined = names.join(",");
            let list = NameList::parse(joined.as_bytes()).unwrap();
            prop_assert_eq!(list.names().collect::<Vec<_>>(), names.iter().map(String::as_str).collect::<Vec<_>>());
        }
    }
}
