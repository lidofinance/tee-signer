//! A cursor over untrusted bytes. Every read is checked: a short buffer gives
//! `None`, never a panic.

pub(crate) struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { rest: buf }
    }

    /// Octets not read yet.
    pub(crate) fn remaining(&self) -> usize {
        self.rest.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// The octets not read yet, without moving the cursor.
    pub(crate) fn rest(&self) -> &'a [u8] {
        self.rest
    }

    /// The next `n` octets, or `None` if fewer are left.
    pub(crate) fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.rest.split_at_checked(n)?;
        self.rest = tail;
        Some(head)
    }

    /// The next `N` octets as an array, or `None` if fewer are left.
    pub(crate) fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, tail) = self.rest.split_first_chunk::<N>()?;
        self.rest = tail;
        Some(*head)
    }

    /// A 16-bit unsigned integer in network byte order.
    pub(crate) fn u16(&mut self) -> Option<u16> {
        self.array::<2>().map(u16::from_be_bytes)
    }
}

/// `n` rounded up to a multiple of 4. NTP extension fields and the parts of
/// the NTS authenticator are padded to 4-octet words (RFC 7822 section 7.5,
/// RFC 8915 section 5.6).
pub(crate) fn pad4(n: usize) -> Option<usize> {
    n.checked_next_multiple_of(4)
}

pub(crate) fn all_zero(b: &[u8]) -> bool {
    b.iter().all(|&x| x == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_stop_at_the_end() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.u16(), Some(0x0102));
        assert_eq!(r.u16(), None);
        assert_eq!(r.remaining(), 1);
        assert_eq!(r.take(2), None);
        assert_eq!(r.take(1), Some(&[3u8][..]));
        assert!(r.is_empty());
        assert_eq!(r.take(0), Some(&[][..]));
        assert_eq!(r.array::<1>(), None);
    }

    #[test]
    fn pad4_rounds_up() {
        assert_eq!(pad4(0), Some(0));
        assert_eq!(pad4(1), Some(4));
        assert_eq!(pad4(16), Some(16));
        assert_eq!(pad4(65535), Some(65536));
        assert_eq!(pad4(usize::MAX), None);
    }
}
