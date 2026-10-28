//! NTP time formats (RFC 5905 section 6) and era-safe conversion to and from
//! Unix time. Nothing here reads a clock: the caller passes the times in.
//!
//! An NTP timestamp on the wire holds 32 bits of seconds and 32 bits of
//! fraction. The seconds wrap every 2^32 seconds (about 136 years), so the
//! wire value does not say which era it is in; era 0 ends on
//! 2036-02-07 06:28:16 UTC. RFC 5905 section 6: the era is found from a
//! nearby time the receiver already knows, and the difference of two
//! timestamps is right as long as they are less than about 68 years apart.
//! `to_unix_nanos` takes such a nearby time (the pivot) for that reason.

/// Seconds from the NTP prime epoch (1900-01-01 00:00 UTC, era 0) to the Unix
/// epoch 1970-01-01 (RFC 5905 section 6, figure 4: 2,208,988,800).
pub const UNIX_EPOCH_NTP_SECONDS: u64 = 2_208_988_800;

const NANOS_PER_SEC: i128 = 1_000_000_000;
/// Units of the fraction field per second: the fraction is in 2^-32 seconds.
const UNITS_PER_SEC: i128 = 1 << 32;
const UNIX_EPOCH_NTP_NANOS: i128 = UNIX_EPOCH_NTP_SECONDS as i128 * NANOS_PER_SEC;

/// An NTP timestamp (RFC 5905 section 6): seconds since the start of its era
/// in the high 32 bits, the fraction of a second (2^-32 s units) in the low 32.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NtpTimestamp(u64);

impl NtpTimestamp {
    /// From the 64-bit wire value.
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// The 64-bit wire value.
    pub const fn to_bits(self) -> u64 {
        self.0
    }

    /// From the 8 wire octets (network byte order).
    pub const fn from_be_bytes(b: [u8; 8]) -> Self {
        Self(u64::from_be_bytes(b))
    }

    /// The 8 wire octets (network byte order).
    pub const fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// From nanoseconds since the Unix epoch. The era is dropped, as on the
    /// wire. The fraction is rounded up, so `to_unix_nanos` with any pivot
    /// within about 68 years gives back the same nanoseconds (one unit,
    /// 2^-32 s, is shorter than a nanosecond).
    pub fn from_unix_nanos(unix_nanos: i64) -> Self {
        let ntp_nanos = i128::from(unix_nanos) + UNIX_EPOCH_NTP_NANOS;
        let units = div_ceil(ntp_nanos * UNITS_PER_SEC, NANOS_PER_SEC);
        // The low 64 bits are the wire value: seconds modulo 2^32 and the fraction.
        Self(units as u64)
    }

    /// Nanoseconds since the Unix epoch, rounded down. The era is the one
    /// that puts the result within 2^31 seconds (about 68 years) of
    /// `pivot_unix_nanos`, a time the caller already trusts to that degree
    /// (RFC 5905 section 6). `None` if the result does not fit in an `i64`.
    pub fn to_unix_nanos(self, pivot_unix_nanos: i64) -> Option<i64> {
        let pivot_ntp_nanos = i128::from(pivot_unix_nanos) + UNIX_EPOCH_NTP_NANOS;
        let pivot_units = (pivot_ntp_nanos * UNITS_PER_SEC).div_euclid(NANOS_PER_SEC);
        // The wrapping difference to the pivot's wire value is the signed
        // distance to the nearest timestamp with these low 64 bits.
        let delta = self.0.wrapping_sub(pivot_units as u64) as i64;
        let units = pivot_units + i128::from(delta);
        let ntp_nanos = (units * NANOS_PER_SEC).div_euclid(UNITS_PER_SEC);
        i64::try_from(ntp_nanos - UNIX_EPOCH_NTP_NANOS).ok()
    }

    /// `self - earlier` in 2^-32 s units, modulo 2^64 and read as signed. It
    /// is right across an era boundary when the two are less than 2^31
    /// seconds apart (RFC 5905 section 6).
    pub const fn wrapping_diff(self, earlier: Self) -> NtpDuration {
        NtpDuration(self.0.wrapping_sub(earlier.0) as i64)
    }
}

/// A signed difference of two NTP timestamps, in 2^-32 s units.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NtpDuration(i64);

impl NtpDuration {
    /// From a count of 2^-32 s units.
    pub const fn from_bits(units: i64) -> Self {
        Self(units)
    }

    /// The count of 2^-32 s units.
    pub const fn to_bits(self) -> i64 {
        self.0
    }

    /// Nanoseconds, rounded toward minus infinity. Always fits: 2^63 units
    /// are about 2.1 * 10^18 ns.
    pub fn to_nanos(self) -> i64 {
        let n = (i128::from(self.0) * NANOS_PER_SEC).div_euclid(UNITS_PER_SEC);
        i64::try_from(n).unwrap_or(if n < 0 { i64::MIN } else { i64::MAX })
    }
}

/// NTP short format (RFC 5905 section 6): 16 bits of seconds, 16 bits of
/// fraction. Root delay and root dispersion use it (RFC 5905 section 7.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NtpShort(u32);

impl NtpShort {
    /// From the 32-bit wire value.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// The 32-bit wire value.
    pub const fn to_bits(self) -> u32 {
        self.0
    }

    /// Nanoseconds, rounded down. At most 65536 s, so it fits.
    pub const fn to_nanos(self) -> u64 {
        (self.0 as u64 * 1_000_000_000) >> 16
    }
}

/// `n / d` rounded toward plus infinity, for `d > 0`.
fn div_ceil(n: i128, d: i128) -> i128 {
    -((-n).div_euclid(d))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: i64 = 1_000_000_000;
    /// The first second of era 1: 2036-02-07 06:28:16 UTC.
    const ERA1_UNIX: i64 = (1 << 32) - UNIX_EPOCH_NTP_SECONDS as i64;

    #[test]
    fn unix_epoch_is_2208988800() {
        let t = NtpTimestamp::from_unix_nanos(0);
        assert_eq!(t.to_bits(), UNIX_EPOCH_NTP_SECONDS << 32);
        assert_eq!(t.to_unix_nanos(0), Some(0));
    }

    #[test]
    fn half_a_second_is_half_the_fraction() {
        let t = NtpTimestamp::from_unix_nanos(SEC / 2);
        assert_eq!(t.to_bits(), (UNIX_EPOCH_NTP_SECONDS << 32) | 0x8000_0000);
        assert_eq!(t.to_be_bytes(), [0x83, 0xaa, 0x7e, 0x80, 0x80, 0, 0, 0]);
        assert_eq!(NtpTimestamp::from_be_bytes(t.to_be_bytes()), t);
    }

    #[test]
    fn era_boundary_2036() {
        // One second after the wrap the wire seconds are 1.
        let t = NtpTimestamp::from_unix_nanos((ERA1_UNIX + 1) * SEC);
        assert_eq!(t.to_bits(), 1 << 32);
        // A pivot in 2026 or in 2100 puts it in era 1.
        assert_eq!(t.to_unix_nanos(1_790_000_000 * SEC), Some((ERA1_UNIX + 1) * SEC));
        assert_eq!(t.to_unix_nanos(4_102_444_800 * SEC), Some((ERA1_UNIX + 1) * SEC));
        // The last second of era 0, read with a pivot in era 1.
        let u = NtpTimestamp::from_unix_nanos((ERA1_UNIX - 1) * SEC);
        assert_eq!(u.to_bits(), 0xffff_ffff_0000_0000);
        assert_eq!(u.to_unix_nanos((ERA1_UNIX + 100) * SEC), Some((ERA1_UNIX - 1) * SEC));
        // Two seconds apart across the wrap.
        assert_eq!(t.wrapping_diff(u).to_bits(), 2 << 32);
        assert_eq!(u.wrapping_diff(t).to_nanos(), -2 * SEC);
    }

    #[test]
    fn round_trip_with_a_pivot_up_to_68_years_away() {
        // A fixed list plus a deterministic spread over 1900 to 2262.
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut values = [-2_208_988_800 * SEC, -1, 0, 1, 999_999_999, ERA1_UNIX * SEC, i64::MAX / 2].to_vec();
        for _ in 0..10_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            values.push((x >> 1) as i64 - (i64::MAX / 2));
        }
        let max_offset = 68 * 365 * 86_400 * SEC;
        for (i, &n) in values.iter().enumerate() {
            let t = NtpTimestamp::from_unix_nanos(n);
            let offset = (i as i64 * 7_777_777_777_777) % max_offset;
            for pivot in [n, n.saturating_sub(offset), n.saturating_add(offset)] {
                if (i128::from(pivot) - i128::from(n)).abs() < i128::from(max_offset) {
                    assert_eq!(t.to_unix_nanos(pivot), Some(n), "n {n} pivot {pivot}");
                }
            }
        }
    }

    #[test]
    fn far_from_the_pivot_gives_another_era() {
        let t = NtpTimestamp::from_unix_nanos(0);
        // 1970 read with a pivot in 2110 is 2106 (era 1), 136 years later.
        let got = t.to_unix_nanos(4_420_000_000 * SEC).unwrap();
        assert_eq!(got, (1i64 << 32) * SEC);
    }

    #[test]
    fn overflow_is_none_not_a_panic() {
        // About 50 years past 2262 and before 1677: outside i64 nanoseconds.
        assert_eq!(NtpTimestamp::from_bits(u64::MAX).to_unix_nanos(i64::MAX), None);
        assert_eq!(NtpTimestamp::from_bits(0).to_unix_nanos(i64::MIN), None);
        for bits in [0, 1, u64::MAX / 2, u64::MAX] {
            for pivot in [i64::MIN, -1, 0, i64::MAX] {
                let _ = NtpTimestamp::from_bits(bits).to_unix_nanos(pivot);
            }
        }
        let _ = NtpTimestamp::from_unix_nanos(i64::MIN);
        let _ = NtpTimestamp::from_unix_nanos(i64::MAX);
    }

    #[test]
    fn durations_and_short_format() {
        assert_eq!(NtpDuration::from_bits(1 << 32).to_nanos(), SEC);
        assert_eq!(NtpDuration::from_bits(-(1 << 31)).to_nanos(), -SEC / 2);
        assert_eq!(NtpDuration::from_bits(1).to_nanos(), 0);
        assert_eq!(NtpDuration::from_bits(-1).to_nanos(), -1);
        assert!(NtpDuration::from_bits(i64::MAX).to_nanos() > 0);
        assert!(NtpDuration::from_bits(i64::MIN).to_nanos() < 0);
        assert_eq!(NtpShort::from_bits(0x0001_8000).to_nanos(), 1_500_000_000);
        assert_eq!(NtpShort::from_bits(0x0000_0001).to_nanos(), 15_258);
        assert_eq!(NtpShort::from_bits(u32::MAX).to_nanos(), 65_535_999_984_741);
    }
}
