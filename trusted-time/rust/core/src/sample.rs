//! Offset, delay and error bound of one server response (RFC 5905 section 8),
//! and the checks of RFC 5905 that need no state from earlier responses.
//!
//! The caller passes T1 and T4 from its own monotonic clock, in nanoseconds
//! from any fixed start. The server's T2 and T3 are wall-clock times. So the
//! offset says how far real time is ahead of the caller's monotonic clock:
//! real Unix time at the local instant `x` is `x + offset`, give or take the
//! bound. The host clock is never read.

use core::fmt;

use crate::ntp::TimeSample;
use crate::time::NtpTimestamp;

/// How fast the local clock may drift against real time, in parts per
/// million. RFC 5905 uses PHI = 15 ppm for the dispersion growth (section
/// 11.2) and caps the frequency at MAXFREQ = 500 ppm (appendix A.1.1). We
/// take the cap: the local clock here is a virtual machine's, set by a host
/// we do not trust, so 15 ppm is too small a promise.
pub const RHO_PPM: i64 = 500;

/// The largest error bound a sample may have: MAXDIST = 1 s, the distance
/// threshold of RFC 5905 (section 7.2, appendix A.1.1). Its fit() test
/// refuses a server whose root distance is over it (section 11.2.1); the
/// error bound below is that root distance plus our rho term.
pub const MAX_BOUND_NS: i64 = 1_000_000_000;

/// Rounding slack added to every bound: each of T2 and T3 loses less than
/// 1 ns when it becomes nanoseconds, and the halving of the offset loses
/// less than 1 ns.
const ROUNDING_NS: i128 = 3;

const NANOS_PER_SEC: i128 = 1_000_000_000;
const PPM: i128 = 1_000_000;

/// One measurement against one server, all in nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Measurement {
    /// Real Unix time minus the caller's monotonic time, at T4.
    pub offset_ns: i64,
    /// Round-trip delay: (T4 - T1) - (T3 - T2) (RFC 5905 section 8).
    pub delay_ns: i64,
    /// Error bound of the offset, at the local time `t4_local_ns`. At least
    /// [`ROUNDING_NS`] and at most [`MAX_BOUND_NS`].
    pub bound_ns: i64,
    /// T4 on the caller's monotonic clock: when the bound holds.
    pub t4_local_ns: i64,
}

/// Why a response gives no measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SampleError {
    /// T4 is before T1 on the caller's clock.
    LocalTimesReversed,
    /// The server says it sent the response (T3) before it got the
    /// request (T2).
    ServerTimesReversed,
    /// The delay is negative: the server's T3 - T2 is longer than our
    /// round trip (RFC 5905 section 8).
    NegativeDelay,
    /// Stratum outside 1 to 15 (RFC 5905 section 7.3).
    BadStratum(u8),
    /// The reference timestamp is zero: the server clock was never set
    /// (RFC 5905 section 7.3).
    NeverSynchronized,
    /// The reference timestamp, when the server clock was last set, is after
    /// T3 (RFC 5905 section 7.3).
    ReferenceAfterTransmit,
    /// A timestamp does not fit in i64 nanoseconds around the pivot.
    TimestampOutOfRange,
    /// The error bound is over [`MAX_BOUND_NS`] (RFC 5905 MAXDIST).
    BoundTooLarge,
}

impl fmt::Display for SampleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalTimesReversed => f.write_str("local receive time before local send time"),
            Self::ServerTimesReversed => f.write_str("server transmit time before its receive time"),
            Self::NegativeDelay => f.write_str("negative round-trip delay"),
            Self::BadStratum(s) => write!(f, "stratum {s} outside 1 to 15"),
            Self::NeverSynchronized => f.write_str("reference timestamp is zero"),
            Self::ReferenceAfterTransmit => f.write_str("reference timestamp after transmit timestamp"),
            Self::TimestampOutOfRange => f.write_str("timestamp out of range"),
            Self::BoundTooLarge => write!(f, "error bound over {MAX_BOUND_NS} ns (MAXDIST)"),
        }
    }
}

impl core::error::Error for SampleError {}

/// `n / d` rounded up, for `n >= 0` and `d > 0`.
fn ceil_div(n: i128, d: i128) -> i128 {
    (n + d - 1) / d
}

/// 2^precision seconds in nanoseconds, rounded up (RFC 5905 section 7.3:
/// precision is a signed log2 of seconds). Capped at 2^7 s, which is far over
/// [`MAX_BOUND_NS`] anyway.
fn precision_ns(precision: i8) -> i128 {
    let p = i32::from(precision);
    if p >= 0 {
        NANOS_PER_SEC << p.min(7)
    } else {
        // 2^-64 s and below round up to 1 ns.
        let shift = (-p).min(64);
        ceil_div(NANOS_PER_SEC, 1i128 << shift)
    }
}

/// `rho * interval`, rounded up, for an interval in nanoseconds (>= 0).
pub fn drift_ns(interval_ns: i64) -> i64 {
    let n = ceil_div(i128::from(interval_ns.max(0)) * i128::from(RHO_PPM), PPM);
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// Offset, delay and error bound of an authentic response.
///
/// `t1_local_ns` is the caller's monotonic time just before the request
/// left, `t4_local_ns` just after the response arrived. `pivot_unix_nanos`
/// is any time within 68 years of now; it only picks the NTP era of T2 and T3
/// (RFC 5905 section 6).
///
/// With T1 to T4 as in RFC 5905 section 8:
///
/// - delay = (T4 - T1) - (T3 - T2)
/// - offset = ((T2 - T1) + (T3 - T4)) / 2
/// - bound = delay/2 + rootdelay/2 + rootdisp + 2^precision
///   + rho * (T4 - T1), plus [`ROUNDING_NS`]
///
/// The bound is the root distance of RFC 5905 section 11.2 with our rho in
/// place of PHI and the server's precision for epsilon. Refused: T4 before
/// T1, T3 before T2, a negative delay, stratum outside 1 to 15, a zero
/// reference timestamp or one after T3, and a bound over MAXDIST.
pub fn measure(
    sample: &TimeSample,
    t1_local_ns: i64,
    t4_local_ns: i64,
    pivot_unix_nanos: i64,
) -> Result<Measurement, SampleError> {
    if !(1..=15).contains(&sample.stratum) {
        return Err(SampleError::BadStratum(sample.stratum));
    }
    if sample.reference == NtpTimestamp::default() {
        return Err(SampleError::NeverSynchronized);
    }
    if sample.transmit.wrapping_diff(sample.reference).to_bits() < 0 {
        return Err(SampleError::ReferenceAfterTransmit);
    }
    if t4_local_ns < t1_local_ns {
        return Err(SampleError::LocalTimesReversed);
    }
    // T3 - T2 from the NTP values, so an era boundary between them does not
    // matter (RFC 5905 section 6).
    let server_ns = sample.transmit.wrapping_diff(sample.receive).to_nanos();
    if server_ns < 0 {
        return Err(SampleError::ServerTimesReversed);
    }
    let t2 = sample.receive.to_unix_nanos(pivot_unix_nanos).ok_or(SampleError::TimestampOutOfRange)?;
    let t3 = sample.transmit.to_unix_nanos(pivot_unix_nanos).ok_or(SampleError::TimestampOutOfRange)?;
    let (t1, t2, t3, t4) = (i128::from(t1_local_ns), i128::from(t2), i128::from(t3), i128::from(t4_local_ns));

    let round_trip = t4 - t1;
    let delay = round_trip - i128::from(server_ns);
    if delay < 0 {
        return Err(SampleError::NegativeDelay);
    }
    let offset = ((t2 - t1) + (t3 - t4)).div_euclid(2);

    let bound = ceil_div(delay, 2)
        + ceil_div(i128::from(sample.root_delay.to_nanos()), 2)
        + i128::from(sample.root_dispersion.to_nanos())
        // to_nanos of NtpShort rounds down by less than 1 ns each.
        + 2
        + precision_ns(sample.precision)
        + ceil_div(round_trip * i128::from(RHO_PPM), PPM)
        + ROUNDING_NS;
    if bound > i128::from(MAX_BOUND_NS) {
        return Err(SampleError::BoundTooLarge);
    }
    let fit = |v: i128| i64::try_from(v).map_err(|_| SampleError::TimestampOutOfRange);
    Ok(Measurement {
        offset_ns: fit(offset)?,
        delay_ns: fit(delay)?,
        bound_ns: fit(bound)?,
        t4_local_ns,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntp::LeapIndicator;
    use crate::time::NtpShort;
    use alloc::vec::Vec;

    const SEC: i64 = 1_000_000_000;
    const MS: i64 = 1_000_000;
    /// 2026-10-17 00:00:00 UTC.
    const NOW: i64 = 1_792_195_200 * SEC;

    fn sample(t2_unix: i64, t3_unix: i64) -> TimeSample {
        TimeSample {
            leap: LeapIndicator::NoWarning,
            stratum: 2,
            precision: -20,
            root_delay: NtpShort::from_bits(0),
            root_dispersion: NtpShort::from_bits(0),
            reference: NtpTimestamp::from_unix_nanos(t2_unix - 10 * SEC),
            origin: NtpTimestamp::from_bits(1),
            receive: NtpTimestamp::from_unix_nanos(t2_unix),
            transmit: NtpTimestamp::from_unix_nanos(t3_unix),
            cookies: Vec::new(),
        }
    }

    #[test]
    fn symmetric_path() {
        // Local clock reads 1000 s at T1; real time is NOW + 1000 s + 5 ms.
        // 20 ms round trip, 1 ms in the server.
        let t1 = 1000 * SEC;
        let real_t1 = NOW + t1 + 5 * MS;
        let s = sample(real_t1 + 9_500_000, real_t1 + 10_500_000);
        let m = measure(&s, t1, t1 + 20 * MS, NOW).unwrap();
        assert_eq!(m.delay_ns, 19 * MS);
        assert!((m.offset_ns - (NOW + 5 * MS)).abs() <= 1, "{}", m.offset_ns);
        // 9.5 ms + 2^-20 s (954 ns, rounded up to 954) + 500 ppm of 20 ms
        // (10 us) + slack.
        let p = 954; // ceil(1e9 / 2^20) = 953.67 -> 954
        assert_eq!(m.bound_ns, 9_500_000 + 2 + p + 10_000 + 3);
        assert_eq!(m.t4_local_ns, t1 + 20 * MS);
    }

    #[test]
    fn root_values_add_to_the_bound() {
        let t1 = 0;
        let mut s = sample(NOW + 5 * MS, NOW + 5 * MS);
        s.root_delay = NtpShort::from_bits(0x0000_0100); // 1/256 s = 3,906,250 ns
        s.root_dispersion = NtpShort::from_bits(0x0000_0200); // 7,812,500 ns
        let m = measure(&s, t1, 10 * MS, NOW).unwrap();
        let base = measure(&sample(NOW + 5 * MS, NOW + 5 * MS), t1, 10 * MS, NOW).unwrap();
        assert_eq!(m.bound_ns - base.bound_ns, 1_953_125 + 7_812_500);
    }

    #[test]
    fn the_true_time_is_inside_the_bound_for_any_path_asymmetry() {
        // The request takes `up` ns, the server holds it 1 ms, the reply
        // takes `down` ns. Whatever the split, |offset - true| <= bound.
        let real_offset = NOW + 123 * MS;
        for (up, down) in [(0, 40 * MS), (40 * MS, 0), (20 * MS, 20 * MS), (1, 1), (0, 0)] {
            let t1 = 77 * SEC;
            let t2 = t1 + up + real_offset;
            let t3 = t2 + MS;
            let t4 = t1 + up + MS + down;
            let m = measure(&sample(t2, t3), t1, t4, NOW).unwrap();
            assert!((m.offset_ns - real_offset).abs() <= m.bound_ns, "up {up} down {down}: {m:?}");
        }
    }

    #[test]
    fn refusals() {
        let ok = sample(NOW, NOW + MS);
        assert!(measure(&ok, 0, 10 * MS, NOW).is_ok());
        assert_eq!(measure(&ok, 10, 9, NOW), Err(SampleError::LocalTimesReversed));
        assert_eq!(measure(&sample(NOW + MS, NOW), 0, 10 * MS, NOW), Err(SampleError::ServerTimesReversed));
        // The server held the request 2 ms; our round trip was 1 ms.
        assert_eq!(measure(&sample(NOW, NOW + 2 * MS), 0, MS, NOW), Err(SampleError::NegativeDelay));
        for stratum in [0, 16, 255] {
            let mut s = ok.clone();
            s.stratum = stratum;
            assert_eq!(measure(&s, 0, MS, NOW), Err(SampleError::BadStratum(stratum)));
        }
        let mut s = ok.clone();
        s.reference = NtpTimestamp::default();
        assert_eq!(measure(&s, 0, 10 * MS, NOW), Err(SampleError::NeverSynchronized));
        s.reference = NtpTimestamp::from_unix_nanos(NOW + SEC);
        assert_eq!(measure(&s, 0, 10 * MS, NOW), Err(SampleError::ReferenceAfterTransmit));
        let mut s = ok.clone();
        s.root_dispersion = NtpShort::from_bits(0x0001_0000); // 1 s
        assert_eq!(measure(&s, 0, 10 * MS, NOW), Err(SampleError::BoundTooLarge));
        let mut s = ok.clone();
        s.precision = 1; // 2 s
        assert_eq!(measure(&s, 0, 10 * MS, NOW), Err(SampleError::BoundTooLarge));
        // A 2.1 s round trip: delay/2 alone is over 1 s.
        assert_eq!(measure(&ok, 0, 2_100 * MS, NOW), Err(SampleError::BoundTooLarge));
    }

    #[test]
    fn extreme_inputs_do_not_panic() {
        let s = sample(NOW, NOW);
        for (t1, t4) in [(i64::MIN, i64::MAX), (i64::MIN, i64::MIN), (i64::MAX, i64::MAX), (0, i64::MAX)] {
            for pivot in [i64::MIN, 0, i64::MAX] {
                let _ = measure(&s, t1, t4, pivot);
            }
        }
        for p in [i8::MIN, -64, -1, 0, 7, 8, i8::MAX] {
            let mut s = s.clone();
            s.precision = p;
            let _ = measure(&s, 0, 1, NOW);
        }
        let mut s = s.clone();
        s.root_delay = NtpShort::from_bits(u32::MAX);
        s.root_dispersion = NtpShort::from_bits(u32::MAX);
        assert_eq!(measure(&s, 0, 1, NOW), Err(SampleError::BoundTooLarge));
    }

    #[test]
    fn precision_and_drift() {
        assert_eq!(precision_ns(0), 1_000_000_000);
        assert_eq!(precision_ns(-1), 500_000_000);
        assert_eq!(precision_ns(-30), 1);
        assert_eq!(precision_ns(-128), 1);
        assert_eq!(precision_ns(127), 128_000_000_000);
        assert_eq!(drift_ns(32 * SEC), 16 * MS);
        assert_eq!(drift_ns(1), 1);
        assert_eq!(drift_ns(-5), 0);
        assert_eq!(drift_ns(i64::MAX), 4_611_686_018_427_388);
    }
}
