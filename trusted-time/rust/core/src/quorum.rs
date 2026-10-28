//! The time from several servers that one of them may get wrong.
//!
//! Each measurement gives an interval [offset - bound, offset + bound] that
//! holds the real offset if the server is honest. With at most [`F`] servers
//! wrong, at least `n - F` intervals hold the real offset, so the real offset
//! is a point that at least `n - F` intervals cover. This module returns
//! [lo, hi], the smallest and the largest such point, or no answer if there
//! is none (more than F servers are wrong). The result is the midpoint, with
//! half the width as its bound. This is the intersection algorithm of
//! RFC 5905 section 11.2.1 (Marzullo) with a fixed F and without the
//! clustering that follows it.
//!
//! The plan for this step named a simpler rule: lo = the (F+1)-th smallest
//! lower end, hi = the (F+1)-th largest upper end, fail if lo > hi. With
//! `n = 2F + 1` that rule never fails: for three servers it takes the middle
//! lower end and the middle upper end, which are always in order, even when
//! the three intervals are disjoint. The [lo, hi] here always lies inside
//! that rule's interval and is refused when no point has `n - F` intervals.
//!
//! The servers must be run by distinct operators (the caller names them),
//! because two servers of one operator can be wrong together.

use alloc::vec::Vec;
use core::fmt;

use crate::sample::drift_ns;

/// How many servers may be wrong.
pub const F: usize = 1;
/// The fewest measurements the quorum needs: 2F + 1.
pub const MIN_SERVERS: usize = 2 * F + 1;
/// The most measurements accepted (our cap).
pub const MAX_SERVERS: usize = 16;
/// The longest operator label, in octets (our cap).
pub const MAX_OPERATOR_LEN: usize = 32;

/// One server's measurement, as [`crate::sample::measure`] gives it, with
/// the operator that runs the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interval<'a> {
    /// Who runs the server, 1 to [`MAX_OPERATOR_LEN`] octets. Two
    /// measurements with the same label are refused.
    pub operator: &'a [u8],
    /// Real Unix time minus the caller's monotonic time.
    pub offset_ns: i64,
    /// Error bound at `t4_local_ns`, at least 0.
    pub bound_ns: i64,
    /// When the bound held, on the caller's monotonic clock.
    pub t4_local_ns: i64,
}

/// The combined offset at the caller's monotonic time `now`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuorumResult {
    /// Real Unix time minus the caller's monotonic time.
    pub offset_ns: i64,
    /// Error bound of the offset at `now`.
    pub bound_ns: i64,
    /// The lower end of the agreed interval.
    pub lo_ns: i64,
    /// The upper end of the agreed interval.
    pub hi_ns: i64,
}

/// Why there is no combined time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuorumError {
    /// Fewer than [`MIN_SERVERS`] measurements.
    TooFew,
    /// More than [`MAX_SERVERS`] measurements.
    TooMany,
    /// An operator label is empty or longer than [`MAX_OPERATOR_LEN`].
    BadOperator,
    /// Two measurements from the same operator.
    DuplicateOperator,
    /// A negative bound.
    BadBound,
    /// A measurement taken after `now`.
    FromTheFuture,
    /// lo > hi: more than F servers are wrong.
    NoAgreement,
    /// The numbers do not fit in i64 nanoseconds.
    OutOfRange,
}

impl fmt::Display for QuorumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooFew => write!(f, "fewer than {MIN_SERVERS} servers"),
            Self::TooMany => write!(f, "more than {MAX_SERVERS} servers"),
            Self::BadOperator => write!(f, "operator label empty or over {MAX_OPERATOR_LEN} octets"),
            Self::DuplicateOperator => f.write_str("two servers of one operator"),
            Self::BadBound => f.write_str("negative error bound"),
            Self::FromTheFuture => f.write_str("measurement after the quorum time"),
            Self::NoAgreement => write!(f, "the servers disagree: more than {F} wrong"),
            Self::OutOfRange => f.write_str("offset out of range"),
        }
    }
}

impl core::error::Error for QuorumError {}

/// Combines the measurements at the caller's monotonic time `now_local_ns`.
/// Each bound first grows by rho times its age, `now - t4`
/// ([`crate::sample::RHO_PPM`]), so all intervals hold at `now`.
pub fn combine(samples: &[Interval<'_>], now_local_ns: i64) -> Result<QuorumResult, QuorumError> {
    if samples.len() < MIN_SERVERS {
        return Err(QuorumError::TooFew);
    }
    if samples.len() > MAX_SERVERS {
        return Err(QuorumError::TooMany);
    }
    // Ends of the intervals as (point, 0 for a lower end or 1 for an upper
    // end). Sorted, a lower end comes before an upper end at the same point,
    // so intervals that only touch count as overlapping (they are closed).
    let mut ends: Vec<(i128, u8)> = Vec::with_capacity(2 * samples.len());
    for (i, s) in samples.iter().enumerate() {
        if s.operator.is_empty() || s.operator.len() > MAX_OPERATOR_LEN {
            return Err(QuorumError::BadOperator);
        }
        if samples.iter().take(i).any(|o| o.operator == s.operator) {
            return Err(QuorumError::DuplicateOperator);
        }
        if s.bound_ns < 0 {
            return Err(QuorumError::BadBound);
        }
        if s.t4_local_ns > now_local_ns {
            return Err(QuorumError::FromTheFuture);
        }
        let age = i128::from(now_local_ns) - i128::from(s.t4_local_ns);
        let age = i64::try_from(age).map_err(|_| QuorumError::OutOfRange)?;
        let bound = i128::from(s.bound_ns) + i128::from(drift_ns(age));
        ends.push((i128::from(s.offset_ns) - bound, 0));
        ends.push((i128::from(s.offset_ns) + bound, 1));
    }
    ends.sort_unstable();
    // Walk left to right counting the intervals that cover the point. lo is
    // the first lower end where the count reaches n - F, hi the last upper
    // end where it is still n - F before that interval closes.
    let need = samples.len() - F;
    let (mut count, mut lo, mut hi) = (0usize, None, None);
    for &(x, kind) in &ends {
        if kind == 0 {
            count += 1;
            if count >= need && lo.is_none() {
                lo = Some(x);
            }
        } else {
            if count >= need {
                hi = Some(x);
            }
            count = count.saturating_sub(1);
        }
    }
    let (Some(lo), Some(hi)) = (lo, hi) else {
        return Err(QuorumError::NoAgreement);
    };
    // floor of the midpoint and ceil of the half width: [mid - b, mid + b]
    // covers [lo, hi].
    let mid = (lo + hi).div_euclid(2);
    let half = (hi - lo + 1) / 2;
    let fit = |v: i128| i64::try_from(v).map_err(|_| QuorumError::OutOfRange);
    Ok(QuorumResult { offset_ns: fit(mid)?, bound_ns: fit(half)?, lo_ns: fit(lo)?, hi_ns: fit(hi)? })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: i64 = 1_000_000;

    fn iv(op: &'static str, offset_ms: i64, bound_ms: i64) -> Interval<'static> {
        Interval { operator: op.as_bytes(), offset_ns: offset_ms * MS, bound_ns: bound_ms * MS, t4_local_ns: 0 }
    }

    #[test]
    fn three_that_agree() {
        // [90, 110], [95, 125], [100, 104]: two or more cover [95, 110].
        let r = combine(&[iv("a", 100, 10), iv("b", 110, 15), iv("c", 102, 2)], 0).unwrap();
        assert_eq!((r.lo_ns, r.hi_ns), (95 * MS, 110 * MS));
        assert_eq!(r.offset_ns, 102_500_000);
        assert_eq!(r.bound_ns, 7_500_000);
    }

    #[test]
    fn one_liar_cannot_move_the_result_outside_the_honest_intervals() {
        for liar in [-1_000_000, -50, 0, 99, 101, 150, 1_000_000] {
            let r = combine(&[iv("a", 100, 5), iv("b", 101, 5), iv("liar", liar, 1)], 0).unwrap();
            // The real offset is in both honest intervals: [96, 105].
            for real in [96 * MS, 100 * MS, 105 * MS] {
                assert!((r.offset_ns - real).abs() <= r.bound_ns, "liar {liar} real {real}: {r:?}");
            }
        }
    }

    #[test]
    fn two_liars_that_agree_with_nobody_give_no_answer() {
        let e = combine(&[iv("a", 0, 1), iv("b", 100, 1), iv("c", 200, 1)], 0);
        assert_eq!(e, Err(QuorumError::NoAgreement));
    }

    #[test]
    fn four_servers() {
        // [95, 105], [98, 102], [99, 101], [500, 502]: three cover [99, 101].
        // The plan's simpler rule would give [98, 105].
        let r = combine(&[iv("a", 100, 5), iv("b", 100, 2), iv("c", 100, 1), iv("d", 501, 1)], 0).unwrap();
        assert_eq!((r.lo_ns, r.hi_ns), (99 * MS, 101 * MS));
    }

    #[test]
    fn touching_intervals_overlap() {
        // [0, 2], [2, 4], [10, 12]: the point 2 is in two.
        let r = combine(&[iv("a", 1, 1), iv("b", 3, 1), iv("c", 11, 1)], 0).unwrap();
        assert_eq!((r.lo_ns, r.hi_ns, r.bound_ns), (2 * MS, 2 * MS, 0));
    }

    /// Against the definition, on random intervals: lo and hi are covered by
    /// n - F intervals, nothing outside [lo, hi] is, and [lo, hi] lies inside
    /// the plan's rule ((F+1)-th smallest lower end, (F+1)-th largest upper).
    #[test]
    fn random_intervals_match_the_definition() {
        let names = ["a", "b", "c", "d", "e", "f", "g"];
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = |m: u64| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x % m) as i64
        };
        let (mut agreed, mut refused) = (0, 0);
        for _ in 0..20_000 {
            let n = 3 + next(5) as usize;
            let v: Vec<_> = (0..n).map(|i| iv(names[i], next(200), next(40))).collect();
            let need = n - F;
            let cover = |p: i64| v.iter().filter(|s| s.offset_ns - s.bound_ns <= p && p <= s.offset_ns + s.bound_ns).count();
            let mut points: Vec<i64> = v.iter().flat_map(|s| [s.offset_ns - s.bound_ns, s.offset_ns + s.bound_ns]).collect();
            points.sort_unstable();
            let covered: Vec<i64> = points.iter().copied().filter(|&p| cover(p) >= need).collect();
            match combine(&v, 0) {
                Ok(r) => {
                    agreed += 1;
                    assert_eq!(covered.first(), Some(&r.lo_ns));
                    assert_eq!(covered.last(), Some(&r.hi_ns));
                    let mut lows: Vec<i64> = v.iter().map(|s| s.offset_ns - s.bound_ns).collect();
                    let mut highs: Vec<i64> = v.iter().map(|s| s.offset_ns + s.bound_ns).collect();
                    lows.sort_unstable();
                    highs.sort_unstable_by(|a, b| b.cmp(a));
                    assert!(lows[F] <= r.lo_ns && r.hi_ns <= highs[F]);
                    assert!(r.offset_ns - r.bound_ns <= r.lo_ns && r.hi_ns <= r.offset_ns + r.bound_ns);
                }
                Err(e) => {
                    refused += 1;
                    assert_eq!(e, QuorumError::NoAgreement);
                    assert!(covered.is_empty());
                }
            }
        }
        assert!(agreed > 1000 && refused > 1000, "{agreed} {refused}");
    }

    #[test]
    fn bounds_age_by_rho() {
        // 10 s old: each bound grows by 500 ppm of 10 s = 5 ms.
        let mut s = [iv("a", 100, 1), iv("b", 100, 1), iv("c", 100, 1)];
        for x in &mut s {
            x.t4_local_ns = 0;
        }
        let r = combine(&s, 10_000 * MS).unwrap();
        assert_eq!(r.bound_ns, 6 * MS);
        assert_eq!(combine(&s, -1), Err(QuorumError::FromTheFuture));
    }

    #[test]
    fn refusals() {
        assert_eq!(combine(&[iv("a", 0, 1), iv("b", 0, 1)], 0), Err(QuorumError::TooFew));
        assert_eq!(combine(&[iv("a", 0, 1), iv("b", 0, 1), iv("a", 0, 1)], 0), Err(QuorumError::DuplicateOperator));
        assert_eq!(combine(&[iv("a", 0, 1), iv("b", 0, 1), iv("", 0, 1)], 0), Err(QuorumError::BadOperator));
        let long = "123456789012345678901234567890123";
        assert_eq!(long.len(), MAX_OPERATOR_LEN + 1);
        assert_eq!(combine(&[iv("a", 0, 1), iv("b", 0, 1), iv(long, 0, 1)], 0), Err(QuorumError::BadOperator));
        assert_eq!(combine(&[iv("a", 0, 1), iv("b", 0, 1), iv("c", 0, -1)], 0), Err(QuorumError::BadBound));
        let names = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q"];
        let many: Vec<_> = names.iter().map(|n| iv(n, 0, 1)).collect();
        assert_eq!(combine(&many, 0), Err(QuorumError::TooMany));
        assert!(combine(&many[..16], 0).is_ok());
    }

    #[test]
    fn extreme_values_do_not_panic() {
        let x = |op: &'static str, o: i64, b: i64, t: i64| Interval {
            operator: op.as_bytes(),
            offset_ns: o,
            bound_ns: b,
            t4_local_ns: t,
        };
        for o in [i64::MIN, 0, i64::MAX] {
            for b in [0, i64::MAX] {
                for (t, now) in [(i64::MIN, i64::MAX), (0, 0), (i64::MAX, i64::MAX)] {
                    let _ = combine(&[x("a", o, b, t), x("b", o, b, t), x("c", o, b, t)], now);
                }
            }
        }
    }
}
