//! An NTS association: the two keys from one NTS-KE session and the cookies
//! the server has handed out (RFC 8915 sections 4 and 5).

use std::collections::VecDeque;

use signer_nts_core::cookie::Cookie;
use signer_nts_core::ke;
use signer_nts_core::keys::{C2sKey, S2cKey};
use signer_nts_core::ntp::{self, LeapIndicator, PendingRequest, RequestInput, Response};
use signer_nts_core::sample;
use signer_nts_core::time::NtpTimestamp;

use crate::code::*;
use crate::{REQUEST_RANDOM_LEN, Sample, reason};
use core::ffi::c_int;

/// Cookies kept: the eight a server SHOULD send (RFC 8915 section 4.1.6).
/// Requests ask for enough placeholders to get back to this many.
pub const COOKIE_JAR: usize = 8;

/// The keys and cookies of one NTS-KE session. Dropping it wipes the keys
/// and the cookies.
#[derive(Debug)]
pub struct Association {
    c2s: C2sKey,
    s2c: S2cKey,
    cookies: VecDeque<Cookie>,
    server: Option<String>,
    port: u16,
}

/// What [`Association::verify`] found.
#[derive(Debug, PartialEq, Eq)]
pub enum Verified {
    /// An authentic sample that passed the RFC 5905 checks.
    Time(Sample),
    /// A Kiss-o'-Death: only `kiss` and `cookies_held` are set.
    Kiss(Sample),
}

impl Association {
    /// Checks the NTS-KE response and takes the two exported keys.
    pub fn new(response: &[u8], c2s: &[u8], s2c: &[u8]) -> Result<Self, (c_int, u32)> {
        let (Some(c2s), Some(s2c)) = (C2sKey::from_slice(c2s), S2cKey::from_slice(s2c)) else {
            return Err((E_ARG, 0));
        };
        let r = ke::parse_response(response).map_err(|e| (E_KE, reason::ke(&e)))?;
        let port = r.ntp_port();
        Ok(Self { c2s, s2c, cookies: r.cookies.into_iter().collect(), server: r.server, port })
    }

    /// Cookies held.
    pub fn cookies(&self) -> usize {
        self.cookies.len()
    }

    /// The NTP port (RFC 8915 section 4.1.8: 123 if none was named).
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The NTP server named by the KE server (section 4.1.7), if any.
    pub fn server(&self) -> Option<&str> {
        self.server.as_deref()
    }

    /// Placeholders for a request with `cookie` while `held` cookies are in
    /// the jar, this one included: enough to have [`COOKIE_JAR`] again after
    /// the response (it carries one cookie plus one per placeholder,
    /// RFC 8915 section 5.7), within the size limit of `max_placeholders`.
    fn placeholders(cookie: &Cookie, held: usize) -> usize {
        COOKIE_JAR.saturating_sub(held).min(ntp::max_placeholders(cookie))
    }

    /// Length of the next request, `None` without a cookie.
    pub fn request_len(&self) -> Option<usize> {
        let cookie = self.cookies.front()?;
        ntp::request_len(cookie.len(), Self::placeholders(cookie, self.cookies.len()))
    }

    /// Builds a request with the oldest cookie and takes that cookie out of
    /// the jar: each cookie goes out once (RFC 8915 section 5.7).
    pub fn request(&mut self, random: &[u8; REQUEST_RANDOM_LEN]) -> Result<(Vec<u8>, PendingRequest), c_int> {
        let (transmit, rest) = random.split_first_chunk::<8>().ok_or(E_ARG)?;
        let (unique_id, rest) = rest.split_first_chunk::<{ ntp::UNIQUE_ID_LEN }>().ok_or(E_ARG)?;
        let nonce = rest.first_chunk::<{ ntp::NONCE_LEN }>().ok_or(E_ARG)?;
        let cookie = self.cookies.pop_front().ok_or(E_NO_COOKIE)?;
        let input = RequestInput {
            transmit: NtpTimestamp::from_be_bytes(*transmit),
            unique_id: *unique_id,
            nonce: *nonce,
            cookie: &cookie,
            placeholders: Self::placeholders(&cookie, self.cookies.len() + 1),
        };
        ntp::build_request(&self.c2s, &input).map_err(|_| E_ARG)
    }

    /// Checks the response to `req`, keeps its cookies and measures it
    /// (`sample::measure`). The cookies of an authentic response are kept
    /// even if the measurement is refused: they are good for the next one.
    pub fn verify(
        &mut self,
        req: &mut PendingRequest,
        packet: &[u8],
        t1_local_ns: i64,
        t4_local_ns: i64,
        pivot_unix_ns: i64,
    ) -> Result<Verified, (c_int, u32)> {
        match req.verify_response(&self.s2c, packet) {
            Err(e) => Err((E_NTP, reason::ntp(&e))),
            Ok(Response::KissOfDeath(code)) => Ok(Verified::Kiss(Sample {
                kiss: reason::kiss_octets(code),
                cookies_held: u32::try_from(self.cookies.len()).unwrap_or(u32::MAX),
                ..Sample::default()
            })),
            Ok(Response::Time(s)) => {
                let received = s.cookies.len();
                for c in &s.cookies {
                    self.cookies.push_back(c.clone());
                }
                while self.cookies.len() > COOKIE_JAR {
                    self.cookies.pop_front();
                }
                let m = sample::measure(&s, t1_local_ns, t4_local_ns, pivot_unix_ns)
                    .map_err(|e| (E_SAMPLE, reason::sample(&e)))?;
                Ok(Verified::Time(Sample {
                    offset_ns: m.offset_ns,
                    delay_ns: m.delay_ns,
                    bound_ns: m.bound_ns,
                    t4_local_ns: m.t4_local_ns,
                    root_delay_ns: i64::try_from(s.root_delay.to_nanos()).unwrap_or(i64::MAX),
                    root_dispersion_ns: i64::try_from(s.root_dispersion.to_nanos()).unwrap_or(i64::MAX),
                    cookies_received: u32::try_from(received).unwrap_or(u32::MAX),
                    cookies_held: u32::try_from(self.cookies.len()).unwrap_or(u32::MAX),
                    precision: i32::from(s.precision),
                    stratum: s.stratum,
                    leap: match s.leap {
                        LeapIndicator::NoWarning => 0,
                        LeapIndicator::InsertSecond => 1,
                        LeapIndicator::DeleteSecond => 2,
                    },
                    kiss: [0; 4],
                }))
            }
        }
    }
}
