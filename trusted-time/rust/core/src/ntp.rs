//! The NTPv4 client request and the check of the server response, with the
//! NTS extension fields (RFC 8915 section 5, RFC 7822, RFC 5905).
//!
//! The caller sends the request over UDP and passes the response in. It
//! also supplies every random value: the transmit timestamp, the Unique
//! Identifier and the AEAD nonce. [`build_request`] returns the packet and a
//! [`PendingRequest`] that checks the response.
//!
//! A request carries, in this order: the 48-octet header, a Unique
//! Identifier, one NTS Cookie, zero to seven Cookie Placeholders, and the
//! NTS Authenticator over all of it with the C2S key. A response must echo
//! the Unique Identifier and carry an authenticator with the S2C key, and its
//! encrypted part holds the new cookies (RFC 8915 section 5.7).

use alloc::vec::Vec;
use core::fmt;
use subtle::ConstantTimeEq;

use crate::bytes::{Reader, all_zero, pad4};
use crate::cookie::{Cookie, MAX_COOKIE_LEN};
use crate::keys::{C2sKey, S2cKey};
use crate::siv;
use crate::time::{NtpShort, NtpTimestamp};

/// Length of the NTP header; extension fields start after it
/// (RFC 5905 section 7.3, RFC 7822 section 7.5).
pub const HEADER_LEN: usize = 48;
/// NTP version 4 (RFC 5905 section 7.3). NTS is defined for NTPv4 only
/// (RFC 8915 section 5).
const VERSION: u8 = 4;
/// Association modes (RFC 5905 section 7.3, figure 10): 3 client, 4 server.
const MODE_CLIENT: u8 = 3;
const MODE_SERVER: u8 = 4;
/// Leap indicator 3: unknown, clock unsynchronized (RFC 5905 section 7.3,
/// figure 9).
const LEAP_UNSYNCHRONIZED: u8 = 3;
/// Highest stratum of a synchronized server. 16 is unsynchronized and 17 to
/// 255 are reserved (RFC 5905 section 7.3, figure 11). 0 marks a
/// Kiss-o'-Death packet (RFC 5905 section 7.4).
const MAX_STRATUM: u8 = 15;

/// NTP extension field types of NTS (RFC 8915 sections 5.3 to 5.6,
/// registered in section 7.5).
pub mod field_type {
    /// Unique Identifier (section 5.3).
    pub const UNIQUE_IDENTIFIER: u16 = 0x0104;
    /// NTS Cookie (section 5.4).
    pub const NTS_COOKIE: u16 = 0x0204;
    /// NTS Cookie Placeholder (section 5.5).
    pub const NTS_COOKIE_PLACEHOLDER: u16 = 0x0304;
    /// NTS Authenticator and Encrypted Extension Fields (section 5.6).
    pub const NTS_AUTHENTICATOR: u16 = 0x0404;
}

/// Length of the Unique Identifier we send. RFC 8915 section 5.3: at least
/// 32 octets from a cryptographically secure random number generator.
pub const UNIQUE_ID_LEN: usize = 32;
/// Length of the AEAD nonce we send. RFC 8915 section 5.6: a client nonce of
/// at least N_REQ octets (16 for AES-SIV-CMAC-256, whose N_MAX has no limit,
/// RFC 5297 section 6.1) needs no Additional Padding.
pub const NONCE_LEN: usize = 16;
/// Most Cookie Placeholders in one request. RFC 8915 section 5.7: the client
/// SHOULD NOT include more than seven.
pub const MAX_PLACEHOLDERS: usize = 7;
/// Longest request we build, in octets. RFC 8915 section 5.7: senders SHOULD
/// send fewer placeholders if needed to avoid fragmentation, and 1280 octets
/// is the IPv6 minimum MTU.
pub const MAX_REQUEST_LEN: usize = 1280;
/// Longest response we accept, in octets (our cap). The server sends at most
/// one cookie more than the placeholders we sent (RFC 8915 section 5.7), so
/// a response to our request is about as long as the request.
pub const MAX_RESPONSE_LEN: usize = 2048;

/// Type and length of an extension field, two octets each (RFC 7822 section 7.5).
const FIELD_HEADER_LEN: usize = 4;
/// Shortest extension field outside the encrypted part: 16 octets when no
/// MAC follows (RFC 7822 section 7.5.1.4). RFC 8915 section 5.6 lets
/// encrypted fields be shorter.
const MIN_FIELD_LEN: usize = 16;
/// Nonce Length and Ciphertext Length of the authenticator, two octets each
/// (RFC 8915 section 5.6).
const AUTH_LENGTHS_LEN: usize = 4;
/// The authenticator we send: field header, the two lengths, our nonce, and
/// a ciphertext that is only the 16-octet tag (we encrypt no fields).
const REQUEST_AUTH_FIELD_LEN: usize = FIELD_HEADER_LEN + AUTH_LENGTHS_LEN + NONCE_LEN + siv::TAG_LEN;

/// What the caller passes to [`build_request`].
pub struct RequestInput<'a> {
    /// The transmit timestamp of the request. Set it to a random value, not
    /// to the local clock: the server copies it into the origin timestamp of
    /// its response, and the check of that copy refuses responses to other
    /// requests (RFC 5905 section 8). The caller keeps its own clock reading
    /// of the send time.
    pub transmit: NtpTimestamp,
    /// The Unique Identifier: 32 octets from a CSPRNG, new for each request
    /// (RFC 8915 section 5.3).
    pub unique_id: [u8; UNIQUE_ID_LEN],
    /// The AEAD nonce of the authenticator: 16 octets from a CSPRNG
    /// (RFC 8915 section 5.6).
    pub nonce: [u8; NONCE_LEN],
    /// The cookie to send (RFC 8915 section 5.4). Send each cookie once
    /// (section 5.7).
    pub cookie: &'a Cookie,
    /// Cookie Placeholders, to ask for that many more cookies (RFC 8915
    /// section 5.5): at most [`MAX_PLACEHOLDERS`], and at most
    /// [`max_placeholders`] for this cookie.
    pub placeholders: usize,
}

/// Length of a request with a cookie of `cookie_len` octets and
/// `placeholders` placeholders.
pub fn request_len(cookie_len: usize, placeholders: usize) -> Option<usize> {
    let cookie_field = FIELD_HEADER_LEN.checked_add(pad4(cookie_len)?)?;
    let cookie_fields = cookie_field.checked_mul(placeholders.checked_add(1)?)?;
    (HEADER_LEN + FIELD_HEADER_LEN + UNIQUE_ID_LEN + REQUEST_AUTH_FIELD_LEN).checked_add(cookie_fields)
}

/// The most placeholders a request with this cookie can carry: at most
/// [`MAX_PLACEHOLDERS`], and few enough that the request fits in
/// [`MAX_REQUEST_LEN`] octets (RFC 8915 section 5.7).
pub fn max_placeholders(cookie: &Cookie) -> usize {
    (0..=MAX_PLACEHOLDERS)
        .rev()
        .find(|&p| request_len(cookie.len(), p).is_some_and(|n| n <= MAX_REQUEST_LEN))
        .unwrap_or(0)
}

/// Appends an extension field: type, length of the whole field, the body,
/// zero padding to a multiple of 4 octets (RFC 7822 section 7.5).
fn push_field(out: &mut Vec<u8>, field_type: u16, body: &[u8]) -> Result<(), NtpError> {
    let padded = pad4(body.len()).ok_or(NtpError::RequestTooLong)?;
    let len = u16::try_from(FIELD_HEADER_LEN + padded).map_err(|_| NtpError::RequestTooLong)?;
    out.extend_from_slice(&field_type.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    out.resize(out.len() + (padded - body.len()), 0);
    Ok(())
}

/// Builds a client request (RFC 8915 section 5.7) and the state that checks
/// its response.
///
/// The header has leap indicator 0, version 4, mode 3 and the caller's
/// transmit timestamp; all other header fields are zero. Then the Unique
/// Identifier, the cookie and the placeholders, all authenticated and not
/// encrypted (section 5.7), and last the authenticator: AES-SIV over the
/// header and those fields with the C2S key and the caller's nonce, with no
/// encrypted fields (section 5.6).
pub fn build_request(c2s: &C2sKey, input: &RequestInput<'_>) -> Result<(Vec<u8>, PendingRequest), NtpError> {
    if input.placeholders > MAX_PLACEHOLDERS {
        return Err(NtpError::TooManyPlaceholders);
    }
    let cookie = input.cookie.as_bytes();
    let len = request_len(cookie.len(), input.placeholders).ok_or(NtpError::RequestTooLong)?;
    if len > MAX_REQUEST_LEN {
        return Err(NtpError::RequestTooLong);
    }
    let mut out = Vec::with_capacity(len);

    // RFC 5905 section 7.3: LI (2 bits), VN (3 bits), mode (3 bits), then
    // stratum, poll, precision, root delay, root dispersion, reference ID,
    // and the reference, origin and receive timestamps, all zero here
    // (octets 1 to 39). The transmit timestamp is octets 40 to 47.
    out.push((VERSION << 3) | MODE_CLIENT);
    out.resize(HEADER_LEN - 8, 0);
    out.extend_from_slice(&input.transmit.to_be_bytes());

    push_field(&mut out, field_type::UNIQUE_IDENTIFIER, &input.unique_id)?;
    push_field(&mut out, field_type::NTS_COOKIE, cookie)?;
    // Section 5.5: a placeholder body has the cookie's length and SHOULD be
    // all zeros.
    let zeros = [0u8; MAX_COOKIE_LEN];
    let placeholder = zeros.get(..cookie.len()).ok_or(NtpError::RequestTooLong)?;
    for _ in 0..input.placeholders {
        push_field(&mut out, field_type::NTS_COOKIE_PLACEHOLDER, placeholder)?;
    }

    // Section 5.6: A is the packet so far, N our nonce, P empty. The output
    // is the 16-octet tag. Nonce and tag are multiples of 4, so there is no
    // padding, and the nonce is N_REQ long, so no Additional Padding.
    let ciphertext = siv::seal(c2s.bytes(), &out, &input.nonce, &[]).ok_or(NtpError::EncryptFailed)?;
    let mut body = Vec::with_capacity(REQUEST_AUTH_FIELD_LEN - FIELD_HEADER_LEN);
    body.extend_from_slice(&(NONCE_LEN as u16).to_be_bytes());
    body.extend_from_slice(&(siv::TAG_LEN as u16).to_be_bytes());
    body.extend_from_slice(&input.nonce);
    body.extend_from_slice(&ciphertext);
    push_field(&mut out, field_type::NTS_AUTHENTICATOR, &body)?;

    if out.len() != len {
        return Err(NtpError::RequestTooLong);
    }
    let pending = PendingRequest {
        transmit: input.transmit,
        unique_id: input.unique_id,
        placeholders: input.placeholders,
        answered: false,
    };
    Ok((out, pending))
}

/// A request that was built and may be waiting for its response. It checks
/// responses with [`verify_response`](Self::verify_response) and accepts at
/// most one. It is not `Clone`, so a copy cannot accept the same response
/// again.
#[derive(Debug)]
pub struct PendingRequest {
    transmit: NtpTimestamp,
    unique_id: [u8; UNIQUE_ID_LEN],
    placeholders: usize,
    answered: bool,
}

/// What a valid response gives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    /// An authentic time sample.
    Time(TimeSample),
    /// A Kiss-o'-Death packet (RFC 5905 section 7.4): no time. It matched our
    /// Unique Identifier and origin timestamp, but it is not authenticated:
    /// RFC 8915 section 5.7 has servers send NTSN without an authenticator,
    /// and lets the client act on a KoD whose Unique Identifier matches.
    KissOfDeath(KissCode),
}

/// The fields of an authentic server response, as on the wire (RFC 5905
/// section 7.3). The error bound and the quorum are computed elsewhere.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimeSample {
    /// Leap indicator, never "unsynchronized" (that is refused).
    pub leap: LeapIndicator,
    /// 1 to 15.
    pub stratum: u8,
    /// Precision of the server clock, log2 seconds.
    pub precision: i8,
    /// Round-trip delay to the reference clock.
    pub root_delay: NtpShort,
    /// Dispersion to the reference clock.
    pub root_dispersion: NtpShort,
    /// When the server clock was last set.
    pub reference: NtpTimestamp,
    /// The origin timestamp; equal to the transmit timestamp of our request.
    pub origin: NtpTimestamp,
    /// When the server received our request (T2).
    pub receive: NtpTimestamp,
    /// When the server sent this response (T3).
    pub transmit: NtpTimestamp,
    /// New cookies from the encrypted part, 1 to 1 + placeholders.
    pub cookies: Vec<Cookie>,
}

/// Leap indicator of a synchronized server (RFC 5905 section 7.3, figure 9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeapIndicator {
    /// 0: no leap second today.
    NoWarning,
    /// 1: the last minute of the day has 61 seconds.
    InsertSecond,
    /// 2: the last minute of the day has 59 seconds.
    DeleteSecond,
}

/// The kiss code of a Kiss-o'-Death packet: the reference ID as 4 ASCII
/// octets (RFC 5905 section 7.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KissCode {
    /// "RATE": poll less often (RFC 5905 section 7.4).
    Rate,
    /// "NTSN": the server could not check our cookie or request; run NTS-KE
    /// again (RFC 8915 section 5.7).
    Ntsn,
    /// "DENY": access denied; stop using this server (RFC 5905 section 7.4).
    Deny,
    /// "RSTR": access restricted; stop using this server (RFC 5905 section 7.4).
    Rstr,
    /// Any other code, as sent.
    Other([u8; 4]),
}

impl KissCode {
    fn from_reference_id(id: [u8; 4]) -> Self {
        match &id {
            b"RATE" => Self::Rate,
            b"NTSN" => Self::Ntsn,
            b"DENY" => Self::Deny,
            b"RSTR" => Self::Rstr,
            _ => Self::Other(id),
        }
    }
}

/// Why a request could not be built or a response was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NtpError {
    /// More than [`MAX_PLACEHOLDERS`] placeholders asked for.
    TooManyPlaceholders,
    /// The request would be longer than [`MAX_REQUEST_LEN`] octets.
    RequestTooLong,
    /// The AEAD refused to encrypt (does not happen with our inputs).
    EncryptFailed,
    /// This request already accepted a response; a second one is a replay.
    AlreadyAnswered,
    /// Shorter than the 48-octet header.
    TooShort,
    /// Longer than [`MAX_RESPONSE_LEN`] octets.
    TooLong,
    /// Not NTP version 4.
    BadVersion(u8),
    /// Not mode 4 (server).
    BadMode(u8),
    /// The origin timestamp is not our transmit timestamp (RFC 5905 section 8).
    OriginMismatch,
    /// An extension field before the authenticator breaks RFC 7822: length
    /// not a multiple of 4, under 16 octets, or past the end of the packet.
    BadExtensionField,
    /// Two Unique Identifier fields.
    DuplicateUniqueId,
    /// No Unique Identifier before the authenticator (RFC 8915 section 5.7).
    MissingUniqueId,
    /// The Unique Identifier is not ours (RFC 8915 section 5.7).
    UniqueIdMismatch,
    /// No authenticator in a response that is not a KoD.
    MissingAuthenticator,
    /// The authenticator field is malformed: a zero-length nonce, a
    /// ciphertext shorter than the tag, lengths past the field, or non-zero
    /// padding (RFC 8915 section 5.6).
    BadAuthenticator,
    /// The authenticator does not verify with the S2C key.
    AuthenticationFailed,
    /// An encrypted extension field is malformed (RFC 8915 section 5.6).
    BadEncryptedField,
    /// A cookie is empty or longer than [`MAX_COOKIE_LEN`] octets.
    BadCookie,
    /// More cookies than one plus our placeholders (RFC 8915 section 5.7:
    /// MUST NOT exceed).
    TooManyCookies,
    /// No cookie in the encrypted part (RFC 8915 section 5.7: one or more).
    NoCookies,
    /// Leap indicator 3: the server clock is not synchronized
    /// (RFC 5905 section 7.3).
    Unsynchronized,
    /// Stratum above 15 (RFC 5905 section 7.3).
    BadStratum(u8),
}

impl fmt::Display for NtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyPlaceholders => write!(f, "more than {MAX_PLACEHOLDERS} cookie placeholders"),
            Self::RequestTooLong => write!(f, "NTS request longer than {MAX_REQUEST_LEN} octets"),
            Self::EncryptFailed => f.write_str("AES-SIV encryption failed"),
            Self::AlreadyAnswered => f.write_str("request already answered (replay)"),
            Self::TooShort => f.write_str("NTP packet shorter than its header"),
            Self::TooLong => write!(f, "NTP packet longer than {MAX_RESPONSE_LEN} octets"),
            Self::BadVersion(v) => write!(f, "NTP version {v}, not 4"),
            Self::BadMode(m) => write!(f, "NTP mode {m}, not 4 (server)"),
            Self::OriginMismatch => f.write_str("origin timestamp is not our transmit timestamp"),
            Self::BadExtensionField => f.write_str("malformed NTP extension field"),
            Self::DuplicateUniqueId => f.write_str("two Unique Identifier fields"),
            Self::MissingUniqueId => f.write_str("no authenticated Unique Identifier"),
            Self::UniqueIdMismatch => f.write_str("Unique Identifier is not ours"),
            Self::MissingAuthenticator => f.write_str("no NTS authenticator"),
            Self::BadAuthenticator => f.write_str("malformed NTS authenticator"),
            Self::AuthenticationFailed => f.write_str("NTS authenticator does not verify"),
            Self::BadEncryptedField => f.write_str("malformed encrypted extension field"),
            Self::BadCookie => f.write_str("cookie empty or too long"),
            Self::TooManyCookies => f.write_str("more cookies than placeholders plus one"),
            Self::NoCookies => f.write_str("no new cookie"),
            Self::Unsynchronized => f.write_str("server clock unsynchronized (leap indicator 3)"),
            Self::BadStratum(s) => write!(f, "stratum {s} above 15"),
        }
    }
}

impl core::error::Error for NtpError {}

/// The NTP header (RFC 5905 section 7.3).
struct Header {
    leap: u8,
    version: u8,
    mode: u8,
    stratum: u8,
    precision: i8,
    root_delay: NtpShort,
    root_dispersion: NtpShort,
    reference_id: [u8; 4],
    reference: NtpTimestamp,
    origin: NtpTimestamp,
    receive: NtpTimestamp,
    transmit: NtpTimestamp,
}

impl Header {
    fn parse(b: &[u8; HEADER_LEN]) -> Option<Self> {
        let mut r = Reader::new(b);
        let [first, stratum, _poll, precision] = r.array::<4>()?;
        let root_delay = NtpShort::from_bits(u32::from_be_bytes(r.array()?));
        let root_dispersion = NtpShort::from_bits(u32::from_be_bytes(r.array()?));
        let reference_id = r.array::<4>()?;
        let reference = NtpTimestamp::from_be_bytes(r.array()?);
        let origin = NtpTimestamp::from_be_bytes(r.array()?);
        let receive = NtpTimestamp::from_be_bytes(r.array()?);
        let transmit = NtpTimestamp::from_be_bytes(r.array()?);
        Some(Self {
            leap: first >> 6,
            version: (first >> 3) & 0x07,
            mode: first & 0x07,
            stratum,
            precision: precision as i8,
            root_delay,
            root_dispersion,
            reference_id,
            reference,
            origin,
            receive,
            transmit,
        })
    }
}

/// The NTS authenticator of a response, located in the packet.
struct Authenticator<'a> {
    /// Where the field starts, counted from the start of the packet. The
    /// associated data is everything before it (RFC 8915 section 5.6).
    start: usize,
    nonce: &'a [u8],
    ciphertext: &'a [u8],
}

/// Reads the body of an authenticator field (RFC 8915 section 5.6): Nonce
/// Length, Ciphertext Length, the nonce and the ciphertext each zero-padded
/// to 4 octets, then Additional Padding.
fn parse_authenticator(body: &[u8], start: usize) -> Result<Authenticator<'_>, NtpError> {
    let bad = NtpError::BadAuthenticator;
    let mut r = Reader::new(body);
    let nonce_len = usize::from(r.u16().ok_or(bad)?);
    let ciphertext_len = usize::from(r.u16().ok_or(bad)?);
    // RFC 5297 section 6.1: N_MIN is 1 octet. The ciphertext holds at least
    // the 16-octet tag.
    if nonce_len == 0 || ciphertext_len < siv::TAG_LEN {
        return Err(bad);
    }
    let nonce_field = r.take(pad4(nonce_len).ok_or(bad)?).ok_or(bad)?;
    let (nonce, nonce_pad) = nonce_field.split_at_checked(nonce_len).ok_or(bad)?;
    let ciphertext_field = r.take(pad4(ciphertext_len).ok_or(bad)?).ok_or(bad)?;
    let (ciphertext, ciphertext_pad) = ciphertext_field.split_at_checked(ciphertext_len).ok_or(bad)?;
    // The padding is zero (section 5.6) and outside the AEAD input, so a
    // change to it would not fail the tag check. It is checked here instead.
    // Mode 4 packets need no Additional Padding; if there is some, it must
    // be zero too.
    if !all_zero(nonce_pad) || !all_zero(ciphertext_pad) || !all_zero(r.rest()) {
        return Err(bad);
    }
    Ok(Authenticator { start, nonce, ciphertext })
}

/// The extension fields of a response up to the authenticator.
struct Fields<'a> {
    unique_id: Option<&'a [u8]>,
    authenticator: Option<Authenticator<'a>>,
}

/// Walks the extension fields after the header (RFC 7822 section 7.5).
/// It stops at the first authenticator: RFC 8915 section 5.7 says the client
/// MUST discard unauthenticated extension fields, which are the ones after
/// it, so they are not read at all. Unknown fields before it, and NTS fields
/// a server should not send in the clear (cookies, placeholders), are
/// skipped (RFC 7822 section 7.5: SHOULD ignore an unknown type).
fn parse_fields(fields: &[u8]) -> Result<Fields<'_>, NtpError> {
    let bad = NtpError::BadExtensionField;
    let mut r = Reader::new(fields);
    let mut out = Fields { unique_id: None, authenticator: None };
    while !r.is_empty() {
        let start = HEADER_LEN + (fields.len() - r.remaining());
        let field_type = r.u16().ok_or(bad)?;
        let len = usize::from(r.u16().ok_or(bad)?);
        // RFC 7822 section 7.5: the length counts the whole field, which is
        // zero-padded to a multiple of 4; section 7.5.1.4: at least 16.
        if len % 4 != 0 || len < MIN_FIELD_LEN {
            return Err(bad);
        }
        let body = r.take(len - FIELD_HEADER_LEN).ok_or(bad)?;
        match field_type {
            field_type::UNIQUE_IDENTIFIER => {
                if out.unique_id.is_some() {
                    return Err(NtpError::DuplicateUniqueId);
                }
                out.unique_id = Some(body);
            }
            field_type::NTS_AUTHENTICATOR => {
                out.authenticator = Some(parse_authenticator(body, start)?);
                break;
            }
            _ => {}
        }
    }
    Ok(out)
}

/// The cookies in the decrypted part. RFC 8915 section 5.6: it holds
/// extension fields in RFC 7822 form that may be shorter than 16 octets but
/// are a multiple of 4. Fields other than NTS Cookie are skipped.
fn encrypted_cookies(plaintext: &[u8], max: usize) -> Result<Vec<Cookie>, NtpError> {
    let bad = NtpError::BadEncryptedField;
    let mut r = Reader::new(plaintext);
    let mut cookies = Vec::with_capacity(max);
    while !r.is_empty() {
        let field_type = r.u16().ok_or(bad)?;
        let len = usize::from(r.u16().ok_or(bad)?);
        if len % 4 != 0 || len < FIELD_HEADER_LEN {
            return Err(bad);
        }
        let body = r.take(len - FIELD_HEADER_LEN).ok_or(bad)?;
        if field_type == field_type::NTS_COOKIE {
            // Section 5.7: no more than one plus the placeholders we sent.
            if cookies.len() >= max {
                return Err(NtpError::TooManyCookies);
            }
            cookies.push(Cookie::new(body).ok_or(NtpError::BadCookie)?);
        }
    }
    Ok(cookies)
}

impl PendingRequest {
    /// The transmit timestamp the request carries.
    pub fn transmit(&self) -> NtpTimestamp {
        self.transmit
    }

    /// True once a response was accepted.
    pub fn is_answered(&self) -> bool {
        self.answered
    }

    /// Checks a response to this request with the S2C key.
    ///
    /// In order: length, version 4 and mode 4, origin timestamp equal to our
    /// transmit timestamp, the extension fields, and our Unique Identifier
    /// before the authenticator (constant-time compares). Stratum 0 then
    /// gives a [`Response::KissOfDeath`] and no time. Otherwise the
    /// authenticator must verify with the S2C key over the header and the
    /// fields before it; then the decrypted fields give the new cookies,
    /// and leap indicator 3 and stratum above 15 are refused.
    ///
    /// A refused response changes nothing, so the real response can still
    /// come. After one is accepted every further one is refused as a replay.
    pub fn verify_response(&mut self, s2c: &S2cKey, packet: &[u8]) -> Result<Response, NtpError> {
        if self.answered {
            return Err(NtpError::AlreadyAnswered);
        }
        if packet.len() > MAX_RESPONSE_LEN {
            return Err(NtpError::TooLong);
        }
        let (head, fields) = packet.split_first_chunk::<HEADER_LEN>().ok_or(NtpError::TooShort)?;
        let h = Header::parse(head).ok_or(NtpError::TooShort)?;
        if h.version != VERSION {
            return Err(NtpError::BadVersion(h.version));
        }
        if h.mode != MODE_SERVER {
            return Err(NtpError::BadMode(h.mode));
        }
        // RFC 5905 section 8: a response whose origin timestamp is not the
        // transmit timestamp we sent is bogus. Ours is random, so this is
        // also a 64-bit check against forged responses.
        if !bool::from(h.origin.to_bits().ct_eq(&self.transmit.to_bits())) {
            return Err(NtpError::OriginMismatch);
        }
        let fields = parse_fields(fields)?;
        // RFC 8915 section 5.7: the Unique Identifier must match ours, in a
        // normal response and in a KoD.
        let unique_id = fields.unique_id.ok_or(NtpError::MissingUniqueId)?;
        if !bool::from(unique_id.ct_eq(&self.unique_id[..])) {
            return Err(NtpError::UniqueIdMismatch);
        }

        if h.stratum == 0 {
            // A Kiss-o'-Death (RFC 5905 section 7.4): no time in it. RFC 8915
            // section 5.7 requires the matching Unique Identifier only after
            // the server has sent authentic responses; we always require it.
            // An authenticator, if there is one, is not checked: stripping it
            // would give the same KoD.
            self.answered = true;
            return Ok(Response::KissOfDeath(KissCode::from_reference_id(h.reference_id)));
        }

        let auth = fields.authenticator.ok_or(NtpError::MissingAuthenticator)?;
        let ad = packet.get(..auth.start).ok_or(NtpError::BadExtensionField)?;
        let plaintext =
            siv::open(s2c.bytes(), ad, auth.nonce, auth.ciphertext).ok_or(NtpError::AuthenticationFailed)?;
        let cookies = encrypted_cookies(&plaintext, self.placeholders + 1)?;

        if h.leap == LEAP_UNSYNCHRONIZED {
            return Err(NtpError::Unsynchronized);
        }
        let leap = match h.leap {
            1 => LeapIndicator::InsertSecond,
            2 => LeapIndicator::DeleteSecond,
            _ => LeapIndicator::NoWarning,
        };
        if h.stratum > MAX_STRATUM {
            return Err(NtpError::BadStratum(h.stratum));
        }
        if cookies.is_empty() {
            return Err(NtpError::NoCookies);
        }

        self.answered = true;
        Ok(Response::Time(TimeSample {
            leap,
            stratum: h.stratum,
            precision: h.precision,
            root_delay: h.root_delay,
            root_dispersion: h.root_dispersion,
            reference: h.reference,
            origin: h.origin,
            receive: h.receive,
            transmit: h.transmit,
            cookies,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cookie(len: usize) -> Cookie {
        Cookie::new(&alloc::vec![0x5a; len]).unwrap()
    }

    #[test]
    fn placeholders_fit_in_1280_octets() {
        // 48 + 36 + 40 + 8 * (4 + 104) = 988: a cookie of the RFC's
        // suggested size leaves room for all seven.
        assert_eq!(max_placeholders(&cookie(104)), 7);
        assert_eq!(request_len(104, 7), Some(988));
        // 48 + 36 + 40 + (p + 1) * (4 + 1024) <= 1280 only for p = 0.
        assert_eq!(max_placeholders(&cookie(MAX_COOKIE_LEN)), 0);
        assert_eq!(request_len(MAX_COOKIE_LEN, 0), Some(1152));
        // 48 + 36 + 40 + 4 * 288 = 1276.
        assert_eq!(max_placeholders(&cookie(284)), 3);
    }

    #[test]
    fn kiss_codes() {
        assert_eq!(KissCode::from_reference_id(*b"RATE"), KissCode::Rate);
        assert_eq!(KissCode::from_reference_id(*b"NTSN"), KissCode::Ntsn);
        assert_eq!(KissCode::from_reference_id(*b"DENY"), KissCode::Deny);
        assert_eq!(KissCode::from_reference_id(*b"RSTR"), KissCode::Rstr);
        assert_eq!(KissCode::from_reference_id(*b"INIT"), KissCode::Other(*b"INIT"));
    }

    #[test]
    fn header_fields() {
        let mut b = [0u8; HEADER_LEN];
        b[0] = 0b10_100_100;
        b[1] = 2;
        b[3] = 0xe9;
        b[4..8].copy_from_slice(&[0, 1, 0, 0]);
        b[12..16].copy_from_slice(b"GPS\0");
        b[24..32].copy_from_slice(&7u64.to_be_bytes());
        let h = Header::parse(&b).unwrap();
        assert_eq!((h.leap, h.version, h.mode, h.stratum, h.precision), (2, 4, 4, 2, -23));
        assert_eq!(h.root_delay.to_bits(), 0x0001_0000);
        assert_eq!(&h.reference_id, b"GPS\0");
        assert_eq!(h.origin.to_bits(), 7);
    }
}
