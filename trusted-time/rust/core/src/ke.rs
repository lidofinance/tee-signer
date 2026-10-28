//! NTS Key Establishment records (RFC 8915 section 4) and the TLS exporter
//! values of the two keys (section 5.1).
//!
//! The TLS 1.3 connection is not here. In the clouds Go runs it (port
//! [`NTS_KE_PORT`], ALPN [`ALPN`]), writes [`build_request`], reads until
//! [`response_length`] says the message is complete, checks it with
//! [`parse_response`], and exports the keys with [`EXPORTER_LABEL`] and
//! [`exporter_context`]. On the boards a trusted app can do the same with
//! TLS inside it.
//!
//! A message is a list of records: a critical bit, a 15-bit record type, a
//! 16-bit body length, then the body (RFC 8915 section 4). The last record
//! is End of Message.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::bytes::Reader;
use crate::cookie::{Cookie, MAX_COOKIE_LEN};

/// TCP port of NTS-KE (RFC 8915 section 4, registered in section 7.1).
pub const NTS_KE_PORT: u16 = 4460;
/// TLS ALPN protocol ID of NTS-KE (RFC 8915 section 4, registered in section 7.2).
pub const ALPN: &[u8] = b"ntske/1";
/// Label for the TLS exporter (RFC 8915 section 5.1, registered in section 7.3).
pub const EXPORTER_LABEL: &str = "EXPORTER-network-time-security";
/// Length of each exported key: the key length of AEAD_AES_SIV_CMAC_256
/// (RFC 5297 section 6.1).
pub const KEY_LEN: usize = crate::keys::KEY_LEN;

/// Next Protocol ID of NTPv4 (RFC 8915 section 4.1.2, registry in section 7.7).
pub const PROTOCOL_NTPV4: u16 = 0;
/// AEAD algorithm ID of AEAD_AES_SIV_CMAC_256, which every server must
/// support (RFC 8915 section 4.1.5). It is the only one we offer.
pub const AEAD_AES_SIV_CMAC_256: u16 = 15;
/// NTP port when the response has no Port Negotiation record
/// (RFC 8915 section 4.1.8).
pub const DEFAULT_NTP_PORT: u16 = 123;

/// Record types (RFC 8915 section 4.1, registry in section 7.6).
pub mod record_type {
    /// Section 4.1.1.
    pub const END_OF_MESSAGE: u16 = 0;
    /// Section 4.1.2.
    pub const NEXT_PROTOCOL: u16 = 1;
    /// Section 4.1.3.
    pub const ERROR: u16 = 2;
    /// Section 4.1.4.
    pub const WARNING: u16 = 3;
    /// Section 4.1.5.
    pub const AEAD_ALGORITHM: u16 = 4;
    /// Section 4.1.6.
    pub const NEW_COOKIE: u16 = 5;
    /// Section 4.1.7.
    pub const SERVER: u16 = 6;
    /// Section 4.1.8.
    pub const PORT: u16 = 7;
}

/// Error codes of the Error record (RFC 8915 section 4.1.3, registry in
/// section 7.8).
pub mod error_code {
    /// The server did not know a record that had the critical bit set.
    pub const UNRECOGNIZED_CRITICAL_RECORD: u16 = 0;
    /// The request was malformed.
    pub const BAD_REQUEST: u16 = 1;
    /// The server failed; the client may try again later.
    pub const INTERNAL_SERVER_ERROR: u16 = 2;
}

/// The critical bit, the top bit of the type field (RFC 8915 section 4).
const CRITICAL: u16 = 0x8000;
/// Record header: type and body length, two octets each (RFC 8915 section 4).
const RECORD_HEADER_LEN: usize = 4;

/// The longest response accepted, in octets. RFC 8915 section 4: clients
/// SHOULD accept responses of at least 65536 octets.
pub const MAX_RESPONSE_LEN: usize = 65536;
/// The most records accepted in one response (our cap). A normal response
/// has about 12: next protocol, AEAD, eight cookies, end of message, and
/// maybe server and port.
pub const MAX_RECORDS: usize = 64;
/// The longest record body accepted, for every record type (our cap). It
/// equals [`MAX_COOKIE_LEN`], the longest body of a known record.
pub const MAX_RECORD_BODY_LEN: usize = MAX_COOKIE_LEN;
/// Cookies kept from one response. RFC 8915 section 4.1.6: servers SHOULD
/// send eight. Further ones are counted in `cookies_dropped`, not kept.
pub const MAX_COOKIES: usize = 8;
/// The longest server name accepted: a DNS name is at most 255 octets
/// (RFC 1035 section 2.3.4), and an address in text is shorter.
pub const MAX_SERVER_NAME_LEN: usize = 255;
/// Length of the request of [`build_request`].
pub const REQUEST_LEN: usize = 16;

/// Which of the two keys an export is for (RFC 8915 section 5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyDirection {
    /// The C2S key: client to server.
    ClientToServer,
    /// The S2C key: server to client.
    ServerToClient,
}

/// The context of the TLS exporter (RFC 8915 section 5.1): the Next Protocol
/// ID of NTPv4 (two zero octets), the AEAD ID in network byte order, then
/// 0x00 for the C2S key or 0x01 for the S2C key. This crate only negotiates
/// AEAD_AES_SIV_CMAC_256, so the AEAD ID is 15.
pub const fn exporter_context(direction: KeyDirection) -> [u8; 5] {
    let [p0, p1] = PROTOCOL_NTPV4.to_be_bytes();
    let [a0, a1] = AEAD_AES_SIV_CMAC_256.to_be_bytes();
    let d = match direction {
        KeyDirection::ClientToServer => 0x00,
        KeyDirection::ServerToClient => 0x01,
    };
    [p0, p1, a0, a1, d]
}

const fn record_header(critical: bool, record_type: u16, body_len: u16) -> [u8; RECORD_HEADER_LEN] {
    let t = if critical { record_type | CRITICAL } else { record_type };
    let [t0, t1] = t.to_be_bytes();
    let [l0, l1] = body_len.to_be_bytes();
    [t0, t1, l0, l1]
}

/// The client request (RFC 8915 section 4), 16 octets:
///
/// - NTS Next Protocol Negotiation with NTPv4. The critical bit MUST be set
///   (section 4.1.2).
/// - AEAD Algorithm Negotiation with AEAD_AES_SIV_CMAC_256. The critical bit
///   MAY be set (section 4.1.5); we set it, because a server that does not
///   know the record cannot serve us.
/// - End of Message. The critical bit MUST be set and the body is empty
///   (section 4.1.1).
pub const fn build_request() -> [u8; REQUEST_LEN] {
    let [n0, n1, n2, n3] = record_header(true, record_type::NEXT_PROTOCOL, 2);
    let [p0, p1] = PROTOCOL_NTPV4.to_be_bytes();
    let [a0, a1, a2, a3] = record_header(true, record_type::AEAD_ALGORITHM, 2);
    let [i0, i1] = AEAD_AES_SIV_CMAC_256.to_be_bytes();
    let [e0, e1, e2, e3] = record_header(true, record_type::END_OF_MESSAGE, 0);
    [n0, n1, n2, n3, p0, p1, a0, a1, a2, a3, i0, i1, e0, e1, e2, e3]
}

/// What a valid server response gives the client. The next protocol is
/// NTPv4 and the AEAD is AEAD_AES_SIV_CMAC_256; anything else is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeResponse {
    /// The first [`MAX_COOKIES`] cookies, in the order the server sent them.
    /// At least one.
    pub cookies: Vec<Cookie>,
    /// Further valid cookies the server sent; not kept.
    pub cookies_dropped: usize,
    /// The NTP server to use, if the server named one (section 4.1.7). An
    /// IPv4 or IPv6 address or a domain name, checked to contain only
    /// letters, digits, '.', '-' and ':'. If `None`, use the address of the
    /// NTS-KE server.
    pub server: Option<String>,
    /// The NTP port, if the server named one (section 4.1.8).
    pub port: Option<u16>,
}

impl KeResponse {
    /// The NTP port to use: the negotiated one or 123 (section 4.1.8).
    pub fn ntp_port(&self) -> u16 {
        self.port.unwrap_or(DEFAULT_NTP_PORT)
    }
}

/// Why a response was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeError {
    /// The message ends before End of Message or inside a record.
    Truncated,
    /// More than [`MAX_RESPONSE_LEN`] octets.
    TooLong,
    /// More than [`MAX_RECORDS`] records.
    TooManyRecords,
    /// A record body longer than [`MAX_RECORD_BODY_LEN`].
    RecordTooLong {
        /// The record type, without the critical bit.
        record_type: u16,
    },
    /// Octets after End of Message (section 4.1.1: it is the final record).
    TrailingData,
    /// End of Message without the critical bit or with a body (section 4.1.1).
    BadEndOfMessage,
    /// A known record whose body has the wrong length or content.
    BadRecordBody {
        /// The record type.
        record_type: u16,
    },
    /// A record that MUST have the critical bit set does not (section 4.1.2).
    CriticalBitMissing {
        /// The record type.
        record_type: u16,
    },
    /// An unknown record with the critical bit set (section 4).
    UnknownCriticalRecord {
        /// The record type.
        record_type: u16,
    },
    /// A second record of a type that may occur once.
    DuplicateRecord {
        /// The record type.
        record_type: u16,
    },
    /// A required record is missing: next protocol, AEAD or cookie.
    MissingRecord {
        /// The record type.
        record_type: u16,
    },
    /// The server sent an Error record (section 4.1.3). The client must not
    /// go on to NTP with this session's keys.
    ServerError(u16),
    /// The server sent a Warning record. No warning codes are defined, and
    /// unknown codes MUST be treated as errors (section 4.1.4).
    ServerWarning(u16),
    /// The server accepts none of the protocols we offered (empty list,
    /// section 4.1.2).
    NoCommonProtocol,
    /// The server named a protocol we did not offer (section 4.1.2: the
    /// response is a subset of the request).
    WrongProtocol(u16),
    /// The server accepts none of the AEAD algorithms we offered (empty
    /// list, section 4.1.5).
    NoCommonAead,
    /// The server chose an AEAD algorithm we did not offer (section 4.1.5).
    WrongAead(u16),
}

impl fmt::Display for KeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("NTS-KE response ends early"),
            Self::TooLong => write!(f, "NTS-KE response longer than {MAX_RESPONSE_LEN} octets"),
            Self::TooManyRecords => write!(f, "NTS-KE response has more than {MAX_RECORDS} records"),
            Self::RecordTooLong { record_type } => write!(f, "NTS-KE record {record_type} longer than {MAX_RECORD_BODY_LEN} octets"),
            Self::TrailingData => f.write_str("NTS-KE response has data after End of Message"),
            Self::BadEndOfMessage => f.write_str("NTS-KE End of Message without critical bit or with a body"),
            Self::BadRecordBody { record_type } => write!(f, "NTS-KE record {record_type} has a bad body"),
            Self::CriticalBitMissing { record_type } => write!(f, "NTS-KE record {record_type} without critical bit"),
            Self::UnknownCriticalRecord { record_type } => write!(f, "NTS-KE unknown critical record {record_type}"),
            Self::DuplicateRecord { record_type } => write!(f, "NTS-KE record {record_type} sent twice"),
            Self::MissingRecord { record_type } => write!(f, "NTS-KE record {record_type} missing"),
            Self::ServerError(code) => write!(f, "NTS-KE server error {code}"),
            Self::ServerWarning(code) => write!(f, "NTS-KE server warning {code}"),
            Self::NoCommonProtocol => f.write_str("NTS-KE server offers no common protocol"),
            Self::WrongProtocol(id) => write!(f, "NTS-KE server chose protocol {id}, not offered"),
            Self::NoCommonAead => f.write_str("NTS-KE server offers no common AEAD algorithm"),
            Self::WrongAead(id) => write!(f, "NTS-KE server chose AEAD {id}, not offered"),
        }
    }
}

impl core::error::Error for KeError {}

struct Record<'a> {
    critical: bool,
    record_type: u16,
    body: &'a [u8],
}

/// Reads one record. `Ok(None)` if the buffer ends inside it.
fn read_record<'a>(r: &mut Reader<'a>) -> Result<Option<Record<'a>>, KeError> {
    let Some(head) = r.array::<RECORD_HEADER_LEN>() else {
        return Ok(None);
    };
    let [t0, t1, l0, l1] = head;
    let t = u16::from_be_bytes([t0, t1]);
    let record_type = t & !CRITICAL;
    let len = usize::from(u16::from_be_bytes([l0, l1]));
    if len > MAX_RECORD_BODY_LEN {
        return Err(KeError::RecordTooLong { record_type });
    }
    Ok(r.take(len).map(|body| Record { critical: t & CRITICAL != 0, record_type, body }))
}

/// The length of the complete response at the start of `buf`: `Ok(Some(n))`
/// once the first n octets end with End of Message, `Ok(None)` if more
/// octets are needed. It checks only the framing and the caps; pass
/// `&buf[..n]` to [`parse_response`] for the rest. Octets after the n are
/// not looked at.
pub fn response_length(buf: &[u8]) -> Result<Option<usize>, KeError> {
    let mut r = Reader::new(buf);
    let mut count = 0usize;
    loop {
        let Some(rec) = read_record(&mut r)? else {
            return if buf.len() >= MAX_RESPONSE_LEN { Err(KeError::TooLong) } else { Ok(None) };
        };
        count += 1;
        if count > MAX_RECORDS {
            return Err(KeError::TooManyRecords);
        }
        let n = buf.len() - r.remaining();
        if n > MAX_RESPONSE_LEN {
            return Err(KeError::TooLong);
        }
        if rec.record_type == record_type::END_OF_MESSAGE {
            return Ok(Some(n));
        }
    }
}

/// Checks a complete server response and returns what the client needs.
///
/// Refused: an Error or Warning record, an unknown record with the critical
/// bit, a missing Next Protocol, AEAD or New Cookie record, a protocol other
/// than NTPv4, an AEAD other than AEAD_AES_SIV_CMAC_256, a duplicate of a
/// record that may occur once, a bad body, and anything over the caps.
/// Unknown records without the critical bit are skipped (section 4).
pub fn parse_response(buf: &[u8]) -> Result<KeResponse, KeError> {
    if buf.len() > MAX_RESPONSE_LEN {
        return Err(KeError::TooLong);
    }
    let mut r = Reader::new(buf);
    let mut count = 0usize;
    let mut next_protocol = false;
    let mut aead = false;
    let mut out = KeResponse { cookies: Vec::new(), cookies_dropped: 0, server: None, port: None };

    loop {
        let rec = read_record(&mut r)?.ok_or(KeError::Truncated)?;
        count += 1;
        if count > MAX_RECORDS {
            return Err(KeError::TooManyRecords);
        }
        let record_type = rec.record_type;
        let bad_body = KeError::BadRecordBody { record_type };
        let duplicate = KeError::DuplicateRecord { record_type };
        match record_type {
            record_type::END_OF_MESSAGE => {
                // Section 4.1.1: critical bit set, empty body, final record.
                if !rec.critical || !rec.body.is_empty() {
                    return Err(KeError::BadEndOfMessage);
                }
                if !r.is_empty() {
                    return Err(KeError::TrailingData);
                }
                break;
            }
            record_type::NEXT_PROTOCOL => {
                // Section 4.1.2: exactly once, critical bit set, a list of
                // 16-bit IDs that is a subset of what we offered (NTPv4).
                if !rec.critical {
                    return Err(KeError::CriticalBitMissing { record_type });
                }
                if next_protocol {
                    return Err(duplicate);
                }
                next_protocol = true;
                let ids = id_list(rec.body).ok_or(bad_body)?;
                if ids.len() == 0 {
                    return Err(KeError::NoCommonProtocol);
                }
                for id in ids {
                    if id != PROTOCOL_NTPV4 {
                        return Err(KeError::WrongProtocol(id));
                    }
                }
            }
            record_type::ERROR => {
                // Section 4.1.3: a 2-octet code. The client discards the keys
                // and does not go on.
                return Err(KeError::ServerError(code(rec.body).ok_or(bad_body)?));
            }
            record_type::WARNING => {
                // Section 4.1.4: no codes are defined and unknown codes MUST
                // be treated as errors, so every warning is one.
                return Err(KeError::ServerWarning(code(rec.body).ok_or(bad_body)?));
            }
            record_type::AEAD_ALGORITHM => {
                // Section 4.1.5: exactly once when NTPv4 is negotiated, at
                // most one ID in a response, chosen from what we offered.
                if aead {
                    return Err(duplicate);
                }
                aead = true;
                let mut ids = id_list(rec.body).ok_or(bad_body)?;
                match (ids.next(), ids.next()) {
                    (None, _) => return Err(KeError::NoCommonAead),
                    (Some(id), None) if id == AEAD_AES_SIV_CMAC_256 => {}
                    (Some(id), None) => return Err(KeError::WrongAead(id)),
                    (Some(_), Some(_)) => return Err(bad_body),
                }
            }
            record_type::NEW_COOKIE => {
                // Section 4.1.6: opaque to the client; at least one.
                let cookie = Cookie::new(rec.body).ok_or(bad_body)?;
                if out.cookies.len() < MAX_COOKIES {
                    out.cookies.push(cookie);
                } else {
                    out.cookies_dropped += 1;
                }
            }
            record_type::SERVER => {
                // Section 4.1.7: at most one; an ASCII IPv4 or IPv6 address
                // (no zone ID) or a domain name.
                if out.server.is_some() {
                    return Err(duplicate);
                }
                out.server = Some(server_name(rec.body).ok_or(bad_body)?);
            }
            record_type::PORT => {
                // Section 4.1.8: a 16-bit port. The RFC sets no count; two
                // ports are ambiguous, so a second one is refused. Port 0 is
                // not a port a server listens on.
                if out.port.is_some() {
                    return Err(duplicate);
                }
                match code(rec.body) {
                    Some(0) | None => return Err(bad_body),
                    Some(port) => out.port = Some(port),
                }
            }
            _ => {
                // Section 4: an unknown record is ignored without the
                // critical bit and is an error with it.
                if rec.critical {
                    return Err(KeError::UnknownCriticalRecord { record_type });
                }
            }
        }
    }

    if !next_protocol {
        return Err(KeError::MissingRecord { record_type: record_type::NEXT_PROTOCOL });
    }
    if !aead {
        return Err(KeError::MissingRecord { record_type: record_type::AEAD_ALGORITHM });
    }
    // Section 4.1.6: servers MUST send at least one cookie.
    if out.cookies.is_empty() {
        return Err(KeError::MissingRecord { record_type: record_type::NEW_COOKIE });
    }
    Ok(out)
}

/// The 16-bit IDs of a Next Protocol or AEAD record body, or `None` if the
/// body length is odd.
fn id_list(body: &[u8]) -> Option<impl ExactSizeIterator<Item = u16> + '_> {
    let (pairs, rest) = body.as_chunks::<2>();
    rest.is_empty().then(|| pairs.iter().map(|p| u16::from_be_bytes(*p)))
}

/// A body of exactly two octets as a 16-bit number.
fn code(body: &[u8]) -> Option<u16> {
    <[u8; 2]>::try_from(body).ok().map(u16::from_be_bytes)
}

/// The NTPv4 server name of section 4.1.7, if it has 1 to
/// [`MAX_SERVER_NAME_LEN`] octets of letters, digits, '.', '-' and ':'.
/// That covers dotted IPv4, IPv6 text without a zone ID, and A-labels of a
/// domain name. Go resolves or parses it.
fn server_name(body: &[u8]) -> Option<String> {
    let ok = !body.is_empty()
        && body.len() <= MAX_SERVER_NAME_LEN
        && body.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b':');
    if !ok {
        return None;
    }
    core::str::from_utf8(body).ok().map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exporter_values() {
        assert_eq!(EXPORTER_LABEL, "EXPORTER-network-time-security");
        assert_eq!(exporter_context(KeyDirection::ClientToServer), [0, 0, 0, 15, 0]);
        assert_eq!(exporter_context(KeyDirection::ServerToClient), [0, 0, 0, 15, 1]);
        assert_eq!(KEY_LEN, 32);
    }

    #[test]
    fn request_bytes() {
        assert_eq!(
            build_request(),
            [0x80, 0x01, 0x00, 0x02, 0x00, 0x00, 0x80, 0x04, 0x00, 0x02, 0x00, 0x0f, 0x80, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn id_lists() {
        assert!(id_list(&[0]).is_none());
        assert_eq!(id_list(&[]).map(|i| i.len()), Some(0));
        let ids: Vec<u16> = id_list(&[0, 1, 0x80, 2]).unwrap().collect();
        assert_eq!(ids, [1, 0x8002]);
    }

    #[test]
    fn server_names() {
        for good in ["192.0.2.1", "2001:db8::1", "time.example.com", "xn--bcher-kva.example"] {
            assert_eq!(server_name(good.as_bytes()).as_deref(), Some(good));
        }
        for bad in ["", "fe80::1%eth0", "a b", "a/b", "ex\u{e4}mple.com", "a\0b"] {
            assert_eq!(server_name(bad.as_bytes()), None, "{bad}");
        }
        assert!(server_name(&[b'a'; 255]).is_some());
        assert!(server_name(&[b'a'; 256]).is_none());
    }
}
