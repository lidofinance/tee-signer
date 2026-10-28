//! The `reason` numbers of the C functions and their texts.
//!
//! A reason is `kind << 16 | value`: `kind` names the error variant (1 and
//! up, per error type), `value` is its number if it has one (a record type,
//! a server error code, a version, a stratum), else 0.

use core::ffi::{CStr, c_int};

use signer_nts_core::ke::KeError;
use signer_nts_core::ntp::{KissCode, NtpError};
use signer_nts_core::quorum::QuorumError;
use signer_nts_core::sample::SampleError;

use crate::code::*;

/// RFC 8915 section 4, the same bytes as `ke::ALPN` (a test checks).
pub const ALPN: &CStr = c"ntske/1";
/// RFC 8915 section 5.1, the same as `ke::EXPORTER_LABEL` (a test checks).
pub const EXPORTER_LABEL: &CStr = c"EXPORTER-network-time-security";

fn pack(kind: u32, value: u16) -> u32 {
    (kind << 16) | u32::from(value)
}

pub fn ke(e: &KeError) -> u32 {
    match *e {
        KeError::Truncated => pack(1, 0),
        KeError::TooLong => pack(2, 0),
        KeError::TooManyRecords => pack(3, 0),
        KeError::RecordTooLong { record_type } => pack(4, record_type),
        KeError::TrailingData => pack(5, 0),
        KeError::BadEndOfMessage => pack(6, 0),
        KeError::BadRecordBody { record_type } => pack(7, record_type),
        KeError::CriticalBitMissing { record_type } => pack(8, record_type),
        KeError::UnknownCriticalRecord { record_type } => pack(9, record_type),
        KeError::DuplicateRecord { record_type } => pack(10, record_type),
        KeError::MissingRecord { record_type } => pack(11, record_type),
        KeError::ServerError(c) => pack(12, c),
        KeError::ServerWarning(c) => pack(13, c),
        KeError::NoCommonProtocol => pack(14, 0),
        KeError::WrongProtocol(id) => pack(15, id),
        KeError::NoCommonAead => pack(16, 0),
        KeError::WrongAead(id) => pack(17, id),
    }
}

const KE_TEXT: [&CStr; 18] = [
    c"NTS-KE: unknown reason",
    c"NTS-KE response ends early",
    c"NTS-KE response too long",
    c"NTS-KE response has too many records",
    c"NTS-KE record body too long (value: record type)",
    c"NTS-KE response has data after End of Message",
    c"NTS-KE End of Message without critical bit or with a body",
    c"NTS-KE record has a bad body (value: record type)",
    c"NTS-KE record without critical bit (value: record type)",
    c"NTS-KE unknown critical record (value: record type)",
    c"NTS-KE record sent twice (value: record type)",
    c"NTS-KE record missing (value: record type)",
    c"NTS-KE server error (value: error code, RFC 8915 4.1.3)",
    c"NTS-KE server warning (value: warning code, RFC 8915 4.1.4)",
    c"NTS-KE server offers no common protocol",
    c"NTS-KE server chose a protocol not offered (value: protocol ID)",
    c"NTS-KE server offers no common AEAD algorithm",
    c"NTS-KE server chose an AEAD not offered (value: AEAD ID)",
];

pub fn ntp(e: &NtpError) -> u32 {
    match *e {
        NtpError::TooManyPlaceholders => pack(1, 0),
        NtpError::RequestTooLong => pack(2, 0),
        NtpError::EncryptFailed => pack(3, 0),
        NtpError::AlreadyAnswered => pack(4, 0),
        NtpError::TooShort => pack(5, 0),
        NtpError::TooLong => pack(6, 0),
        NtpError::BadVersion(v) => pack(7, u16::from(v)),
        NtpError::BadMode(m) => pack(8, u16::from(m)),
        NtpError::OriginMismatch => pack(9, 0),
        NtpError::BadExtensionField => pack(10, 0),
        NtpError::DuplicateUniqueId => pack(11, 0),
        NtpError::MissingUniqueId => pack(12, 0),
        NtpError::UniqueIdMismatch => pack(13, 0),
        NtpError::MissingAuthenticator => pack(14, 0),
        NtpError::BadAuthenticator => pack(15, 0),
        NtpError::AuthenticationFailed => pack(16, 0),
        NtpError::BadEncryptedField => pack(17, 0),
        NtpError::BadCookie => pack(18, 0),
        NtpError::TooManyCookies => pack(19, 0),
        NtpError::NoCookies => pack(20, 0),
        NtpError::Unsynchronized => pack(21, 0),
        NtpError::BadStratum(s) => pack(22, u16::from(s)),
    }
}

const NTP_TEXT: [&CStr; 23] = [
    c"NTP: unknown reason",
    c"more cookie placeholders than allowed",
    c"NTS request too long",
    c"AES-SIV encryption failed",
    c"request already answered (replay)",
    c"NTP packet shorter than its header",
    c"NTP packet too long",
    c"NTP version not 4 (value: version)",
    c"NTP mode not 4, server (value: mode)",
    c"origin timestamp is not our transmit timestamp",
    c"malformed NTP extension field",
    c"two Unique Identifier fields",
    c"no authenticated Unique Identifier",
    c"Unique Identifier is not ours",
    c"no NTS authenticator",
    c"malformed NTS authenticator",
    c"NTS authenticator does not verify",
    c"malformed encrypted extension field",
    c"cookie empty or too long",
    c"more cookies than placeholders plus one",
    c"no new cookie",
    c"server clock unsynchronized (leap indicator 3)",
    c"stratum above 15 (value: stratum)",
];

pub fn sample(e: &SampleError) -> u32 {
    match *e {
        SampleError::LocalTimesReversed => pack(1, 0),
        SampleError::ServerTimesReversed => pack(2, 0),
        SampleError::NegativeDelay => pack(3, 0),
        SampleError::BadStratum(s) => pack(4, u16::from(s)),
        SampleError::NeverSynchronized => pack(5, 0),
        SampleError::ReferenceAfterTransmit => pack(6, 0),
        SampleError::TimestampOutOfRange => pack(7, 0),
        SampleError::BoundTooLarge => pack(8, 0),
    }
}

const SAMPLE_TEXT: [&CStr; 9] = [
    c"sample: unknown reason",
    c"local receive time before local send time",
    c"server transmit time before its receive time",
    c"negative round-trip delay",
    c"stratum outside 1 to 15 (value: stratum)",
    c"reference timestamp is zero",
    c"reference timestamp after transmit timestamp",
    c"timestamp out of range",
    c"error bound over 1 s (MAXDIST)",
];

pub fn quorum(e: &QuorumError) -> u32 {
    match *e {
        QuorumError::TooFew => pack(1, 0),
        QuorumError::TooMany => pack(2, 0),
        QuorumError::BadOperator => pack(3, 0),
        QuorumError::DuplicateOperator => pack(4, 0),
        QuorumError::BadBound => pack(5, 0),
        QuorumError::FromTheFuture => pack(6, 0),
        QuorumError::NoAgreement => pack(7, 0),
        QuorumError::OutOfRange => pack(8, 0),
    }
}

const QUORUM_TEXT: [&CStr; 9] = [
    c"quorum: unknown reason",
    c"fewer than 3 servers",
    c"more than 16 servers",
    c"operator label empty or over 32 octets",
    c"two servers of one operator",
    c"negative error bound",
    c"measurement after the quorum time",
    c"the servers disagree: more than 1 wrong",
    c"offset out of range",
];

/// The kiss code as its four ASCII octets (RFC 5905 section 7.4).
pub fn kiss_octets(k: KissCode) -> [u8; 4] {
    match k {
        KissCode::Rate => *b"RATE",
        KissCode::Ntsn => *b"NTSN",
        KissCode::Deny => *b"DENY",
        KissCode::Rstr => *b"RSTR",
        KissCode::Other(o) => o,
    }
}

fn from_table(table: &[&'static CStr], reason: u32) -> &'static CStr {
    let kind = usize::try_from(reason >> 16).unwrap_or(0);
    table.get(kind).or_else(|| table.first()).copied().unwrap_or(c"unknown")
}

/// The text of a return code and, for the four that carry one, its reason.
pub fn text(code: c_int, reason: u32) -> &'static CStr {
    match code {
        OK => c"ok",
        KISS => c"Kiss-o'-Death",
        MORE => c"NTS-KE response not complete yet",
        E_NULL => c"null pointer",
        E_BUFFER => c"output buffer too small",
        E_ARG => c"argument out of range",
        E_NO_COOKIE => c"no cookie left; run NTS-KE again",
        E_KE => from_table(&KE_TEXT, reason),
        E_NTP => from_table(&NTP_TEXT, reason),
        E_SAMPLE => from_table(&SAMPLE_TEXT, reason),
        E_QUORUM => from_table(&QUORUM_TEXT, reason),
        _ => c"unknown return code",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signer_nts_core::quorum::{MAX_OPERATOR_LEN, MAX_SERVERS, MIN_SERVERS};

    #[test]
    fn constants_match_the_core() {
        assert_eq!(ALPN.to_bytes(), signer_nts_core::ke::ALPN);
        assert_eq!(EXPORTER_LABEL.to_bytes(), signer_nts_core::ke::EXPORTER_LABEL.as_bytes());
        // The quorum texts name these numbers.
        assert_eq!((MIN_SERVERS, MAX_SERVERS, MAX_OPERATOR_LEN), (3, 16, 32));
        assert_eq!(signer_nts_core::sample::MAX_BOUND_NS, 1_000_000_000);
    }

    #[test]
    fn every_kind_has_its_own_text() {
        for (table, n) in [(&KE_TEXT[..], 17), (&NTP_TEXT[..], 22), (&SAMPLE_TEXT[..], 8), (&QUORUM_TEXT[..], 8)] {
            assert_eq!(table.len(), n + 1);
            let mut seen = std::collections::HashSet::new();
            for t in table {
                assert!(seen.insert(t.to_bytes()), "{t:?} twice");
            }
        }
        assert_eq!(text(E_KE, ke(&KeError::ServerError(1))), c"NTS-KE server error (value: error code, RFC 8915 4.1.3)");
        assert_eq!(ke(&KeError::ServerError(1)), (12 << 16) | 1);
        assert_eq!(text(E_NTP, ntp(&NtpError::BadStratum(16))), c"stratum above 15 (value: stratum)");
        assert_eq!(text(E_SAMPLE, sample(&SampleError::BoundTooLarge)), c"error bound over 1 s (MAXDIST)");
        assert_eq!(text(E_QUORUM, quorum(&QuorumError::NoAgreement)), c"the servers disagree: more than 1 wrong");
        // Unknown kinds and codes still give a text.
        assert_eq!(text(E_KE, 99 << 16), c"NTS-KE: unknown reason");
        assert_eq!(text(-99, 0), c"unknown return code");
    }

    #[test]
    fn kinds_are_numbered_in_order() {
        // Each table's position matches the kind: compare with Display, which
        // starts with the same words for the variants without a value.
        let pairs_ke = [(KeError::Truncated, 1), (KeError::WrongAead(3), 17), (KeError::NoCommonAead, 16)];
        for (e, k) in pairs_ke {
            assert_eq!(ke(&e) >> 16, k);
        }
        assert_eq!(ntp(&NtpError::AuthenticationFailed) >> 16, 16);
        assert_eq!(text(E_NTP, ntp(&NtpError::AuthenticationFailed)).to_str().unwrap(), NtpError::AuthenticationFailed.to_string());
        assert_eq!(text(E_NTP, ntp(&NtpError::OriginMismatch)).to_str().unwrap(), NtpError::OriginMismatch.to_string());
        assert_eq!(text(E_SAMPLE, sample(&SampleError::NegativeDelay)).to_str().unwrap(), SampleError::NegativeDelay.to_string());
        assert_eq!(text(E_QUORUM, quorum(&QuorumError::DuplicateOperator)).to_str().unwrap(), QuorumError::DuplicateOperator.to_string());
        assert_eq!(text(E_KE, ke(&KeError::TrailingData)).to_str().unwrap(), KeError::TrailingData.to_string());
    }
}
