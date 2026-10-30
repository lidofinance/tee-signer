//go:build nts

package ntscore

import (
	"errors"
	"fmt"
)

// The core's codes (enum nts_err of nts_core.h). The Go error of each is
// below; the messages are those of the Go package the core replaced, so
// that logs and tests read as before.
const (
	codeOK                   = 0
	codeKeyLen               = 1
	codeTooManyPlaceholders  = 10
	codeRequestTooLong       = 11
	codeBadCookie            = 12
	codeAlreadyAnswered      = 20
	codeTooShort             = 21
	codeTooLong              = 22
	codeBadVersion           = 23
	codeBadMode              = 24
	codeOriginMismatch       = 25
	codeBadExtensionField    = 26
	codeDuplicateUID         = 27
	codeMissingUID           = 28
	codeUIDMismatch          = 29
	codeMissingAuthenticator = 30
	codeBadAuthenticator     = 31
	codeNotAuthentic         = 32
	codeBadEncryptedField    = 33
	codeTooManyCookies       = 34
	codeNoCookies            = 35
	codeUnsynchronized       = 36
	codeBadStratum           = 37
	codeLocalTimesReversed   = 40
	codeServerTimesReversed  = 41
	codeNegativeDelay        = 42
	codeSampleStratum        = 43
	codeNeverSynchronized    = 44
	codeZeroTimestamp        = 45
	codeReferenceAfterXmit   = 46
	codeTimestampOutOfRange  = 47
	codeBoundTooLarge        = 48
	codeQuorumTooFew         = 60
	codeQuorumTooMany        = 61
	codeBadOperator          = 62
	codeDuplicateOperator    = 63
	codeNegativeBound        = 64
	codeFromTheFuture        = 65
	codeNoAgreement          = 66
	codeQuorumOutOfRange     = 67
	codeKETruncated          = 70
	codeKETooLong            = 71
	codeKETooManyRecords     = 72
	codeKERecordTooLong      = 73
	codeKETrailingData       = 74
	codeKEBadEOM             = 75
	codeKEBadRecordBody      = 76
	codeKECriticalBitMissing = 77
	codeKEUnknownCritical    = 78
	codeKEDuplicateRecord    = 79
	codeKEMissingRecord      = 80
	codeKEServerError        = 81
	codeKEServerWarning      = 82
	codeKENoCommonProtocol   = 83
	codeKEWrongProtocol      = 84
	codeKENoCommonAEAD       = 85
	codeKEWrongAEAD          = 86
	codeHost                 = 90
	codeHostTimeout          = 91
	codeHostRandom           = 92
	codeNoCookie             = 100
	codeBadConfig            = 101
	codeNotDue               = 102
	codeKiss                 = 103
	codeNoQuorum             = 104
	codeBoundOverLimit       = 105
	codeCoarseCheck          = 106
	codeDrift                = 107
)

// Why a request could not be built or a response was refused.
var (
	ErrKeyLen               = fmt.Errorf("AES-SIV-CMAC-256 key of the wrong length, want %d octets", KeyLen)
	ErrTooManyPlaceholders  = fmt.Errorf("more than %d cookie placeholders", MaxPlaceholders)
	ErrRequestTooLong       = fmt.Errorf("NTS request longer than %d octets", NTPMaxRequestLen)
	ErrAlreadyAnswered      = errors.New("request already answered (replay)")
	ErrTooShort             = errors.New("NTP packet shorter than its header")
	ErrTooLong              = fmt.Errorf("NTP packet longer than %d octets", NTPMaxResponseLen)
	ErrBadVersion           = errors.New("NTP version is not 4")
	ErrBadMode              = errors.New("NTP mode is not 4 (server)")
	ErrOriginMismatch       = errors.New("origin timestamp is not our transmit timestamp")
	ErrBadExtensionField    = errors.New("malformed NTP extension field")
	ErrDuplicateUniqueID    = errors.New("two Unique Identifier fields")
	ErrMissingUniqueID      = errors.New("no authenticated Unique Identifier")
	ErrUniqueIDMismatch     = errors.New("Unique Identifier is not ours")
	ErrMissingAuthenticator = errors.New("no NTS authenticator")
	ErrBadAuthenticator     = errors.New("malformed NTS authenticator")
	ErrNotAuthentic         = errors.New("authenticator does not verify")
	ErrBadEncryptedField    = errors.New("malformed encrypted extension field")
	ErrBadCookie            = errors.New("cookie empty or too long")
	ErrTooManyCookies       = errors.New("more cookies than placeholders plus one")
	ErrNoCookies            = errors.New("no new cookie")
	ErrUnsynchronized       = errors.New("server clock unsynchronized (leap indicator 3)")
	ErrBadStratum           = errors.New("stratum above 15")
)

// Why a response gives no measurement.
var (
	ErrLocalTimesReversed     = errors.New("local receive time before local send time")
	ErrServerTimesReversed    = errors.New("server transmit time before its receive time")
	ErrNegativeDelay          = errors.New("negative round-trip delay")
	ErrSampleStratum          = errors.New("stratum outside 1 to 15")
	ErrNeverSynchronized      = errors.New("reference timestamp is zero")
	ErrZeroTimestamp          = errors.New("receive or transmit timestamp is zero")
	ErrReferenceAfterTransmit = errors.New("reference timestamp after transmit timestamp")
	ErrTimestampOutOfRange    = errors.New("timestamp out of range")
	ErrBoundTooLarge          = fmt.Errorf("error bound over %d ns (MAXDIST)", MaxSampleBoundNs)
)

// Why a quorum was refused.
var (
	ErrQuorumTooFew      = fmt.Errorf("fewer than %d servers", MinServers)
	ErrQuorumTooMany     = fmt.Errorf("more than %d servers", MaxServers)
	ErrBadOperator       = fmt.Errorf("operator label empty or over %d octets", MaxOperatorLen)
	ErrDuplicateOperator = errors.New("two servers of one operator")
	ErrNegativeBound     = errors.New("negative error bound")
	ErrFromTheFuture     = errors.New("measurement after the quorum time")
	ErrNoAgreement       = fmt.Errorf("the servers disagree: more than %d wrong", F)
	ErrQuorumOutOfRange  = errors.New("offset out of range")
)

// Why an NTS-KE response was refused, as the Rust core named them.
var (
	ErrKETruncated          = errors.New("NTS-KE response ends early, before End of Message")
	ErrKETooLong            = fmt.Errorf("NTS-KE response longer than %d octets", KEMaxResponseLen)
	ErrKETooManyRecords     = fmt.Errorf("NTS-KE response has more than %d records", KEMaxRecords)
	ErrKERecordTooLong      = errors.New("NTS-KE record too long")
	ErrKETrailingData       = errors.New("NTS-KE response has data after End of Message")
	ErrKEBadEOM             = errors.New("NTS-KE End of Message without critical bit or with a body")
	ErrKEBadRecordBody      = errors.New("NTS-KE record has a bad body")
	ErrKECriticalBitMissing = errors.New("NTS-KE record without critical bit")
	ErrKEUnknownCritical    = errors.New("NTS-KE unknown critical record")
	ErrKEDuplicateRecord    = errors.New("NTS-KE record sent twice")
	ErrKEMissingRecord      = errors.New("NTS-KE record missing")
	ErrKEServerError        = errors.New("NTS-KE server error")
	ErrKEServerWarning      = errors.New("NTS-KE server warning")
	ErrKENoCommonProtocol   = errors.New("NTS-KE server offers no common protocol")
	ErrKEWrongProtocol      = errors.New("NTS-KE server chose a protocol not offered")
	ErrKENoCommonAEAD       = errors.New("NTS-KE server offers no common AEAD algorithm")
	ErrKEWrongAEAD          = errors.New("NTS-KE server chose an AEAD not offered")
)

// The host operations and the client.
var (
	ErrHost           = errors.New("host operation failed")
	ErrHostTimeout    = errors.New("i/o timeout")
	ErrHostRandom     = errors.New("no random bytes")
	ErrNoCookie       = errors.New("no cookie left; run NTS-KE again")
	ErrBadConfig      = errors.New("bad configuration")
	ErrNotDue         = errors.New("the server waits for its next key exchange")
	ErrKiss           = errors.New("Kiss-o'-Death")
	ErrNoQuorum       = errors.New("no quorum yet")
	ErrBoundOverLimit = errors.New("error bound over the limit")
	ErrCoarseCheck    = errors.New("quorum time too far from the coarse clock")
	ErrDrift          = errors.New("the local clock does not keep within rho")
	errUnknownCode    = errors.New("unknown core error code")
)

var byCode = map[int]error{
	codeKeyLen: ErrKeyLen, codeTooManyPlaceholders: ErrTooManyPlaceholders, codeRequestTooLong: ErrRequestTooLong, codeBadCookie: ErrBadCookie,
	codeAlreadyAnswered: ErrAlreadyAnswered, codeTooShort: ErrTooShort, codeTooLong: ErrTooLong, codeBadVersion: ErrBadVersion, codeBadMode: ErrBadMode,
	codeOriginMismatch: ErrOriginMismatch, codeBadExtensionField: ErrBadExtensionField, codeDuplicateUID: ErrDuplicateUniqueID,
	codeMissingUID: ErrMissingUniqueID, codeUIDMismatch: ErrUniqueIDMismatch, codeMissingAuthenticator: ErrMissingAuthenticator,
	codeBadAuthenticator: ErrBadAuthenticator, codeNotAuthentic: ErrNotAuthentic, codeBadEncryptedField: ErrBadEncryptedField,
	codeTooManyCookies: ErrTooManyCookies, codeNoCookies: ErrNoCookies, codeUnsynchronized: ErrUnsynchronized, codeBadStratum: ErrBadStratum,
	codeLocalTimesReversed: ErrLocalTimesReversed, codeServerTimesReversed: ErrServerTimesReversed, codeNegativeDelay: ErrNegativeDelay,
	codeSampleStratum: ErrSampleStratum, codeNeverSynchronized: ErrNeverSynchronized, codeZeroTimestamp: ErrZeroTimestamp,
	codeReferenceAfterXmit: ErrReferenceAfterTransmit, codeTimestampOutOfRange: ErrTimestampOutOfRange, codeBoundTooLarge: ErrBoundTooLarge,
	codeQuorumTooFew: ErrQuorumTooFew, codeQuorumTooMany: ErrQuorumTooMany, codeBadOperator: ErrBadOperator, codeDuplicateOperator: ErrDuplicateOperator,
	codeNegativeBound: ErrNegativeBound, codeFromTheFuture: ErrFromTheFuture, codeNoAgreement: ErrNoAgreement, codeQuorumOutOfRange: ErrQuorumOutOfRange,
	codeKETruncated: ErrKETruncated, codeKETooLong: ErrKETooLong, codeKETooManyRecords: ErrKETooManyRecords, codeKERecordTooLong: ErrKERecordTooLong,
	codeKETrailingData: ErrKETrailingData, codeKEBadEOM: ErrKEBadEOM, codeKEBadRecordBody: ErrKEBadRecordBody,
	codeKECriticalBitMissing: ErrKECriticalBitMissing, codeKEUnknownCritical: ErrKEUnknownCritical, codeKEDuplicateRecord: ErrKEDuplicateRecord,
	codeKEMissingRecord: ErrKEMissingRecord, codeKEServerError: ErrKEServerError, codeKEServerWarning: ErrKEServerWarning,
	codeKENoCommonProtocol: ErrKENoCommonProtocol, codeKEWrongProtocol: ErrKEWrongProtocol, codeKENoCommonAEAD: ErrKENoCommonAEAD, codeKEWrongAEAD: ErrKEWrongAEAD,
	codeHost: ErrHost, codeHostTimeout: ErrHostTimeout, codeHostRandom: ErrHostRandom,
	codeNoCookie: ErrNoCookie, codeBadConfig: ErrBadConfig, codeNotDue: ErrNotDue, codeKiss: ErrKiss, codeNoQuorum: ErrNoQuorum,
	codeBoundOverLimit: ErrBoundOverLimit, codeCoarseCheck: ErrCoarseCheck, codeDrift: ErrDrift,
}

// NTS-KE record types, for the messages.
const (
	recNextProtocol = 1
	recError        = 2
	recWarning      = 3
	recAEAD         = 4
	recCookie       = 5
	recServer       = 6
	recPort         = 7
)

// CodeError is the Go error of a core code and its detail; nil for 0.
func CodeError(code, detail int) error {
	if code == codeOK {
		return nil
	}
	base, ok := byCode[code]
	if !ok {
		return fmt.Errorf("%w %d", errUnknownCode, code)
	}
	switch code {
	case codeBadVersion:
		return fmt.Errorf("%w: version %d", base, detail)
	case codeBadMode:
		return fmt.Errorf("%w: mode %d", base, detail)
	case codeBadStratum, codeSampleStratum:
		return fmt.Errorf("%w: stratum %d", base, detail)
	case codeKERecordTooLong:
		return fmt.Errorf("%w: record %d: body of more than %d octets, at most %d", base, detail, KEMaxBody, KEMaxBody)
	case codeKETrailingData:
		return fmt.Errorf("%w: %d octets", base, detail)
	case codeKEBadRecordBody:
		typ, n := detail&0xffff, detail>>16
		var what string
		switch typ {
		case recNextProtocol:
			what = "odd length"
		case recError:
			what = fmt.Sprintf("error code of %d octets", n)
		case recWarning:
			what = fmt.Sprintf("warning code of %d octets", n)
		case recAEAD:
			what = fmt.Sprintf("%d octets, want one AEAD ID", n)
		case recCookie:
			what = fmt.Sprintf("cookie of %d octets, want 1 to %d", n, MaxCookieLen)
		case recServer:
			what = fmt.Sprintf("NTPv4 Server Negotiation: not a host name or address of 1 to %d octets", MaxServerName)
		case recPort:
			what = "NTPv4 Port Negotiation: want a port of 1 to 65535 in 2 octets"
		default:
			what = fmt.Sprintf("%d octets", n)
		}
		return fmt.Errorf("%w: record %d: %s", base, typ, what)
	case codeKECriticalBitMissing:
		return fmt.Errorf("%w: Next Protocol (record %d)", base, detail)
	case codeKEUnknownCritical:
		return fmt.Errorf("%w %d", base, detail)
	case codeKEDuplicateRecord:
		return fmt.Errorf("%w: record %d repeated", base, detail)
	case codeKEMissingRecord:
		switch detail {
		case recNextProtocol:
			return fmt.Errorf("%w: no Next Protocol record", base)
		case recAEAD:
			return fmt.Errorf("%w: no AEAD Algorithm record", base)
		default:
			return fmt.Errorf("%w: no cookie", base)
		}
	case codeKEServerError:
		return fmt.Errorf("%w %d (RFC 8915 section 4.1.3)", base, detail)
	case codeKEServerWarning:
		return fmt.Errorf("%w %d (RFC 8915 section 4.1.4)", base, detail)
	case codeKEWrongProtocol:
		return fmt.Errorf("%w: protocol %d, not NTPv4 (0)", base, detail)
	case codeKEWrongAEAD:
		return fmt.Errorf("%w: AEAD %d, not AEAD_AES_SIV_CMAC_256 (%d)", base, detail, aeadSIVCMAC256)
	case codeHostTimeout:
		if detail != 0 {
			return fmt.Errorf("%w (and earlier: %w)", base, CodeError(detail, 0))
		}
	}
	return base
}

// CodeClass is which step a code belongs to: the NTP exchange, the
// measurement, the quorum, NTS-KE, a host operation, or the client.
type CodeClass int

const (
	ClassNone CodeClass = iota
	ClassNTP
	ClassSample
	ClassQuorum
	ClassKE
	ClassHost
	ClassClient
)

// ClassOf is the class of a core code.
func ClassOf(code int) CodeClass {
	switch {
	case code == codeOK:
		return ClassNone
	case code < 40:
		return ClassNTP
	case code < 60:
		return ClassSample
	case code < 70:
		return ClassQuorum
	case code < 90:
		return ClassKE
	case code < 100:
		return ClassHost
	default:
		return ClassClient
	}
}
