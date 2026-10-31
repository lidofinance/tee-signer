package backend

import (
	"errors"
	"fmt"
)

// Status is a result code. Values below 1000 are the signer core's
// sc_status codes (include/signer_core.h of signer-core). Values from 1000
// are runner and protocol codes.
type Status uint16

const (
	StatusOK                  Status = 0
	StatusArg                 Status = 1
	StatusNoMem               Status = 2
	StatusDecode              Status = 3
	StatusBadKey              Status = 4
	StatusDuplicate           Status = 5
	StatusUnknownValidator    Status = 6
	StatusStorage             Status = 7
	StatusClock               Status = 8
	StatusSlashBlock          Status = 9
	StatusSlashSource         Status = 10
	StatusSlashTarget         Status = 11
	StatusSlashSourceGtTarget Status = 12
	StatusPolicyFuture        Status = 13
	StatusPolicyExit          Status = 14
	StatusPolicyFeeRecipient  Status = 15
	StatusPolicyGasLimit      Status = 16
	StatusPolicyTimestamp     Status = 17
	StatusPolicyPubkey        Status = 18
	StatusPolicyIndex         Status = 19
	StatusPolicyDomain        Status = 20
	// Gloas (signer-core appends them after SC_ERR_POLICY_DOMAIN).
	StatusPolicyFork     Status = 21 // message type not in force at its epoch
	StatusPolicyBuilder  Status = 22 // envelope builder index is not BUILDER_INDEX_SELF_BUILD
	StatusPolicyEnvelope Status = 23 // envelope not for the last block this validator signed
	StatusEquivocation   Status = 24 // second PTC vote or envelope for a slot
	// Aggregates and contributions (signer-core SC_ERR_SELECTION_PROOF).
	StatusSelectionProof Status = 25 // selection proof does not verify under the validator key
	// Fork schedule updates (signer-core SC_ERR_SCHEDULE).
	StatusSchedule Status = 26 // a new fork schedule changes an epoch the signer may sign before it applies
	// Builder API authentication (signer-core SC_ERR_POLICY_BUILDER_AUTH).
	StatusPolicyBuilderAuth Status = 27 // BuilderRequestAuth data not on builder_request_auth_roots
	// Attestation data consistency (signer-core SC_ERR_POLICY_TARGET_SLOT).
	StatusPolicyTargetSlot Status = 28 // attestation target epoch is not the epoch of its slot

	StatusBadRequest     Status = 1000 // malformed frame or payload
	StatusUnsupported    Status = 1001 // unknown message type or kind
	StatusInternal       Status = 1002
	StatusDomainMismatch Status = 1003 // the request's domain differs from the backend's
	StatusNotReady       Status = 1004
	StatusPlatform       Status = 1005 // sealing, storage or attestation hook failed
	StatusForbidden      Status = 1006 // the client certificate's role does not allow this message
	StatusRateLimited    Status = 1007 // an attest-only certificate had its fresh attestations of the minute
)

var statusNames = map[Status]string{
	StatusOK: "SC_OK", StatusArg: "SC_ERR_ARG", StatusNoMem: "SC_ERR_NOMEM",
	StatusDecode: "SC_ERR_DECODE", StatusBadKey: "SC_ERR_BAD_KEY",
	StatusDuplicate: "SC_ERR_DUPLICATE", StatusUnknownValidator: "SC_ERR_UNKNOWN_VALIDATOR",
	StatusStorage: "SC_ERR_STORAGE", StatusClock: "SC_ERR_CLOCK",
	StatusSlashBlock: "SC_ERR_SLASH_BLOCK", StatusSlashSource: "SC_ERR_SLASH_SOURCE",
	StatusSlashTarget: "SC_ERR_SLASH_TARGET", StatusSlashSourceGtTarget: "SC_ERR_SLASH_SOURCE_GT_TARGET",
	StatusPolicyFuture: "SC_ERR_POLICY_FUTURE", StatusPolicyExit: "SC_ERR_POLICY_EXIT",
	StatusPolicyFeeRecipient: "SC_ERR_POLICY_FEE_RECIPIENT", StatusPolicyGasLimit: "SC_ERR_POLICY_GAS_LIMIT",
	StatusPolicyTimestamp: "SC_ERR_POLICY_TIMESTAMP", StatusPolicyPubkey: "SC_ERR_POLICY_PUBKEY",
	StatusPolicyIndex: "SC_ERR_POLICY_INDEX", StatusPolicyDomain: "SC_ERR_POLICY_DOMAIN",
	StatusPolicyFork: "SC_ERR_POLICY_FORK", StatusPolicyBuilder: "SC_ERR_POLICY_BUILDER",
	StatusPolicyEnvelope: "SC_ERR_POLICY_ENVELOPE", StatusEquivocation: "SC_ERR_EQUIVOCATION",
	StatusSelectionProof: "SC_ERR_SELECTION_PROOF", StatusSchedule: "SC_ERR_SCHEDULE",
	StatusPolicyBuilderAuth: "SC_ERR_POLICY_BUILDER_AUTH",
	StatusPolicyTargetSlot:  "SC_ERR_POLICY_TARGET_SLOT",
	StatusBadRequest:        "BAD_REQUEST", StatusUnsupported: "UNSUPPORTED", StatusInternal: "INTERNAL",
	StatusDomainMismatch: "DOMAIN_MISMATCH", StatusNotReady: "NOT_READY", StatusPlatform: "PLATFORM",
	StatusForbidden: "FORBIDDEN", StatusRateLimited: "RATE_LIMITED",
}

func (s Status) String() string {
	if n, ok := statusNames[s]; ok {
		return n
	}
	return fmt.Sprintf("STATUS_%d", uint16(s))
}

// IsSlashing reports whether s is a slashing-protection refusal. A second
// Gloas PTC vote or envelope for one slot counts as one.
func (s Status) IsSlashing() bool {
	return (s >= StatusSlashBlock && s <= StatusSlashSourceGtTarget) || s == StatusEquivocation
}

// IsPolicy reports whether s is a signing-policy refusal.
func (s Status) IsPolicy() bool {
	return (s >= StatusPolicyFuture && s <= StatusPolicyEnvelope) || s == StatusSelectionProof ||
		s == StatusPolicyTargetSlot || s == StatusDomainMismatch
}

// RefusedError is returned when the backend answers with a non-OK status.
type RefusedError struct {
	Code   Status
	Detail string
}

func (e *RefusedError) Error() string {
	if e.Detail == "" {
		return "backend refused: " + e.Code.String()
	}
	return "backend refused: " + e.Code.String() + ": " + e.Detail
}

// Refused builds a *RefusedError.
func Refused(code Status, format string, args ...any) error {
	return &RefusedError{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// StatusOf returns the status carried by err, StatusOK for nil, and
// StatusInternal for other errors.
func StatusOf(err error) Status {
	if err == nil {
		return StatusOK
	}
	var r *RefusedError
	if errors.As(err, &r) {
		return r.Code
	}
	return StatusInternal
}
