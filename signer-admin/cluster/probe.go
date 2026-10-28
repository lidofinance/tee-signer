package cluster

import (
	"context"
	"errors"
	"fmt"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// RoundTripper sends one request and returns the answer's body or the
// runner's refusal (*backend.RefusedError). remote.Client is one.
type RoundTripper interface {
	RoundTrip(ctx context.Context, t wire.MsgType, payload []byte) ([]byte, error)
}

// probeUnknownType is a message type no runner serves. The runner's role
// table answers it FORBIDDEN for every role, since a type missing from the
// table is denied.
const probeUnknownType wire.MsgType = 0x7f

// ProbeResult is what Probe learned about one connection.
type ProbeResult struct {
	// Admin: the connection's certificate has the admin role.
	Admin bool
	// Setup: the runner has a setup (CONFIG_UPDATE got past its setup
	// check). Known only when the role check let CONFIG_UPDATE through.
	Setup bool
	// Answer is the runner's answer to the empty CONFIG_UPDATE.
	Answer string
}

// OK reports whether admin messages from this connection reach the
// runner's handlers: the certificate has the admin role.
func (r ProbeResult) OK() bool { return r.Admin }

func (r ProbeResult) String() string {
	switch {
	case r.Admin && r.Setup:
		return "admin: the role check passed (" + r.Answer + ")"
	case r.Admin:
		return "admin: the role check passed; the runner has no setup (" + r.Answer + ")"
	}
	return "not admin: the runner refuses admin messages from this certificate (" + r.Answer + "); its connection file needs an admin client certificate"
}

// Probe finds out whether admin messages from rt's certificate get past
// the runner's role check, without changing anything on the runner:
//
//  1. A message of a type no runner serves, which the role table answers
//     FORBIDDEN. Any other answer is an error.
//  2. CONFIG_UPDATE with an empty payload. FORBIDDEN means the
//     certificate lacks the admin role; BAD_REQUEST
//     (the empty payload does not decode) means it passed and the runner
//     has a setup; UNSUPPORTED means it passed and the runner has no setup.
//     A handed-over runner answers that it was handed over (STORAGE).
func Probe(ctx context.Context, rt RoundTripper) (ProbeResult, error) {
	var r ProbeResult
	_, err := rt.RoundTrip(ctx, probeUnknownType, nil)
	if code(err) != backend.StatusForbidden {
		return r, fmt.Errorf("probe: a message of unknown type 0x%02x got %v, want FORBIDDEN", uint8(probeUnknownType), answer(err))
	}
	_, err = rt.RoundTrip(ctx, wireadmin.TypeConfigUpdate, nil)
	r.Answer = answer(err)
	switch code(err) {
	case backend.StatusForbidden:
		return r, nil
	case backend.StatusBadRequest:
		r.Setup = true
	case backend.StatusUnsupported, backend.StatusStorage:
	default:
		return r, fmt.Errorf("probe: an empty CONFIG_UPDATE got %s, want FORBIDDEN, BAD_REQUEST or UNSUPPORTED", r.Answer)
	}
	r.Admin = true
	return r, nil
}

// code is the status of a refusal; StatusOK for no error and for an error
// that is not a refusal.
func code(err error) backend.Status {
	var re *backend.RefusedError
	if errors.As(err, &re) {
		return re.Code
	}
	return backend.StatusOK
}

func answer(err error) string {
	if err == nil {
		return "OK"
	}
	var re *backend.RefusedError
	if errors.As(err, &re) {
		return re.Code.String()
	}
	return err.Error()
}
