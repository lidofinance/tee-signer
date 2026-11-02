// Package optset holds the options of package verify and of the client
// in package runnerclient. It is internal, so only code under
// attestation-verify/runnerclient sets its fields: the test switches
// (NitroRoots, Now, KeyRefreshGap) have no exported way in.
package optset

import (
	"crypto/x509"
	"net/http"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// Option changes how a verifier or a client is built.
type Option func(*Options)

// Options are the settings an Option changes.
type Options struct {
	Timeout time.Duration
	HTTP    *http.Client
	// NitroRoots replaces the pinned AWS root, for the tests of
	// runnerclient and verify only (a local test CA); there is no exported
	// way and no setting.
	NitroRoots []*x509.Certificate
	// Now is the minimum version check's clock (time.Now); tests set it.
	Now func() time.Time
	// Verified is called with each connection's identity once it passed
	// every check (runnerclient.WithVerified).
	Verified func(*backend.Identity)
}

// New applies opts to the defaults.
func New(opts []Option) *Options {
	o := &Options{}
	for _, f := range opts {
		f(o)
	}
	if o.HTTP == nil {
		o.HTTP = &http.Client{Timeout: 15 * time.Second}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// KeyRefreshGap is the least time between two fetches of a key set for an
// unknown key id (verify/keysource.go). Tests change it.
var KeyRefreshGap = 30 * time.Second
