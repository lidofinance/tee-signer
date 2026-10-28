//go:build !verifierselect || platform_azure || platform_gcp

package runnerclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify"
)

// Key set cache: a fetch is reused for keyTTL. A token under an unknown key
// id triggers one new fetch, but not more often than every keyRefreshGap, so
// a runner that sends random key ids cannot make the client hammer the
// provider. After keyTTL the keys are fetched again, and a failed fetch
// fails the verification (a key the provider removed is not trusted for
// longer than that). A pinned key set (pinned) is used as it is and never
// fetched.
const keyTTL = time.Hour

var keyRefreshGap = 30 * time.Second

type keySource struct {
	name   string // "MAA" or "Confidential Space", for error messages
	issuer string
	http   *http.Client
	pinned *attest.KeySet

	mu sync.Mutex
	ks *attest.KeySet
	at time.Time
}

// verify runs check with the key set. If check fails with an unknown key
// id, the provider may have rotated its keys since the last fetch, so it
// runs check once more with a fresh set, when get allows a fetch.
func (s *keySource) verify(ctx context.Context, check func(*attest.KeySet) error) error {
	ks, err := s.get(ctx, false)
	if err != nil {
		return err
	}
	err = check(ks)
	if errors.Is(err, attest.ErrUnknownKey) {
		fresh, ferr := s.get(ctx, true)
		if ferr != nil {
			return ferr
		}
		if fresh != ks {
			err = check(fresh)
		}
	}
	return err
}

func (s *keySource) get(ctx context.Context, unknownKey bool) (*attest.KeySet, error) {
	if s.pinned != nil {
		return s.pinned, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	age := time.Since(s.at)
	if s.ks != nil && age < keyTTL && !(unknownKey && age >= keyRefreshGap) {
		return s.ks, nil
	}
	ks, err := attest.DiscoverJWKS(ctx, s.http, s.issuer)
	if err != nil {
		return nil, fmt.Errorf("%s key set of %s: %w", s.name, s.issuer, err)
	}
	s.ks, s.at = ks, time.Now()
	return ks, nil
}
