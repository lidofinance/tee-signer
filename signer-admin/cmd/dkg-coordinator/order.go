package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/governance/dkgorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	remoteadmin "github.com/lidofinance/tee-signer/signer-admin/remote/admin"
	"github.com/lidofinance/tee-signer/signer-protocol/dkgmsg"
	"github.com/lidofinance/tee-signer/tee-signer/keygen"
	"github.com/lidofinance/tee-signer/tee-signer/keygen/relay"
)

// DKG orders: runners with a setup take no policy file. The config names
// the signed order (dkgorder, from signer-config) in place of the policy,
// and for the setup commands the locked group whose withdrawal credentials
// and deposit amounts the runners hold in force: the signers' binary setup
// while no locked update changed them, else the signed locked update in
// force (or its body). The coordinator is not trusted: each runner checks
// every setup message against its own locked group.
//
//	{"order": "dkg-order.signed", "locked": "setups/azure-1.setup",
//	 "runners": [{"address": "tcp:10.0.0.1:7100", "client_cert": "c.pem", "client_key": "k.pem"}, ...]}

// loadOrder reads a signed order (or its body) and, if lockedPath is set,
// the locked group. It returns the order's policy, its hash and the signed
// order (nil for a body).
func loadOrder(path, lockedPath, platformName string) (*keygen.Policy, [32]byte, []byte, error) {
	var hash [32]byte
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, hash, nil, err
	}
	var body *dkgorder.Body
	var signed []byte
	switch {
	case dkgorder.IsOrder(raw):
		o, err := dkgorder.Decode(raw)
		if err != nil {
			return nil, hash, nil, fmt.Errorf("%s: %w", path, err)
		}
		body, signed = &o.Body, raw
	case dkgorder.IsBody(raw):
		if body, err = dkgorder.DecodeBody(raw); err != nil {
			return nil, hash, nil, fmt.Errorf("%s: %w", path, err)
		}
	default:
		return nil, hash, nil, fmt.Errorf("%s: not a DKG order", path)
	}
	enc, _ := body.Encode()
	hash = dkgorder.Hash(enc)
	var locked func() (*setupwire.Locked, error)
	if lockedPath != "" {
		l, err := readLocked(lockedPath)
		if err != nil {
			return nil, hash, nil, err
		}
		locked = func() (*setupwire.Locked, error) { return l, nil }
	}
	pol, err := keygen.PolicyFromOrder(body, hash, platformName, locked)
	if err != nil {
		return nil, hash, nil, err
	}
	return pol, hash, signed, nil
}

// readLocked reads the locked group from a binary setup, a signed locked
// update or the body of one.
func readLocked(path string) (*setupwire.Locked, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var body *setupwire.UpdateBody
	switch {
	case len(raw) > 0 && raw[0] == 'S':
		s, err := setupwire.DecodeSetup(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return &s.Locked, nil
	case len(raw) > 0 && raw[0] == 'U':
		u, err := setupwire.DecodeUpdate(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		body = &u.Body
	case len(raw) > 0 && raw[0] == 'B':
		if body, err = setupwire.DecodeUpdateBody(raw); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	default:
		return nil, fmt.Errorf("%s: not a setup or a config update", path)
	}
	if body.Group != setupwire.GroupLocked {
		return nil, fmt.Errorf("%s: an update of the %s group; locked needs the locked group", path, body.Group)
	}
	return body.Locked, nil
}

// dkgRunner is one runner's key generation as the coordinator drives it.
type dkgRunner interface {
	relay.Runner
	DKGSetupSign(ctx context.Context, q *dkgmsg.SetupRequest) ([]byte, error)
}

// dkgClient is the key generation of cl: plain on the policy file path, in
// the order's envelope (DKG_IN_ORDER) for an order.
func dkgClient(cl *runnerclient.Client, pol *keygen.Policy, hash [32]byte) dkgRunner {
	if pol.FromOrder() {
		return remoteadmin.Wrap(cl.Client).InOrder(hash)
	}
	return remoteadmin.Wrap(cl.Client)
}

// cmdPushOrder sends the config's signed order to every runner and prints
// each runner's state of it. With -wait it pushes again until every runner
// has it active or the time is up.
func cmdPushOrder(args []string) error {
	fs := flag.NewFlagSet("push-order", flag.ExitOnError)
	var cf commonFlags
	cf.register(fs)
	wait := fs.Duration("wait", 0, "push again until every runner has the order active, for at most this long (0: push once)")
	_ = fs.Parse(args)
	cfg, err := readConfig(cf.config)
	if err != nil {
		return err
	}
	if cfg.Order == "" {
		return errors.New("config: push-order needs order")
	}
	pol, hash, signed, err := loadOrder(cfg.abs(cfg.Order), "", cf.platform)
	if err != nil {
		return err
	}
	if signed == nil {
		return fmt.Errorf("%s is an order body: sign it first (signer-config sign and assemble)", cfg.Order)
	}
	if len(cfg.Runners) != len(pol.Participants) {
		return fmt.Errorf("%d runners for %d order participants", len(cfg.Runners), len(pol.Participants))
	}
	ctx := context.Background()
	cls, _, err := cfg.connectAll(ctx, pol, cf.timeout)
	if err != nil {
		return err
	}
	defer func() {
		for _, c := range cls {
			c.Close()
		}
	}()
	deadline := time.Now().Add(*wait)
	for {
		active := 0
		for i, cl := range cls {
			st, err := remoteadmin.Wrap(cl.Client).DKGOrder(ctx, signed)
			if err != nil {
				return fmt.Errorf("runner %d (%s): %w", i+1, pol.Participants[i].Name, err)
			}
			if int(st.Position) != i || st.Hash != hash {
				return fmt.Errorf("runner %d (%s): answered for position %d of order %x", i+1, pol.Participants[i].Name, st.Position+1, st.Hash[:6])
			}
			outcome := "accepted"
			if st.Outcome == dkgmsg.OrderKnown {
				outcome = "known"
			}
			line := fmt.Sprintf("runner %d (%s): order %x %s, %s, arrived %s, acts %s, not after %s", i+1, pol.Participants[i].Name,
				hash[:6], outcome, st.Status, unixTime(st.Arrived), unixTime(st.ActAt), unixTime(st.NotAfter))
			if st.Why != "" {
				line += ": " + st.Why
			}
			fmt.Fprintln(os.Stderr, line)
			if st.Status == dkgmsg.OrderActive {
				active++
			}
		}
		if active == len(cls) {
			fmt.Fprintf(os.Stderr, "order %x active on all %d runners\n", hash[:6], len(cls))
			return nil
		}
		if *wait == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("order %x active on %d of %d runners after %v", hash[:6], active, len(cls), *wait)
		}
		time.Sleep(min(5*time.Second, time.Until(deadline)+time.Millisecond))
	}
}

func unixTime(s uint64) string {
	if s > 253402300799 {
		return "far future"
	}
	return time.Unix(int64(s), 0).UTC().Format(time.RFC3339)
}
