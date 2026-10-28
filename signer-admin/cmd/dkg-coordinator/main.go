// Command dkg-coordinator runs key generation among the runners of a
// cluster (docs/dkg.md) and builds what each path needs from the result.
//
//	dkg-coordinator operator-keys -config c.json                 each runner's attested operator key
//	dkg-coordinator push-order    -config c.json [-wait 1m]      runners with a setup: send the signed DKG order
//	dkg-coordinator keygen        -config c.json -count 4        make keys; writes dkg-result.json
//	dkg-coordinator accounts      -result dkg-result.json ...    Dirk fork / signer shim accounts files
//	dkg-coordinator deposits      -config c.json -result ...     deposit data, threshold-signed by the runners
//	dkg-coordinator charon-lock   -config c.json -result ...     a Charon lock, signed by the runners
//	dkg-coordinator charon-shims  -config c.json -result ...     each Charon node's signer shim settings
//	dkg-coordinator check-deposits -config c.json -policy p.json -result ...  deposits, or a lock's, checked before sending; each runner must hold the result's keys
//	                              (-order o.signed -locked setup.bin for an order)
//
// It is not trusted and holds nothing secret besides its client
// certificate, which must have the admin role (docs/protocol.md, "Client
// roles"): connect probes it on every runner first (admin/cluster.Probe). It connects to each runner over mutual TLS, checks the
// runner's attestation and the binding of the TLS key to it with the
// verifier the policy names for that participant, and carries messages.
// Shares travel only sealed to an attested peer's session key, so it never
// sees one, and the full keys exist nowhere. Each runner checks every
// message on its own; the coordinator's checks only stop a bad run early.
//
// The config names the policy file (the same file every runner loads) and
// one connection per participant, in policy order:
//
//	{"policy": "dkg-policy.json",
//	 "runners": [{"address": "tcp:10.0.0.1:7100", "client_cert": "c.pem", "client_key": "k.pem"}, ...]}
//
// Runners with a setup take no policy file but approver-signed DKG orders
// (order.go): the config names the order in place of the policy, and the
// locked group whose withdrawal credentials and deposit amounts the setup
// commands use. Every message then names the order, so the same runners
// serve several orders (a Dirk fork lane and a Charon lane).
//
// operator-keys runs before the policy exists, so there each runner entry
// carries its own "attestation" settings. Relative paths are relative to
// the config file's folder. A runner entry takes a testnet runner only
// with "allow_testnet_build": true.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/governance/flavor"
	admincluster "github.com/lidofinance/tee-signer/signer-admin/cluster"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
	"github.com/lidofinance/tee-signer/tee-signer/keygen"
)

// Config is the coordinator's settings file.
type Config struct {
	Policy string `json:"policy,omitempty"`
	// Order and Locked: runners with a setup (order.go).
	Order   string       `json:"order,omitempty"`
	Locked  string       `json:"locked,omitempty"`
	Runners []Connection `json:"runners"`

	dir string
}

// Connection reaches one runner.
type Connection struct {
	Address    string `json:"address"`
	ClientCert string `json:"client_cert"`
	ClientKey  string `json:"client_key"`
	TLSKeyPin  string `json:"tls_key_pin,omitempty"`
	// Attestation is used only by operator-keys; the other commands take
	// the policy's settings for the position.
	Attestation *runnerclient.Attestation `json:"attestation,omitempty"`
	// AllowTestnetBuild takes a runner of a testnet build
	// (attest/runnerclient); off, such a runner is refused.
	AllowTestnetBuild bool `json:"allow_testnet_build,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmds := map[string]func([]string) error{
		"operator-keys":  cmdOperatorKeys,
		"push-order":     cmdPushOrder,
		"keygen":         cmdKeygen,
		"accounts":       cmdAccounts,
		"deposits":       cmdDeposits,
		"charon-lock":    cmdCharonLock,
		"charon-shims":   cmdCharonShims,
		"check-deposits": cmdCheckDeposits,
	}
	f, ok := cmds[os.Args[1]]
	if !ok {
		usage()
	}
	if err := f(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "dkg-coordinator:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: dkg-coordinator operator-keys|push-order|keygen|accounts|deposits|charon-lock|charon-shims|check-deposits -h")
	os.Exit(2)
}

func hex0x(b []byte) string { return "0x" + hex.EncodeToString(b) }

func readConfig(path string) (*Config, error) {
	if path == "" {
		return nil, errors.New("-config is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	c.dir = filepath.Dir(path)
	return &c, nil
}

func (c *Config) abs(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.dir, p)
}

// loadPolicy reads the policy the config names, or the policy of its DKG
// order.
func (c *Config) loadPolicy(platformName string) (*keygen.Policy, [32]byte, error) {
	if c.Order != "" {
		if c.Policy != "" {
			return nil, [32]byte{}, errors.New("config: policy or order, not both")
		}
		locked := ""
		if c.Locked != "" {
			locked = c.abs(c.Locked)
		}
		pol, hash, _, err := loadOrder(c.abs(c.Order), locked, platformName)
		if err != nil {
			return nil, hash, err
		}
		if len(c.Runners) != len(pol.Participants) {
			return nil, hash, fmt.Errorf("%d runners for %d order participants", len(c.Runners), len(pol.Participants))
		}
		return pol, hash, nil
	}
	if c.Policy == "" {
		return nil, [32]byte{}, errors.New("config: no policy or order")
	}
	raw, err := os.ReadFile(c.abs(c.Policy))
	if err != nil {
		return nil, [32]byte{}, err
	}
	pol, hash, err := keygen.ParsePolicy(raw, platformName)
	if err != nil {
		return nil, hash, err
	}
	if len(c.Runners) != len(pol.Participants) {
		return nil, hash, fmt.Errorf("%d runners for %d policy participants", len(c.Runners), len(pol.Participants))
	}
	return pol, hash, nil
}

// connect opens an attested client to runner i with the given attestation
// settings, and makes the first request so the client connects and checks
// the runner's identity now.
func (c *Config) connect(ctx context.Context, i int, att runnerclient.Attestation, name string, timeout time.Duration) (*runnerclient.Client, error) {
	rc := c.Runners[i]
	conn := runnerclient.Connection{Address: rc.Address, ClientCert: c.abs(rc.ClientCert), ClientKey: c.abs(rc.ClientKey),
		TLSKeyPin: rc.TLSKeyPin, Attestation: att, AllowTestnetBuild: rc.AllowTestnetBuild}
	cl, err := conn.New(runnerclient.WithTimeout(timeout))
	if err != nil {
		return nil, fmt.Errorf("runner %d (%s): %w", i+1, name, err)
	}
	hctx, cancel := context.WithTimeout(ctx, timeout)
	h, err := cl.Health(hctx)
	cancel()
	if err != nil {
		cl.Close()
		return nil, fmt.Errorf("runner %d (%s): attested connection: %w", i+1, name, err)
	}
	// Key generation messages need the admin role: find out now, before
	// the run, whether this client certificate has it (admin/cluster.Probe).
	pctx, cancel := context.WithTimeout(ctx, timeout)
	pr, err := admincluster.Probe(pctx, cl.Client)
	cancel()
	if err != nil {
		cl.Close()
		return nil, fmt.Errorf("runner %d (%s): %w", i+1, name, err)
	}
	if !pr.OK() {
		cl.Close()
		return nil, fmt.Errorf("runner %d (%s): %s", i+1, name, pr)
	}
	fmt.Fprintf(os.Stderr, "runner %d (%s) at %s: attested (%s), platform %s, %s build (version %s), %d keys loaded; role probe: %s\n",
		i+1, name, rc.Address, att.Verifier, h.Platform, flavor.FromVersion(h.Version), h.Version, h.Validators, pr)
	return cl, nil
}

// connectAll connects to every runner with the policy's settings.
func (c *Config) connectAll(ctx context.Context, pol *keygen.Policy, timeout time.Duration) ([]*runnerclient.Client, []remote.VerifyFunc, error) {
	var cls []*runnerclient.Client
	var vs []remote.VerifyFunc
	for i := range c.Runners {
		pt := pol.Participants[i]
		cl, err := c.connect(ctx, i, pt.Attestation, pt.Name, timeout)
		if err != nil {
			for _, o := range cls {
				o.Close()
			}
			return nil, nil, err
		}
		// The hello check takes the hello's user data, not IDENTITY's.
		hv, err := pt.Attestation.NewDKGHelloVerifier()
		if err != nil {
			cl.Close()
			for _, o := range cls {
				o.Close()
			}
			return nil, nil, err
		}
		cls, vs = append(cls, cl), append(vs, hv)
	}
	return cls, vs, nil
}

// commonFlags are the flags of every command that talks to runners.
type commonFlags struct {
	config, platform string
	timeout          time.Duration
}

func (f *commonFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.config, "config", "", "coordinator config (JSON)")
	fs.StringVar(&f.platform, "platform", "", `platform the runners run on; "dev" allows the dev verifier`)
	fs.DurationVar(&f.timeout, "timeout", 2*time.Minute, "time limit of each request")
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
