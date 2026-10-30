package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient/verify"
	"github.com/lidofinance/tee-signer/governance/flavor"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	admincluster "github.com/lidofinance/tee-signer/signer-admin/cluster"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// member is one signer of the cluster with its setup, decoded.
type member struct {
	name      string
	cloudPath string
	setup     *setupwire.Setup
	setupRaw  []byte
	setupHash [32]byte
}

type cluster struct {
	updates string // folder of the updates push keeps
	members []*member
}

// clusterFlags are the flags of the subcommands that talk to the signers.
type clusterFlags struct {
	path    *string
	only    *string
	timeout *time.Duration
}

func addClusterFlags(fs *flag.FlagSet) clusterFlags {
	return clusterFlags{
		path:    fs.String("cluster", "", "cluster.json: the cloud.json and the setup of each signer"),
		only:    fs.String("signers", "", "comma-separated names: work on these signers of the cluster only"),
		timeout: fs.Duration("timeout", 30*time.Second, "time allowed for each signer"),
	}
}

func (f clusterFlags) load() (*cluster, error) {
	if *f.path == "" {
		return nil, errors.New("-cluster is required")
	}
	var only []string
	if *f.only != "" {
		only = strings.Split(*f.only, ",")
	}
	return loadCluster(*f.path, only)
}

// readStrictJSON decodes a JSON file and refuses unknown fields and
// trailing data.
func readStrictJSON(path string, v any) error { return admincluster.ReadStrictJSON(path, v) }

// loadCluster reads cluster.json and the setup of each signer
// (admin/cluster.Load). only, if not empty, keeps the signers of these
// names.
func loadCluster(path string, only []string) (*cluster, error) {
	ac, err := admincluster.Load(path, only)
	if err != nil {
		return nil, err
	}
	c := &cluster{updates: ac.Updates}
	for _, m := range ac.Members {
		c.members = append(c.members, &member{name: m.Name, cloudPath: m.CloudPath, setup: m.Setup, setupRaw: m.SetupRaw, setupHash: m.SetupHash})
	}
	return c, nil
}

func cmpOr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// loadConn reads a signer's cloud.json as runnerclient does.
func loadConn(path string) (*runnerclient.Connection, error) { return admincluster.LoadConn(path) }

// signerState is what the tool reads of one signer.
type signerState struct {
	state  *cloud.SetupState
	health *cloud.Health
	// flavor is the runner's build flavour, from HEALTH's version. A
	// testnet runner's governance times run in minutes; the connection
	// refuses one unless cloud.json sets allow_testnet_build.
	flavor flavor.Flavor
}

// readState connects with conn (TLS, attestation, setup pins), asks for
// HEALTH, then reads the setup state of a fresh, verified IDENTITY
// (admin/cluster.ReadState).
func readState(ctx context.Context, m *member, conn *runnerclient.Connection, timeout time.Duration) (*signerState, *runnerclient.Client, error) {
	st, cl, err := admincluster.ReadState(ctx, &admincluster.Member{Name: m.name, SetupHash: m.setupHash}, conn, timeout)
	if err != nil {
		return nil, nil, err
	}
	return &signerState{state: st.State, health: st.Health, flavor: st.Flavor}, cl, nil
}

// clusterLimits are the governance times of the signers' build flavour,
// which the waits of updates and orders follow. Signers of two flavours in
// one draft are refused.
func clusterLimits(c *cluster, states []*signerState) (flavor.Flavor, flavor.Limits, error) {
	f := states[0].flavor
	for i, st := range states {
		if st.flavor != f {
			return "", flavor.Limits{}, fmt.Errorf("signer %s is a %s build and %s a %s build; draft for signers of one build flavour (-signers)",
				c.members[0].name, f, c.members[i].name, st.flavor)
		}
	}
	return f, f.Limits(), nil
}

// readAll reads the state of every member in turn. A member that fails
// has a nil state and its error.
func readAll(c *cluster, timeout time.Duration) ([]*signerState, []error) {
	states := make([]*signerState, len(c.members))
	errs := make([]error, len(c.members))
	for i, m := range c.members {
		conn, err := loadConn(m.cloudPath)
		if err != nil {
			errs[i] = err
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		st, cl, err := readState(ctx, m, conn, timeout)
		cancel()
		if err != nil {
			errs[i] = err
			continue
		}
		cl.Close()
		states[i] = st
	}
	return states, errs
}

// editCloudJSON rewrites the attestation section of a cloud.json with
// edit and keeps every other field (admin/cluster.EditCloudJSON).
func editCloudJSON(path string, edit func(att map[string]json.RawMessage) error) error {
	return admincluster.EditCloudJSON(path, edit)
}

// writeAtomic writes a file next to path and renames it over path.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	return admincluster.WriteAtomic(path, data, mode)
}

// hex8 is the 8 hex digit fingerprint of a hash, as the dashboard shows it.
func hex8(h [32]byte) string { return hex.EncodeToString(h[:4]) }

// fullHex is a whole hash as 64 hex digits.
func fullHex(h [32]byte) string { return hex.EncodeToString(h[:]) }

// when writes Unix seconds as RFC 3339 UTC.
func when(sec uint64) string { return verify.UnixTime(sec) }

// left is the time from now to sec, or "due" when it has passed.
func left(sec uint64, t time.Time) string {
	n := uint64(max(t.Unix(), 0))
	if sec <= n {
		return "due"
	}
	d := time.Duration(min(sec-n, uint64(1<<62)/uint64(time.Second))) * time.Second
	return "in " + d.String()
}

// ref is one config group's version and hash.
type ref struct {
	version uint64
	hash    [32]byte
}

func (r ref) String() string { return fmt.Sprintf("v%d/%s", r.version, hex8(r.hash)) }

func groupOf(s *cloud.SetupState, g setupwire.Group) cloud.ConfigGroup {
	if g == setupwire.GroupLocked {
		return s.Locked
	}
	return s.Open
}

func activeRef(g cloud.ConfigGroup) ref { return ref{g.Version, g.Hash} }

func pendingRef(g cloud.ConfigGroup) ref { return ref{g.Pending.Version, g.Pending.Hash} }

var groups = []setupwire.Group{setupwire.GroupLocked, setupwire.GroupOpen}

func fprintf(w io.Writer, format string, args ...any) { fmt.Fprintf(w, format, args...) }

// sameCluster checks that b belongs to a's cluster (admin/cluster.SameCluster).
func sameCluster(a, b *member) error {
	return admincluster.SameCluster(&admincluster.Member{Name: a.name, Setup: a.setup}, &admincluster.Member{Name: b.name, Setup: b.setup})
}
