// Command proof-check is the proof check of the dashboard. For each signer in
// topology.json it connects the way a Dirk fork does: mutual TLS 1.3 with the
// client certificate, and the attestation of the signer checked on every
// connection with package runnerclient (the verifier named in the signer's
// cloud.json: dev, azure-maa, aws-nitro or gcp-cs). It then asks for HEALTH,
// and for a fresh IDENTITY with a new nonce, which it verifies again.
//
// The result goes to one JSON file that the dashboard exporter reads. The file
// holds the time of the last passed check, the round trip, the clock figures
// below, short fingerprints (8 hex digits) of the attested identity and of
// the image measurement the verifier pins, the signer core's counters from
// HEALTH (signatures, hash cache, writes), the numbers of the newest mark
// log record (HEALTH record of a runner with -mark-store), and the signer's
// setup state (setupView, below). No full address, no full hash and no
// error text with an address leave this tool.
//
// The connection checks the setup pins of the signer's cloud.json
// (setup_sha256, min_locked_version, min_open_version; package runnerclient,
// setup.go). A signer whose setup_hash is not the pinned one, that reports a
// setup with no pin, or whose config is below a minimum fails the check:
// ok false, with the reason in error.
//
// A cloud.json may name identity_version; it must be the client's. The
// file names the version of each signer (identity_version, setup_format)
// and the key origin of its verified identity (setup.key_origin).
//
// Two clock figures, not to be confused:
//
//   - nts: the signer's own NTS clock, from HEALTH clock_nts (runners with
//     the NTS clock only). bound_now_ms is the error bound of the signer's
//     time: real time is within that many milliseconds of it.
//     offset_from_host_ms is the NTS time minus the system clock inside the
//     TEE. Both are measured inside the TEE and do not depend on this
//     machine. These are the figures to trust.
//
//   - clock_vs_checker_ms: the signer's time minus this machine's clock,
//     from a second HEALTH on the open connection, taken at the middle of
//     its round trip. It is only as right as this machine's clock.
//     clock_vs_checker_err_ms is
//     its resolution: half the round trip, plus 500 ms for a runner that
//     reports whole seconds only (no clock_unix_ms).
//
//     proof-check -topology topology.json -proof-dir /proof -out /out/proof.json
//
// -proof-dir holds one folder per signer name with cloud.json (the connection:
// address, client_cert, client_key, attestation, optionally identity_version)
// and the two PEM files it names. The client certificate should be an
// attest-only one (docs/protocol.md, "Client roles"): HEALTH and IDENTITY
// are all the check sends, and a signer gives an attest-only certificate 4
// fresh attestations a minute. Run the tool in the network namespace that
// reaches the signers (the network entry's, as the Dirk forks do).
// The check sends no signing request and changes nothing in the signer.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

type topoSigner struct {
	Name     string `json:"name"`
	Slot     string `json:"slot"`
	Provider string `json:"provider"`
	Enabled  bool   `json:"enabled"`
	Proof    bool   `json:"proof"`
}

type topo struct {
	Signers []topoSigner `json:"signers"`
}

// result is one entry of the output file. The exporter reads the same names.
type result struct {
	Name            string  `json:"name"`
	Slot            string  `json:"slot"`
	Provider        string  `json:"provider"`
	Enabled         bool    `json:"enabled"`
	Verifier        string  `json:"verifier"`
	OK              bool    `json:"ok"`
	LastAttemptUnix int64   `json:"last_attempt_unix"`
	LastOKUnix      int64   `json:"last_ok_unix"`
	RoundTripMS     float64 `json:"round_trip_ms"`
	Error           string  `json:"error,omitempty"`
	TLSKey          string  `json:"tls_key,omitempty"`
	Config          string  `json:"config,omitempty"`
	Ready           bool    `json:"ready"`
	ClockSource     string  `json:"clock_source,omitempty"`
	ClockTrusted    bool    `json:"clock_trusted"`
	ClockUnix       int64   `json:"clock_unix"`              // whole seconds, 0 when the signer had no time
	ClockUnixMS     int64   `json:"clock_unix_ms,omitempty"` // 0 from runners that report whole seconds only
	// The signer's time minus this machine's clock: see the package doc.
	ClockVsCheckerMS    float64 `json:"clock_vs_checker_ms"`
	ClockVsCheckerErrMS float64 `json:"clock_vs_checker_err_ms"`
	// NTS is HEALTH clock_nts as the runner sent it, nil without one.
	NTS *cloud.ClockNTS `json:"nts,omitempty"`
	// Validators is the number of shares the signer holds (HEALTH
	// validators). Stats are the signer core's counters since the runner
	// started (HEALTH stats), nil from runners without them. Counts only.
	Validators int                `json:"validators"`
	Stats      *cloud.SignerStats `json:"stats,omitempty"`
	// Image is 8 hex digits of the image measurement that the verifier
	// pins and a passed check proved (imageOf); empty for the dev verifier.
	// Mark is the newest record of the signer's mark log (HEALTH record),
	// nil for a runner without the mark log.
	Image string `json:"image,omitempty"`
	Mark  *mark  `json:"mark,omitempty"`
	// IdentityVersion is the IDENTITY version the check asked in, and
	// SetupFormat the setup format of its runners. Both 0 when the check
	// found no cloud.json.
	IdentityVersion int `json:"identity_version,omitempty"`
	SetupFormat     int `json:"setup_format,omitempty"`
	// Setup is the setup state of the verified identity, nil when the
	// check failed before it.
	Setup *setupView `json:"setup,omitempty"`
}

// mark is what the file keeps of a mark log record: its number, the writes
// since the runner started, the bounds it holds and the log's state. The
// log's name (a bucket or container) stays out.
type mark struct {
	Record      uint64 `json:"record"`
	Writes      uint64 `json:"writes"`
	TargetEpoch uint64 `json:"target_epoch"`
	SourceEpoch uint64 `json:"source_epoch"`
	BlockSlot   uint64 `json:"block_slot"`
	State       string `json:"state"` // ok, lost or handed-over
}

// setupView is the signer's setup state as the proof file carries it, for
// the dashboard's Config row (research/setup-phase.md, "Dashboard panel").
// Hashes are 8 hex digits, like tls_key and config. Times are Unix
// seconds, capped at 2^63-1 (a runner saturates its sums at 2^64-1).
//
//	"setup": {
//	  "setup_hash": "5e700000",
//	  "pinned": true,
//	  "flag_path": false,
//	  "locked": {
//	    "version": 2, "effective_version": 2, "hash": "01000000", "min_version": 2,
//	    "pending": {"version": 3, "hash": "02000000", "effective_at_unix": 1800000000}
//	  },
//	  "open": {"version": 1, "effective_version": 1, "hash": "03000000", "min_version": 0},
//	  "approver_set_hash": "04000000",
//	  "order": {"kind": "handover", "hash": "05000000", "act_at_unix": 1900000000},
//	  "key_release_hash": "06000000",
//	  "key_origin": {"generated": 3, "imported": 0, "orders_hash": "07000000"}
//	}
//
// key_origin is IDENTITY's: of the loaded keys, how many the
// runner made in key generation and how many it imported, and the hash of
// the DKG orders of the generated ones. Left out on the flag path.
//
// pinned: cloud.json pins setup_sha256 (the check passed, so it matched).
// flag_path: a runner without a setup, whose setup_hash is the hash of its
// -config file; it has no locked, open, approver_set_hash or order.
// effective_version counts a pending update once its effective time has
// passed on this machine's clock; the runner applies it from then on, while
// it still reports it as pending. min_version is cloud.json's
// min_locked_version or min_open_version, 0 when not set. pending is left
// out when no update waits, order when none is pending, key_release_hash
// while it is zero (phase 2). approver_set_hash "00000000" means the runner
// cannot read its active approver set.
type setupView struct {
	SetupHash       string         `json:"setup_hash"`
	Pinned          bool           `json:"pinned"`
	FlagPath        bool           `json:"flag_path"`
	Locked          *groupView     `json:"locked,omitempty"`
	Open            *groupView     `json:"open,omitempty"`
	ApproverSetHash string         `json:"approver_set_hash,omitempty"`
	Order           *orderView     `json:"order,omitempty"`
	KeyReleaseHash  string         `json:"key_release_hash,omitempty"`
	KeyOrigin       *keyOriginView `json:"key_origin,omitempty"`
}

type keyOriginView struct {
	Generated  uint32 `json:"generated"`
	Imported   uint32 `json:"imported"`
	OrdersHash string `json:"orders_hash"`
}

type groupView struct {
	Version          uint64       `json:"version"`
	EffectiveVersion uint64       `json:"effective_version"`
	Hash             string       `json:"hash"`
	MinVersion       uint64       `json:"min_version"`
	Pending          *pendingView `json:"pending,omitempty"`
}

type pendingView struct {
	Version         uint64 `json:"version"`
	Hash            string `json:"hash"`
	EffectiveAtUnix int64  `json:"effective_at_unix"`
}

type orderView struct {
	Kind      string `json:"kind"`
	Hash      string `json:"hash"`
	ActAtUnix int64  `json:"act_at_unix"`
}

// short is the 8 hex digit fingerprint of a hash.
func short(r cloud.Root) string { return hex.EncodeToString(r[:4]) }

// unixCapped is a runner's Unix time as an int64, capped at 2^63-1.
func unixCapped(sec uint64) int64 { return int64(min(sec, math.MaxInt64)) }

// viewOf is the proof file's form of state s, checked with att at now.
func viewOf(s *cloud.SetupState, att *runnerclient.Attestation, now time.Time) *setupView {
	v := &setupView{SetupHash: short(s.SetupHash), Pinned: att.SetupSHA256 != "", FlagPath: runnerclient.FlagPath(s)}
	if v.FlagPath {
		return v
	}
	group := func(g cloud.ConfigGroup, least uint64) *groupView {
		gv := &groupView{Version: g.Version, EffectiveVersion: runnerclient.EffectiveVersion(g, now), Hash: short(g.Hash), MinVersion: least}
		if p := g.Pending; p.Version != 0 {
			gv.Pending = &pendingView{Version: p.Version, Hash: short(p.Hash), EffectiveAtUnix: unixCapped(p.EffectiveAt)}
		}
		return gv
	}
	v.Locked, v.Open = group(s.Locked, att.MinLockedVersion), group(s.Open, att.MinOpenVersion)
	v.ApproverSetHash = short(s.ApproverSetHash)
	if o := s.Order; o.Kind != 0 {
		v.Order = &orderView{Kind: runnerclient.OrderKind(o.Kind), Hash: short(o.Hash), ActAtUnix: unixCapped(o.ActAt)}
	}
	if s.KeyReleaseHash != (cloud.Root{}) {
		v.KeyReleaseHash = short(s.KeyReleaseHash)
	}
	if k := s.KeyOrigin; k != (cloud.KeyOrigin{}) {
		v.KeyOrigin = &keyOriginView{Generated: k.Generated, Imported: k.Imported, OrdersHash: short(k.OrdersHash)}
	}
	return v
}

// identityView is viewOf for a verified identity.
func identityView(id *cloud.Identity, att *runnerclient.Attestation, now time.Time) *setupView {
	return viewOf(&id.State, att, now)
}

type outFile struct {
	UpdatedUnix int64    `json:"updated_unix"`
	IntervalS   int      `json:"interval_s"`
	Signers     []result `json:"signers"`
}

func main() {
	var (
		topoPath = flag.String("topology", "/etc/dashboard/topology.json", "topology file")
		proofDir = flag.String("proof-dir", "/proof", "folder with one folder per signer: cloud.json and its PEM files")
		out      = flag.String("out", "/out/proof.json", "result file")
		interval = flag.Duration("interval", 60*time.Second, "time between checks")
		timeout  = flag.Duration("timeout", 30*time.Second, "time allowed for one signer")
		once     = flag.Bool("once", false, "check once, print the result and exit")
	)
	flag.Parse()

	b, err := os.ReadFile(*topoPath)
	if err != nil {
		fatal(err)
	}
	var t topo
	if err := json.Unmarshal(b, &t); err != nil {
		fatal(fmt.Errorf("%s: %w", *topoPath, err))
	}

	last := map[string]result{} // keeps last_ok across cycles
	loadPrevious(*out, last)
	for {
		of := outFile{IntervalS: int(interval.Seconds())}
		for _, s := range t.Signers {
			r := result{Name: s.Name, Slot: s.Slot, Provider: s.Provider, Enabled: s.Enabled}
			if s.Enabled && s.Proof {
				prev := last[s.Name]
				r = check(*proofDir, s, *timeout)
				if r.OK {
					r.LastOKUnix = r.LastAttemptUnix
				} else {
					r.LastOKUnix = prev.LastOKUnix
				}
				last[s.Name] = r
			}
			of.Signers = append(of.Signers, r)
		}
		of.UpdatedUnix = time.Now().Unix()
		if err := write(*out, of); err != nil {
			fmt.Fprintln(os.Stderr, "proof-check: cannot write the result:", err)
		}
		for _, r := range of.Signers {
			if r.Enabled && r.LastAttemptUnix != 0 {
				fmt.Printf("%s %s ok=%v rtt=%.0fms %s tls=%s config=%s identity=v%d %s %s\n", time.Now().UTC().Format(time.RFC3339), r.Name, r.OK,
					r.RoundTripMS, clockLine(r), r.TLSKey, r.Config, r.IdentityVersion, setupLine(r), r.Error)
			}
		}
		if *once {
			return
		}
		time.Sleep(*interval)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "proof-check:", err)
	os.Exit(1)
}

func loadPrevious(path string, into map[string]result) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var of outFile
	if json.Unmarshal(b, &of) != nil {
		return
	}
	for _, r := range of.Signers {
		into[r.Name] = r
	}
}

// write replaces the file in one step, so the exporter never reads half of it.
func write(path string, of outFile) error {
	b, err := json.MarshalIndent(of, "", " ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func check(dir string, s topoSigner, timeout time.Duration) result {
	r := result{Name: s.Name, Slot: s.Slot, Provider: s.Provider, Enabled: true, LastAttemptUnix: time.Now().Unix()}
	fail := func(err error) result {
		r.OK = false
		r.Error = tidy(err.Error())
		return r
	}

	folder := filepath.Join(dir, s.Name)
	b, err := os.ReadFile(filepath.Join(folder, "cloud.json"))
	if err != nil {
		return fail(fmt.Errorf("no connection file for %s", s.Name))
	}
	// The connection fields, and the IDENTITY version of the signer. Fields
	// of the Dirk fork (accounts, slots_per_epoch) are left alone.
	var conn struct {
		runnerclient.Connection
		IdentityVersion int `json:"identity_version"`
	}
	if err := json.Unmarshal(b, &conn); err != nil {
		return fail(fmt.Errorf("cloud.json: %w", err))
	}
	conn.ResolvePaths(folder)
	r.Verifier = conn.Attestation.Verifier
	if conn.IdentityVersion != 0 && conn.IdentityVersion != identityVersion {
		return fail(fmt.Errorf("cloud.json: identity_version %d; this tool speaks IDENTITY v%d only", conn.IdentityVersion, identityVersion))
	}
	r.IdentityVersion, r.SetupFormat = identityVersion, setupFormat

	cl, err := conn.New(runnerclient.WithTimeout(timeout))
	if err != nil {
		return fail(err)
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	r = probe(ctx, cl, cl.Verify, &conn.Attestation, r)
	if r.OK {
		r.Image = imageOf(conn.Attestation)
	}
	return r
}

// imageOf is 8 hex digits of the measurement the verifier pins: the CCE
// policy hash on Azure, PCR0 (the enclave image) on Nitro, the image digest
// on GCP. Once the check passed, the signer runs that image.
func imageOf(a runnerclient.Attestation) string {
	var h string
	switch a.Verifier {
	case runnerclient.VerifierAzureMAA:
		h = a.CCEPolicySHA256
	case runnerclient.VerifierAWSNitro:
		h = a.NitroPCRs["0"]
	case runnerclient.VerifierGCPCS:
		h = strings.TrimPrefix(strings.ToLower(a.GCPImageDigest), "sha256:")
	}
	h = strings.ToLower(h)
	if len(h) < 8 {
		return ""
	}
	return h[:8]
}

// markOf reads HEALTH record of a runner with the mark log (-mark-store):
// "marklog LOG signer=S owner=O version=N writes=W target=T source=S
// block=B [skipped=K] [HANDED-OVER|LOST]". Any other record (none, the clone
// guard) gives nil.
func markOf(record string) *mark {
	f := strings.Fields(record)
	if len(f) < 2 || f[0] != "marklog" {
		return nil
	}
	m := &mark{State: "ok"}
	for _, kv := range f[2:] {
		switch kv {
		case "LOST":
			m.State = "lost"
			continue
		case "HANDED-OVER":
			m.State = "handed-over"
			continue
		}
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			continue
		}
		switch k {
		case "version":
			m.Record = n
		case "writes":
			m.Writes = n
		case "target":
			m.TargetEpoch = n
		case "source":
			m.SourceEpoch = n
		case "block":
			m.BlockSlot = n
		}
	}
	return m
}

// The IDENTITY version of the client, and the setup format of its runners.
const (
	identityVersion = wire.IdentityVersion
	setupFormat     = setupwire.FormatVersion
)

// runner is what probe asks of a runner client (runnerclient.Client).
type runner interface {
	Health(ctx context.Context) (*cloud.Health, error)
	Identity(ctx context.Context, nonce []byte) (*cloud.Identity, error)
}

// verifyFunc checks an identity the runner gave for nonce
// (runnerclient.Client.Verify).
type verifyFunc = remote.VerifyFunc

// probe runs the check on a client that has not connected yet. att are the
// settings verify was built from; the setup view shows their pins.
func probe(ctx context.Context, cl runner, verify verifyFunc, att *runnerclient.Attestation, r result) result {
	fail := func(err error) result {
		r.OK = false
		r.Error = tidy(err.Error())
		return r
	}

	// HEALTH. The connection behind it runs the whole check: TLS 1.3 with the
	// client certificate, IDENTITY with a fresh nonce, the verifier, the TLS
	// key pin from the verified identity.
	t0 := time.Now()
	h, err := cl.Health(ctx)
	rtt := time.Since(t0)
	r.RoundTripMS = float64(rtt.Microseconds()) / 1000
	if err != nil {
		return fail(err)
	}
	// A second HEALTH on the open connection times the clock: its round
	// trip is one exchange, not the connection and the attestation check.
	// If it fails, the first answer serves, with its longer round trip.
	t1 := time.Now()
	if h1, err := cl.Health(ctx); err == nil {
		h, t0, rtt = h1, t1, time.Since(t1)
	}
	r.Ready = h.Ready
	r.Validators, r.Stats = h.Validators, h.Stats
	r.Mark = markOf(h.Record)
	clockOf(&r, h, t0, rtt)

	// A second, explicit identity with a nonce of our own.
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fail(err)
	}
	id, err := cl.Identity(ctx, nonce)
	if err != nil {
		return fail(fmt.Errorf("identity: %w", err))
	}
	if err := verify(ctx, nonce, id); err != nil {
		return fail(fmt.Errorf("identity not verified: %w", err))
	}
	r.OK = true
	if len(id.TLSKeyHash) >= 4 {
		r.TLSKey = hex.EncodeToString(id.TLSKeyHash[:4])
	}
	// The first bytes of setup_hash (the flag path's
	// runners put the hash of their chain config file there).
	r.Config = hex.EncodeToString(id.State.SetupHash[:4])
	r.IdentityVersion, r.SetupFormat = identityVersion, setupFormat
	r.Setup = identityView(id, att, time.Now())
	return r
}

// setupLine is the setup part of the log line: the version in force per
// group, the approver set, a pending update or order, and "unpinned" when
// cloud.json pins no setup_sha256.
func setupLine(r result) string {
	v := r.Setup
	switch {
	case v == nil:
		return "setup=none"
	case v.FlagPath:
		return "setup=flag-path"
	}
	s := fmt.Sprintf("locked=v%d open=v%d approvers=%s", v.Locked.EffectiveVersion, v.Open.EffectiveVersion, v.ApproverSetHash)
	for _, g := range []struct {
		name string
		v    *groupView
	}{{"locked", v.Locked}, {"open", v.Open}} {
		if p := g.v.Pending; p != nil && p.Version != g.v.EffectiveVersion {
			s += fmt.Sprintf(" pending=%s:v%d@%s", g.name, p.Version, time.Unix(p.EffectiveAtUnix, 0).UTC().Format(time.RFC3339))
		}
	}
	if o := v.Order; o != nil {
		s += fmt.Sprintf(" order=%s@%s", o.Kind, time.Unix(o.ActAtUnix, 0).UTC().Format(time.RFC3339))
	}
	if k := v.KeyOrigin; k != nil {
		s += fmt.Sprintf(" keys=generated:%d,imported:%d", k.Generated, k.Imported)
	}
	if !v.Pinned {
		s += " unpinned"
	}
	return s
}

// clockOf records the clock figures of one HEALTH answer, sent at t0 with
// round trip rtt. The signer read its clock somewhere in the round trip, so
// the middle is the best guess, within half the round trip.
func clockOf(r *result, h *cloud.Health, t0 time.Time, rtt time.Duration) {
	r.ClockSource, r.ClockTrusted, r.NTS = h.ClockSource, h.ClockTrusted, h.NTS
	if h.ClockUnix == 0 {
		return // the signer has no time (its clock refused)
	}
	r.ClockUnix = int64(h.ClockUnix)
	errMS := float64(rtt.Microseconds()) / 2000
	signerMS := float64(h.ClockUnixMS)
	if h.ClockUnixMS == 0 {
		// A runner before clock_unix_ms: the reading lies in the second it
		// names, so take its middle and add half a second to the error.
		signerMS = float64(h.ClockUnix)*1000 + 500
		errMS += 500
	} else {
		r.ClockUnixMS = int64(h.ClockUnixMS)
	}
	mid := float64(t0.UnixMicro())/1000 + float64(rtt.Microseconds())/2000
	r.ClockVsCheckerMS = round1(signerMS - mid)
	r.ClockVsCheckerErrMS = round1(errMS)
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

// clockLine is the clock part of the log line: the NTS figures when the
// signer has them, and the figure against this machine's clock.
func clockLine(r result) string {
	s := ""
	if n := r.NTS; n != nil {
		s = fmt.Sprintf("nts_bound=%.1fms nts_offset_from_tee_host=%+.1fms members=%d ", n.BoundNowMS, n.OffsetFromHostMS, len(n.Members))
	}
	if r.ClockUnix == 0 {
		return s + "signer_clock=none"
	}
	return s + fmt.Sprintf("vs_this_pc=%+.0fms(+-%.0f)", r.ClockVsCheckerMS, r.ClockVsCheckerErrMS)
}

var (
	ipRE  = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b`)
	hexRE = regexp.MustCompile(`\b[0-9a-fA-F]{16,}\b`)
)

// tidy shortens an error text: addresses and long hex strings go.
func tidy(s string) string {
	s = ipRE.ReplaceAllString(s, "<ip>")
	s = hexRE.ReplaceAllStringFunc(s, func(h string) string { return h[:8] + "…" })
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}
