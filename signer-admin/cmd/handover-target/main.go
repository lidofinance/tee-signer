//go:build !verifierselect

// Command handover-target is the target half of the handover tool
// (signer-protocol docs/protocol.md, "Handover"). The source half is
// handover-source.
//
//	handover-target identity -conn target.json -setup target.setup -order order.signed -out identity.json
//	handover-source ... -identity identity.json -out pages/
//	handover-target import -conn target.json -order order.signed -pages pages/
//
// identity first pushes the signed order to the target, which reserves
// itself for it: it takes the order into its import slot and from then on
// no config update, so the identity the source checks stays true until the
// import. A source hands over only to a target reserved for its order.
//
// identity reads the target's IDENTITY with a fresh nonce over a
// connection that checks its attestation with the settings of target.json
// (an attest/runnerclient Connection, as deploy.sh verifier-config writes
// it, with the target's setup_sha256 pinned), and checks the target's
// setup file against the identity: its published part (the public part
// with every salt and platform_commitment, never the private part) must
// hash to the setup_hash the target attests. It writes the nonce, the raw
// identity and the published part to the identity file, which the source
// half sends in HANDOVER.
//
// import passes the sealed pages the source half wrote on to the target
// (IMPORT_HANDOVER), a few requests at a time. The pages are ciphertext,
// sealed to the import key of the target's boot that answered the identity
// step; if the target restarted since, its import key changed: run the
// identity step and the source half again. Shares the target holds already
// are skipped, so a stopped import resumes where it stopped. The target
// itself checks the order, the origin proof and every share.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/governance/handoverorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	admincluster "github.com/lidofinance/tee-signer/signer-admin/cluster"
	remoteadmin "github.com/lidofinance/tee-signer/signer-admin/remote/admin"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/tee-signer/handover"
)

// identityFile is what the identity step writes and the source half reads.
type identityFile struct {
	Format            string `json:"format"`
	TargetSetupSHA256 string `json:"target_setup_sha256"`
	ImportKeySHA256   string `json:"import_key_sha256"`
	Nonce             string `json:"nonce"`     // hex
	Identity          []byte `json:"identity"`  // the IDENTITY answer
	Published         []byte `json:"published"` // setupwire.Published encoding
	ReadAt            string `json:"read_at"`
}

const identityFormat = "signer-handover-identity-v1"

// manifest is what the source half writes next to the pages.
type manifest struct {
	Format            string            `json:"format"`
	OrderSHA256       string            `json:"order_sha256"`
	TargetSetupSHA256 string            `json:"target_setup_sha256"`
	ImportKeySHA256   string            `json:"import_key_sha256"`
	Mark              backend.Watermark `json:"mark"`
	Total             uint32            `json:"total"`
	Pages             []string          `json:"pages"`
}

const pagesFormat = "signer-handover-pages-v1"

func main() {
	var err error
	if len(os.Args) < 2 {
		err = errors.New("usage: handover-target identity|import [flags]")
	} else {
		switch os.Args[1] {
		case "identity":
			err = identityCmd(os.Args[2:])
		case "import":
			err = importCmd(os.Args[2:])
		default:
			err = fmt.Errorf("unknown command %q (identity or import)", os.Args[1])
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "handover-target:", err)
		os.Exit(1)
	}
}

// connection reads a runnerclient Connection; it must pin the target's
// setup_sha256.
func connection(path string) (*runnerclient.Connection, [32]byte, error) {
	var h [32]byte
	var c runnerclient.Connection
	if err := admincluster.ReadStrictJSON(path, &c); err != nil {
		return nil, h, err
	}
	c.ResolvePaths(filepath.Dir(path))
	b, err := hex.DecodeString(strings.TrimPrefix(c.Attestation.SetupSHA256, "0x"))
	if err != nil || len(b) != 32 {
		return nil, h, fmt.Errorf("%s: attestation.setup_sha256 must pin the target's setup (64 hex digits)", path)
	}
	copy(h[:], b)
	return &c, h, nil
}

// identity reads and verifies the target's identity for a fresh nonce.
func identity(ctx context.Context, cl *runnerclient.Client) ([]byte, []byte, *backend.Identity, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, nil, err
	}
	raw, id, err := cl.IdentityRaw(ctx, nonce)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("target: identity: %w", err)
	}
	if err := cl.Verify(ctx, nonce, id); err != nil {
		return nil, nil, nil, fmt.Errorf("target: attestation: %w", err)
	}
	return nonce, raw, id, nil
}

func hexHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func identityCmd(args []string) error {
	fs := flag.NewFlagSet("identity", flag.ExitOnError)
	connPath := fs.String("conn", "", "Connection (JSON) of the target, its setup_sha256 pinned")
	setupPath := fs.String("setup", "", "the target's setup file (signer-config setup -handover-from)")
	orderPath := fs.String("order", "", "the signed handover order: the target reserves itself for it first")
	out := fs.String("out", "", "the identity file to write")
	fs.Parse(args)
	if *connPath == "" || *setupPath == "" || *orderPath == "" || *out == "" {
		return errors.New("identity: set -conn, -setup, -order and -out")
	}
	conn, pin, err := connection(*connPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*setupPath)
	if err != nil {
		return err
	}
	s, err := setupwire.DecodeSetup(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", *setupPath, err)
	}
	pub, err := setupwire.PublishedOf(s)
	if err != nil {
		return err
	}
	pubEnc, err := pub.Encode()
	if err != nil {
		return err
	}
	sh, err := pub.SetupHash()
	if err != nil {
		return err
	}
	if sh != pin {
		return fmt.Errorf("%s hashes to setup %x, %s pins %x", *setupPath, sh[:8], *connPath, pin[:8])
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cl, err := conn.New(runnerclient.WithTimeout(60 * time.Second))
	if err != nil {
		return err
	}
	defer cl.Close()
	order, err := os.ReadFile(*orderPath)
	if err != nil {
		return err
	}
	o, err := handoverorder.Decode(order)
	if err != nil {
		return fmt.Errorf("%s: %w", *orderPath, err)
	}
	if o.Body.Target.SetupHash != sh {
		return fmt.Errorf("%s hands over to setup %x, the target's is %x", *orderPath, o.Body.Target.SetupHash[:8], sh[:8])
	}
	rs, err := remoteadmin.Wrap(cl.Client).HandoverOrder(ctx, order)
	if err != nil {
		return fmt.Errorf("target: reserve for the order: %w", err)
	}
	what := "reserved"
	if rs.Outcome == handoverorder.Known {
		what = "reserved already"
	}
	fmt.Fprintf(os.Stderr, "the target is %s for order %x: it takes no config update until the import ends\n", what, rs.Hash[:6])
	nonce, idRaw, id, err := identity(ctx, cl)
	if err != nil {
		return err
	}
	st := &id.State
	if st.SetupHash != sh {
		return fmt.Errorf("the target attests setup %x, its setup file hashes to %x", st.SetupHash[:8], sh[:8])
	}
	keys := st.KeyOrigin.Generated + st.KeyOrigin.Imported
	switch {
	case st.Locked.Version != 0 || st.Open.Version != 0:
		return fmt.Errorf("the target is past version 0 (locked %d, open %d); a handover target starts at version 0", st.Locked.Version, st.Open.Version)
	case keys > 0 && st.Order.Kind == 0:
		return fmt.Errorf("the target holds %d keys and no handover import is in progress on it", keys)
	}
	f := identityFile{Format: identityFormat, TargetSetupSHA256: hex.EncodeToString(sh[:]), ImportKeySHA256: hexHash(id.ImportKey),
		Nonce: hex.EncodeToString(nonce), Identity: idRaw, Published: pubEnc, ReadAt: time.Now().UTC().Format(time.RFC3339)}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, append(b, '\n'), 0o600); err != nil {
		return err
	}
	if keys > 0 {
		fmt.Fprintf(os.Stderr, "the target restarted mid-import (order %x): it holds %d keys; the source seals the rest again to its new import key\n",
			st.Order.Hash[:6], keys)
	}
	fmt.Fprintf(os.Stderr, "target setup %x, import key %s..., %d keys held: wrote %s\n", sh[:8], f.ImportKeySHA256[:16], keys, *out)
	return nil
}

// batch is shares of one page that go in one request.
type batch struct {
	page *handover.Response
	idx  []int
}

func importCmd(args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	connPath := fs.String("conn", "", "Connection (JSON) of the target, its setup_sha256 pinned")
	orderPath := fs.String("order", "", "the signed handover order")
	dir := fs.String("pages", "", "the folder handover-source wrote")
	parallel := fs.Int("parallel", 4, "requests at a time, each on its own connection")
	per := fs.Int("batch", 32, "shares per request")
	asImported := fs.Bool("as-imported", false, "count every share as imported: for a target that cannot check the source's origin proof")
	limit := fs.Int("limit", 0, "store at most this many new shares, then stop (a first look, or a test of the resume); 0: all")
	fs.Parse(args)
	if *connPath == "" || *orderPath == "" || *dir == "" {
		return errors.New("import: set -conn, -order and -pages")
	}
	if *parallel < 1 || *per < 1 || *per > handover.MaxPerResponse {
		return fmt.Errorf("import: -parallel at least 1, -batch 1 to %d", handover.MaxPerResponse)
	}
	conn, pin, err := connection(*connPath)
	if err != nil {
		return err
	}
	order, err := os.ReadFile(*orderPath)
	if err != nil {
		return err
	}
	o, err := handoverorder.Decode(order)
	if err != nil {
		return fmt.Errorf("%s: %w", *orderPath, err)
	}
	orderHash, _ := o.Body.Hash()
	mraw, err := os.ReadFile(filepath.Join(*dir, "manifest.json"))
	if err != nil {
		return fmt.Errorf("%s: no manifest (run handover-source first): %w", *dir, err)
	}
	var m manifest
	if err := json.Unmarshal(mraw, &m); err != nil || m.Format != pagesFormat {
		return fmt.Errorf("%s/manifest.json: not a %s manifest (%v)", *dir, pagesFormat, err)
	}
	switch {
	case m.OrderSHA256 != hex.EncodeToString(orderHash[:]):
		return fmt.Errorf("the pages were sealed under order %s, %s is %x", m.OrderSHA256, *orderPath, orderHash)
	case m.TargetSetupSHA256 != hex.EncodeToString(pin[:]):
		return fmt.Errorf("the pages are for setup %s, %s pins %x", m.TargetSetupSHA256, *connPath, pin)
	case o.Body.Target.SetupHash != pin:
		return fmt.Errorf("the order hands over to setup %x, %s pins %x", o.Body.Target.SetupHash[:8], *connPath, pin[:8])
	}

	// The pages: one mark, one total, every share once.
	var pages []*handover.Response
	seen := map[backend.Pubkey]bool{}
	for _, name := range m.Pages {
		b, err := os.ReadFile(filepath.Join(*dir, filepath.Base(name)))
		if err != nil {
			return err
		}
		p, err := handover.DecodeResponse(b)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if p.Mark != m.Mark || p.Total != m.Total {
			return fmt.Errorf("%s: mark or total differ from the manifest's", name)
		}
		for _, s := range p.Shares {
			if seen[s.Pubkey] {
				return fmt.Errorf("%s: validator %s twice", name, s.Pubkey)
			}
			seen[s.Pubkey] = true
		}
		pages = append(pages, p)
	}
	if uint32(len(seen)) != m.Total {
		return fmt.Errorf("%s holds %d shares, the source has %d: run handover-source again to fetch the rest", *dir, len(seen), m.Total)
	}

	ctx := context.Background()
	newClient := func() (*runnerclient.Client, error) { return conn.New(runnerclient.WithTimeout(5 * time.Minute)) }
	cl, err := newClient()
	if err != nil {
		return err
	}
	defer cl.Close()
	// IMPORT_HANDOVER needs the admin role: refuse before any page goes out
	// when this certificate lacks it (admin/cluster.Probe).
	pr, err := admincluster.Probe(ctx, cl.Client)
	if err != nil {
		return err
	}
	if !pr.OK() {
		return fmt.Errorf("target: %s", pr)
	}
	_, _, id, err := identity(ctx, cl)
	if err != nil {
		return err
	}
	if hexHash(id.ImportKey) != m.ImportKeySHA256 {
		return errors.New("the target's import key is not the one the pages are sealed to: it restarted since the identity step. " +
			"Run handover-target identity and handover-source again (a new folder), then import from there")
	}
	keys, err := cl.PublicKeys(ctx)
	if err != nil {
		return fmt.Errorf("target: public keys: %w", err)
	}
	held := map[backend.Pubkey]backend.Pubkey{}
	for _, k := range keys {
		held[k.Pubkey] = k.SharePubkey
	}
	var work []batch
	skipped := 0
	for _, p := range pages {
		var cur []int
		for i, s := range p.Shares {
			if sp, ok := held[s.Pubkey]; ok {
				if sp != s.SharePubkey {
					return fmt.Errorf("the target holds another share of validator %s", s.Pubkey)
				}
				skipped++
				continue
			}
			cur = append(cur, i)
			if len(cur) == *per {
				work = append(work, batch{p, cur})
				cur = nil
			}
		}
		if len(cur) > 0 {
			work = append(work, batch{p, cur})
		}
	}
	limited := false
	if *limit > 0 {
		n := 0
		for i, b := range work {
			if n += len(b.idx); n >= *limit {
				b.idx = b.idx[:len(b.idx)-(n-*limit)]
				work, limited = append(work[:i], b), i+1 < len(work) || n > *limit
				break
			}
		}
	}
	if len(work) == 0 {
		// Nothing left to store. One request with a held share (or an
		// empty page) lets the target end an import whose last record
		// was lost, and answers its state.
		p := *pages[0]
		p.Shares = p.Shares[:min(1, len(p.Shares))]
		work = append(work, batch{&p, nil})
		for i := range p.Shares {
			work[0].idx = append(work[0].idx, i)
		}
	}
	fmt.Fprintf(os.Stderr, "importing %d shares in %d requests (%d at a time), %d held already, total %d; mark target %d source %d block %d\n",
		len(seen)-skipped, len(work), *parallel, skipped, m.Total, m.Mark.TargetEpoch, m.Mark.SourceEpoch, m.Mark.BlockSlot)

	var flags uint8
	if *asImported {
		flags = handover.ImportAsImported
	}
	start := time.Now()
	jobs := make(chan batch)
	var mu sync.Mutex
	var stored, heldNow int
	report := len(seen) / 10
	var firstErr error
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	for range min(*parallel, len(work)) {
		wg.Go(func() {
			c, err := newClient()
			if err != nil {
				mu.Lock()
				firstErr = cmpErr(firstErr, err)
				mu.Unlock()
				cancel()
				return
			}
			defer c.Close()
			for b := range jobs {
				p := *b.page
				p.Shares = nil
				for _, i := range b.idx {
					p.Shares = append(p.Shares, b.page.Shares[i])
				}
				r, err := send(ctx, c, &handover.ImportRequest{Flags: flags, Order: order, Page: &p})
				mu.Lock()
				if err != nil {
					firstErr = cmpErr(firstErr, err)
					mu.Unlock()
					cancel()
					continue
				}
				for _, oc := range r.Outcomes {
					if oc == handover.Stored {
						stored++
					} else {
						heldNow++
					}
				}
				if n := stored + heldNow + skipped; report > 0 && n >= report {
					fmt.Fprintf(os.Stderr, "  %d of %d in, %.1f s\n", n, len(seen), time.Since(start).Seconds())
					report += len(seen) / 10
				}
				mu.Unlock()
			}
		})
	}
feed:
	for _, b := range work {
		select {
		case jobs <- b:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	elapsed := time.Since(start)
	if firstErr != nil {
		return fmt.Errorf("import stopped after %d new shares in %.1f s: %w (run import again to resume)", stored, elapsed.Seconds(), firstErr)
	}
	// The state the target attests now.
	_, _, id, err = identity(context.Background(), cl)
	if err != nil {
		return err
	}
	ko := id.State.KeyOrigin
	done := id.State.Order.Kind == 0 && ko.Generated+ko.Imported >= m.Total
	rate := 0.0
	if stored > 0 {
		rate = elapsed.Seconds() / float64(stored)
	}
	fmt.Printf("handover import: %d new shares stored in %.1f s (%.3f s a share), %d held before; the target holds %d of %d (generated %d, imported %d); done %t\n",
		stored, elapsed.Seconds(), rate, skipped+heldNow, ko.Generated+ko.Imported, m.Total, ko.Generated, ko.Imported, done)
	switch {
	case !done && limited:
		return fmt.Errorf("stopped at -limit %d: the import has not ended; run import again without -limit", *limit)
	case !done:
		return errors.New("the import has not ended on the target: run import again")
	}
	return nil
}

// send sends one request; a network error is tried again twice, on a new
// connection (the client dials again after one). A refusal is not.
func send(ctx context.Context, c *runnerclient.Client, q *handover.ImportRequest) (*handover.ImportResponse, error) {
	var err error
	for try := range 3 {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var r *handover.ImportResponse
		if r, err = remoteadmin.Wrap(c.Client).HandoverImport(ctx, q); err == nil {
			return r, nil
		}
		var ref *backend.RefusedError
		if errors.As(err, &ref) {
			return nil, err
		}
		time.Sleep(time.Duration(try+1) * time.Second)
	}
	return nil, err
}

// cmpErr keeps the first error, unless it is only the cancellation that a
// later, real error caused.
func cmpErr(first, err error) error {
	if first == nil || errors.Is(first, context.Canceled) {
		return err
	}
	return first
}
