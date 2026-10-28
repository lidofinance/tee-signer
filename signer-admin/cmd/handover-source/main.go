//go:build !verifierselect

// Command handover-source is the source half of the handover tool
// (signer-protocol docs/protocol.md, "Handover"). It speaks to the source;
// handover-target speaks to the target:
//
//	handover-target identity -conn target.json -setup target.setup -order order.signed -out identity.json
//	handover-source -conn source.json -order order.signed -identity identity.json -out pages/ [-go]
//	handover-target import -conn target.json -order order.signed -pages pages/
//
// source.json is an attest/runnerclient Connection of the source runner
// with an admin client certificate (HANDOVER_ORDER and HANDOVER are
// admin messages). The tool first pushes the order again (HANDOVER_ORDER,
// which does no harm) to read its state: a pending order waits, an expired
// or void one stops the tool. The first HANDOVER page that passes the
// source's checks makes the source stop signing for good and write the
// tombstone that names the target, so for an active order the tool wants
// -go. After the tombstone (state done) it runs without it: the source
// answers the same target with the same mark, also after a restart.
//
// It sends the target's identity and published setup from the identity
// file, which the source checks itself (this tool decodes them only for
// its own checks and output), and writes each page as the source answered
// it to the folder, with a manifest. The pages are ciphertext: every share
// is sealed to the import key of the target's boot that answered the
// identity step. Running the tool again fetches every page again; a
// folder made for another import key, order or target is refused, so a
// target that restarted gets a new folder.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/governance/handoverorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	admincluster "github.com/lidofinance/tee-signer/signer-admin/cluster"
	remoteadmin "github.com/lidofinance/tee-signer/signer-admin/remote/admin"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	"github.com/lidofinance/tee-signer/tee-signer/handover"
)

// identityFile is what handover-target identity writes.
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

// manifest is what this tool writes next to the pages and handover-target
// import reads.
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
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "handover-source:", err)
		os.Exit(1)
	}
}

func hexHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func connect(path string) (*runnerclient.Client, error) {
	var c runnerclient.Connection
	if err := admincluster.ReadStrictJSON(path, &c); err != nil {
		return nil, err
	}
	c.ResolvePaths(filepath.Dir(path))
	return c.New(runnerclient.WithTimeout(5 * time.Minute))
}

// writeFile writes b to path through a temporary file and a rename.
func writeFile(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func run(args []string) error {
	fs := flag.NewFlagSet("handover-source", flag.ExitOnError)
	connPath := fs.String("conn", "", "Connection (JSON) of the source runner, with an admin client certificate")
	orderPath := fs.String("order", "", "the signed handover order")
	idPath := fs.String("identity", "", "the identity file of handover-target identity")
	out := fs.String("out", "", "the folder for the sealed pages")
	goFlag := fs.Bool("go", false, "start the handover under an active order: the source writes its tombstone and never signs again")
	fs.Parse(args)
	if *connPath == "" || *orderPath == "" || *idPath == "" || *out == "" {
		return errors.New("set -conn, -order, -identity and -out")
	}

	// The identity file, checked as far as this tool can.
	raw, err := os.ReadFile(*idPath)
	if err != nil {
		return err
	}
	var f identityFile
	if err := json.Unmarshal(raw, &f); err != nil || f.Format != identityFormat {
		return fmt.Errorf("%s: not a %s file (%v)", *idPath, identityFormat, err)
	}
	nonce, err := hex.DecodeString(f.Nonce)
	if err != nil {
		return fmt.Errorf("%s: nonce: %w", *idPath, err)
	}
	id, err := wire.DecodeIdentity(f.Identity)
	if err != nil {
		return fmt.Errorf("%s: %w", *idPath, err)
	}
	pub, err := setupwire.DecodePublished(f.Published)
	if err != nil {
		return fmt.Errorf("%s: %w", *idPath, err)
	}
	sh, err := pub.SetupHash()
	if err != nil {
		return err
	}
	switch {
	case hex.EncodeToString(sh[:]) != f.TargetSetupSHA256 || id.State.SetupHash != sh:
		return fmt.Errorf("%s: the published setup hashes to %x, the file names %s, the identity carries %x", *idPath, sh[:8], f.TargetSetupSHA256, id.State.SetupHash[:8])
	case hexHash(id.ImportKey) != f.ImportKeySHA256:
		return fmt.Errorf("%s: the import key is not the one the file names", *idPath)
	case id.Attestation == nil || !bytes.Equal(id.Attestation.UserData, backend.IdentityUserData(nonce, id)):
		return fmt.Errorf("%s: the identity's user data is not over its fields and nonce", *idPath)
	}

	order, err := os.ReadFile(*orderPath)
	if err != nil {
		return err
	}
	o, err := handoverorder.Decode(order)
	if err != nil {
		return fmt.Errorf("%s: %w", *orderPath, err)
	}
	hash, _ := o.Body.Hash()
	if o.Body.Target.SetupHash != sh {
		return fmt.Errorf("the order hands over to setup %x, the identity is of setup %x", o.Body.Target.SetupHash[:8], sh[:8])
	}

	// The folder: new, or one of the same import.
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}
	mpath := filepath.Join(*out, "manifest.json")
	if b, err := os.ReadFile(mpath); err == nil {
		var old manifest
		if err := json.Unmarshal(b, &old); err != nil {
			return fmt.Errorf("%s: %w", mpath, err)
		}
		if old.OrderSHA256 != hex.EncodeToString(hash[:]) || old.TargetSetupSHA256 != f.TargetSetupSHA256 || old.ImportKeySHA256 != f.ImportKeySHA256 {
			return fmt.Errorf("%s holds pages of another order, target or import key: use a new folder", *out)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	ctx := context.Background()
	cl, err := connect(*connPath)
	if err != nil {
		return err
	}
	defer cl.Close()
	// HANDOVER_ORDER and HANDOVER need the admin role: refuse before
	// anything goes out when this certificate lacks it.
	pr, err := admincluster.Probe(ctx, cl.Client)
	if err != nil {
		return err
	}
	if !pr.OK() {
		return fmt.Errorf("source: %s", pr)
	}
	ad := remoteadmin.Wrap(cl.Client)
	st, err := ad.HandoverOrder(ctx, order)
	if err != nil {
		return fmt.Errorf("source: handover order: %w", err)
	}
	switch st.Status {
	case handoverorder.Pending:
		return fmt.Errorf("order %x waits on the source until %s; run again then", hash[:6], time.Unix(int64(min(st.ActAt, 1<<62)), 0).UTC().Format(time.RFC3339))
	case handoverorder.Expired, handoverorder.Void:
		return fmt.Errorf("order %x is %s on the source (%s)", hash[:6], st.Status, st.Why)
	case handoverorder.Active:
		if !*goFlag {
			return fmt.Errorf("order %x is active: the first page makes the source write its tombstone and never sign again. Run again with -go to hand over", hash[:6])
		}
		fmt.Fprintf(os.Stderr, "order %x active: handing over; the source stops signing now\n", hash[:6])
	case handoverorder.Done:
		fmt.Fprintf(os.Stderr, "order %x done: the source handed over already; fetching the pages again\n", hash[:6])
	default:
		return fmt.Errorf("order %x: status %s", hash[:6], st.Status)
	}

	start := time.Now()
	m := manifest{Format: pagesFormat, OrderSHA256: hex.EncodeToString(hash[:]), TargetSetupSHA256: f.TargetSetupSHA256, ImportKeySHA256: f.ImportKeySHA256}
	seen := map[backend.Pubkey]bool{}
	var originKey [32]byte
	exits := 0
	for next := uint32(0); ; {
		resp, enc, err := ad.Handover(ctx, &handover.Request{Nonce: nonce, Identity: f.Identity, Policy: f.Published, Order: order, Start: next})
		if err != nil {
			return fmt.Errorf("source: handover at share %d: %w (run again to go on)", next, err)
		}
		if next == 0 {
			m.Mark, m.Total, originKey = resp.Mark, resp.Total, resp.Origin.Key
			if resp.Carry.Exits != nil {
				exits = len(resp.Carry.Exits.Entries)
			}
			fmt.Fprintf(os.Stderr, "the source stopped signing: %d shares, mark target %d source %d block %d, %d exits of the day carried\n",
				resp.Total, resp.Mark.TargetEpoch, resp.Mark.SourceEpoch, resp.Mark.BlockSlot, exits)
		} else if resp.Mark != m.Mark || resp.Total != m.Total {
			return errors.New("source: the mark or the total changed between pages")
		}
		if m.Total == 0 {
			// No share: one empty page still carries the mark and the origin
			// proof the target's import ends with.
			if err := writeFile(filepath.Join(*out, "page-000000.bin"), enc); err != nil {
				return err
			}
			m.Pages = []string{"page-000000.bin"}
			break
		}
		if len(resp.Shares) == 0 {
			return fmt.Errorf("source: an empty page at share %d of %d", next, m.Total)
		}
		for _, s := range resp.Shares {
			if seen[s.Pubkey] {
				return fmt.Errorf("source: validator %s twice", s.Pubkey)
			}
			seen[s.Pubkey] = true
		}
		name := fmt.Sprintf("page-%06d.bin", next)
		if err := writeFile(filepath.Join(*out, name), enc); err != nil {
			return err
		}
		m.Pages = append(m.Pages, name)
		next += uint32(len(resp.Shares))
		if next >= m.Total {
			break
		}
	}
	if uint32(len(seen)) != m.Total {
		return fmt.Errorf("source: %d distinct shares, the total is %d", len(seen), m.Total)
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFile(mpath, append(b, '\n')); err != nil {
		return err
	}
	fmt.Printf("handover pages: %d shares in %d pages in %s (%.1f s), origin key %x, mark target %d source %d block %d, %d exits carried; now run handover-target import\n",
		m.Total, len(m.Pages), *out, time.Since(start).Seconds(), originKey[:8], m.Mark.TargetEpoch, m.Mark.SourceEpoch, m.Mark.BlockSlot, exits)
	return nil
}
