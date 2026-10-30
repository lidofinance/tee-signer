// Package cluster reads the cluster files of signer-admin: cluster.json,
// which lists the signers of one cluster, and each signer's connection
// file (cloud.json, as attest/runnerclient reads it). It reads a signer's
// attested state and probes the client role of a connection (probe.go).
// handover-target shares it with signer-admin.
//
// cluster.json lists the signers of one cluster, with paths relative to it:
//
//	{
//	  "signers": [
//	    {"name": "azure-1", "cloud": "azure-1/cloud.json", "setup": "setups/azure-1.setup"}
//	  ],
//	  "updates": "updates"
//	}
//
// cloud is the signer's connection file (address, client_cert, client_key,
// attestation). For signer-admin it names the admin client certificate.
// setup is the binary setup signer-admin setup wrote for it. updates is
// the folder where push keeps a copy of each update a signer took.
package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/governance/flavor"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// File is cluster.json.
type File struct {
	Signers []struct {
		Name  string `json:"name"`
		Cloud string `json:"cloud"`
		Setup string `json:"setup"`
	} `json:"signers"`
	Updates string `json:"updates,omitempty"`
}

// Member is one signer of the cluster with its setup, decoded.
type Member struct {
	Name      string
	CloudPath string
	Setup     *setupwire.Setup
	SetupRaw  []byte
	SetupHash [32]byte
}

// Cluster is a loaded cluster.json.
type Cluster struct {
	Updates string // folder of the updates push keeps
	Members []*Member
}

// ReadStrictJSON decodes a JSON file and refuses unknown fields and
// trailing data.
func ReadStrictJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if dec.More() {
		return fmt.Errorf("%s: data after the JSON object", path)
	}
	return nil
}

// Load reads cluster.json and the setup of each signer. It refuses a
// cluster whose setups name more than one cluster_id or chain, or start
// from different config groups: one signed update must fit every signer.
// only, if not empty, keeps the signers of these names, in that order.
func Load(path string, only []string) (*Cluster, error) {
	var cf File
	if err := ReadStrictJSON(path, &cf); err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	rel := func(p string) string {
		if filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(dir, p)
	}
	updates := cf.Updates
	if updates == "" {
		updates = "updates"
	}
	c := &Cluster{Updates: rel(updates)}
	if len(cf.Signers) == 0 {
		return nil, fmt.Errorf("%s: no signers", path)
	}
	seen := map[string]bool{}
	for i, s := range cf.Signers {
		if s.Cloud == "" || s.Setup == "" {
			return nil, fmt.Errorf("%s: signer %d needs cloud and setup", path, i+1)
		}
		m := &Member{Name: s.Name, CloudPath: rel(s.Cloud)}
		var err error
		if m.SetupRaw, err = os.ReadFile(rel(s.Setup)); err != nil {
			return nil, err
		}
		if m.Setup, err = setupwire.DecodeSetup(m.SetupRaw); err != nil {
			return nil, fmt.Errorf("%s: %w", rel(s.Setup), err)
		}
		if m.SetupHash, err = m.Setup.Hash(); err != nil {
			return nil, fmt.Errorf("%s: %w", rel(s.Setup), err)
		}
		if m.Name == "" {
			m.Name = m.Setup.SignerName
		}
		if seen[m.Name] {
			return nil, fmt.Errorf("%s: signer %q is listed twice", path, m.Name)
		}
		seen[m.Name] = true
		if len(c.Members) > 0 {
			if err := SameCluster(c.Members[0], m); err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
		}
		c.Members = append(c.Members, m)
	}
	if len(only) > 0 {
		var keep []*Member
		for _, name := range only {
			i := slices.IndexFunc(c.Members, func(m *Member) bool { return m.Name == name })
			if i < 0 {
				return nil, fmt.Errorf("-signers: %q is not a signer of %s", name, path)
			}
			keep = append(keep, c.Members[i])
		}
		c.Members = keep
	}
	return c, nil
}

// SameCluster checks that b belongs to a's cluster: the same cluster_id,
// chain, safety settings and handover_generation, and the same version 0
// of both config groups: the same values and, once drawn, the same salts,
// so the groups' hashes agree and one signed update serves every signer.
func SameCluster(a, b *Member) error {
	sa, sb := a.Setup, b.Setup
	switch {
	case sa.ClusterID != sb.ClusterID:
		return fmt.Errorf("signers %s and %s have different cluster_id", a.Name, b.Name)
	case sa.Chain != sb.Chain:
		return fmt.Errorf("signers %s and %s have different chains", a.Name, b.Name)
	case sa.Safety != sb.Safety || sa.HandoverGeneration != sb.HandoverGeneration:
		return fmt.Errorf("signers %s and %s have different safety settings or handover generations", a.Name, b.Name)
	case sa.SigningMode != sb.SigningMode:
		return fmt.Errorf("signers %s and %s have different signing_mode (%s, %s)", a.Name, b.Name, sa.SigningMode, sb.SigningMode)
	}
	la, err1 := sa.Locked.Encode()
	lb, err2 := sb.Locked.Encode()
	oa, err3 := sa.Open.Encode()
	ob, err4 := sb.Open.Encode()
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		return err
	}
	if !bytes.Equal(la, lb) {
		return fmt.Errorf("signers %s and %s start from different %s groups", a.Name, b.Name, setupwire.GroupLocked)
	}
	if !bytes.Equal(oa, ob) {
		return fmt.Errorf("signers %s and %s start from different %s groups", a.Name, b.Name, setupwire.GroupOpen)
	}
	if !sa.Salted() || !sb.Salted() {
		return nil
	}
	for _, g := range []setupwire.Group{setupwire.GroupLocked, setupwire.GroupOpen} {
		ha, _ := sa.GroupHash(g)
		hb, _ := sb.GroupHash(g)
		if ha != hb {
			return fmt.Errorf("signers %s and %s have different salts of the %s group; signer-admin setup draws one set for a cluster", a.Name, b.Name, g)
		}
	}
	return nil
}

// LoadConn reads a signer's connection file as runnerclient does: fields
// of other tools (accounts, slots_per_epoch of the signing client) are left
// alone, and paths are relative to the file.
func LoadConn(path string) (*runnerclient.Connection, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var conn runnerclient.Connection
	if err := json.Unmarshal(b, &conn); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	conn.ResolvePaths(filepath.Dir(path))
	return &conn, nil
}

// State is what the tool reads of one signer.
type State struct {
	State  *backend.SetupState
	Health *backend.Health
	// Flavor is the runner's build flavour, from HEALTH's version. A
	// testnet runner's governance times run in minutes; the connection
	// refuses one unless cloud.json sets allow_testnet_build.
	Flavor flavor.Flavor
}

// ReadState connects with conn (TLS, attestation, setup pins), asks for
// HEALTH, then reads the setup state of a fresh, verified IDENTITY. It
// refuses a signer whose setup_hash is not the setup built for it. The
// caller closes the client.
func ReadState(ctx context.Context, m *Member, conn *runnerclient.Connection, timeout time.Duration) (*State, *runnerclient.Client, error) {
	cl, err := conn.New(runnerclient.WithTimeout(timeout))
	if err != nil {
		return nil, nil, err
	}
	h, err := cl.Health(ctx)
	if err != nil {
		cl.Close()
		return nil, nil, err
	}
	s, err := cl.SetupState(ctx, cl.Verify)
	if err != nil {
		cl.Close()
		return nil, nil, err
	}
	if s.SetupHash != m.SetupHash {
		cl.Close()
		return nil, nil, fmt.Errorf("IDENTITY shows setup %x, cluster.json names the setup %x", s.SetupHash[:4], m.SetupHash[:4])
	}
	return &State{State: s, Health: h, Flavor: flavor.FromVersion(h.Version)}, cl, nil
}

// EditCloudJSON rewrites the attestation section of a cloud.json with
// edit, keeps every other field as it is, and replaces the file in one
// step with the same mode. Keys come out sorted.
func EditCloudJSON(path string, edit func(att map[string]json.RawMessage) error) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	att := map[string]json.RawMessage{}
	if raw, ok := top["attestation"]; ok {
		if err := json.Unmarshal(raw, &att); err != nil {
			return fmt.Errorf("%s: attestation: %w", path, err)
		}
	}
	if err := edit(att); err != nil {
		return err
	}
	if top["attestation"], err = json.Marshal(att); err != nil {
		return err
	}
	out, err := json.MarshalIndent(top, "", "  ")
	if err != nil {
		return err
	}
	return WriteAtomic(path, append(out, '\n'), fi.Mode().Perm())
}

// WriteAtomic writes a file next to path and renames it over path.
func WriteAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
