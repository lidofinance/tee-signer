//go:build !verifierselect

// Command identity-check connects to one runner the way the Dirk fork's cloud
// adapter does and checks its attestation, several times, each time on a new
// connection. It sends no request but IDENTITY, and one HEALTH after the
// first accepted run, whose version names the runner's build flavour
// (default, or testnet: a testnet runner is refused unless the config sets
// allow_testnet_build). It imports nothing.
//
//	identity-check -config <secrets-dir>/gcp-signer.json -address tcp:HOST:7100
//
// The config is a runnerclient.Connection as JSON: address, client_cert,
// client_key and attestation (verifier and its settings). Each run opens a
// connection with mutual TLS, asks IDENTITY with a fresh nonce, and runs the
// verifier of the config on the answer. A refusal prints its reason. The
// first accepted run also prints the claims of a Confidential Space token
// (names and values, never the token), so the real claims can be compared
// with the WIF condition and the verifier.
//
// -gcp-image-digest replaces the expected digest, to see a refusal for a
// wrong image. -health asks HEALTH once more on a verified connection and
// prints the answer as JSON: clock, number of keys and the signer core's
// counters (signatures, hash-to-curve cache hits and misses, watermark
// writes, exact repeats). The exit status is 0 only if every run was accepted.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/governance/flavor"
	"github.com/lidofinance/tee-signer/platform/jwtclaims"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("identity-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		cfgPath = fs.String("config", "", "runnerclient.Connection as JSON (required)")
		addr    = fs.String("address", "", "replaces the address of the config (tcp:HOST:PORT)")
		digest  = fs.String("gcp-image-digest", "", "replaces gcp_image_digest of the config, to test a refusal")
		runs    = fs.Int("n", 3, "number of runs, each on a new connection")
		timeout = fs.Duration("timeout", 30*time.Second, "time limit of one run")
		health  = fs.Bool("health", false, "also print the runner's HEALTH answer as JSON")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *cfgPath == "" || *runs < 1 {
		fmt.Fprintln(stderr, "identity-check: -config is required and -n must be at least 1")
		return 2
	}
	b, err := os.ReadFile(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "identity-check:", err)
		return 2
	}
	var conn runnerclient.Connection
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&conn); err != nil {
		fmt.Fprintln(stderr, "identity-check: config:", err)
		return 2
	}
	conn.ResolvePaths(filepath.Dir(*cfgPath))
	if *addr != "" {
		conn.Address = *addr
	}
	if *digest != "" {
		conn.Attestation.GCPImageDigest = *digest
	}
	if err := conn.Validate(); err != nil {
		fmt.Fprintln(stderr, "identity-check:", err)
		return 2
	}

	accepted := 0
	for i := 1; i <= *runs; i++ {
		id, err := once(&conn, *timeout)
		if err != nil {
			fmt.Fprintf(stdout, "run %d: REFUSED: %v\n", i, err)
			continue
		}
		accepted++
		fmt.Fprintf(stdout, "run %d: accepted (%s)\n", i, conn.Attestation.Verifier)
		if accepted == 1 {
			if h, err := healthOnce(&conn, *timeout); err != nil {
				fmt.Fprintf(stdout, "flavour: %v\n", err)
			} else {
				fmt.Fprintf(stdout, "flavour: %s build (version %s)\n", flavor.FromVersion(h.Version), h.Version)
			}
		}
		if accepted == 1 && id.Attestation != nil && id.Attestation.Format == "gcp-confidential-space-jwt" {
			lines, err := claimLines(id.Attestation.Document)
			if err != nil {
				fmt.Fprintf(stdout, "claims: %v\n", err)
				continue
			}
			fmt.Fprintln(stdout, "claims of the Confidential Space token:")
			for _, l := range lines {
				fmt.Fprintln(stdout, "  "+l)
			}
		}
	}
	fmt.Fprintf(stdout, "accepted %d of %d\n", accepted, *runs)
	if *health && accepted > 0 {
		h, err := healthOnce(&conn, *timeout)
		if err != nil {
			fmt.Fprintf(stdout, "health: %v\n", err)
			return 1
		}
		b, err := json.Marshal(h)
		if err != nil {
			fmt.Fprintf(stdout, "health: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "health %s\n", b)
	}
	if accepted != *runs {
		return 1
	}
	return 0
}

// once opens a new connection (the client's dial checks the identity of a
// fresh nonce), then asks IDENTITY again and runs the verifier on that answer.
func once(conn *runnerclient.Connection, timeout time.Duration) (*backend.Identity, error) {
	cl, err := conn.New(runnerclient.WithTimeout(timeout))
	if err != nil {
		return nil, err
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	id, err := cl.Identity(ctx, nonce)
	if err != nil {
		return nil, err
	}
	if cl.Verify == nil {
		return nil, errors.New("the client has no verifier")
	}
	if err := cl.Verify(ctx, nonce, id); err != nil {
		return nil, fmt.Errorf("attestation: %w", err)
	}
	return id, nil
}

// healthOnce opens a verified connection and asks HEALTH.
func healthOnce(conn *runnerclient.Connection, timeout time.Duration) (*backend.Health, error) {
	cl, err := conn.New(runnerclient.WithTimeout(timeout))
	if err != nil {
		return nil, err
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return cl.Health(ctx)
}

// claimLines lists the claims of a token as sorted "path = value" lines. The
// values of the container's env claims are left out: a variable passed to the
// container is a value that must not be shown.
func claimLines(token []byte) ([]string, error) {
	c, err := jwtclaims.Claims(string(token))
	if err != nil {
		return nil, err
	}
	var out []string
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch t := v.(type) {
		case map[string]any:
			for k, x := range t {
				p := k
				if path != "" {
					p = path + "." + k
				}
				walk(p, x)
			}
		case []any:
			if strings.HasPrefix(path, "submods.container.env") {
				out = append(out, fmt.Sprintf("%s = <%d entries, values not shown>", path, len(t)))
				return
			}
			parts := make([]string, len(t))
			for i, x := range t {
				parts[i] = fmt.Sprint(x)
			}
			out = append(out, path+" = ["+strings.Join(parts, ", ")+"]")
		default:
			if strings.HasPrefix(path, "submods.container.env") {
				out = append(out, path+" = <value not shown>")
				return
			}
			out = append(out, fmt.Sprintf("%s = %v", path, t))
		}
	}
	walk("", c)
	sort.Strings(out)
	return out, nil
}
