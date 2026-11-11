//go:build nts

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/lidofinance/tee-signer/platform/cloudroots"
	"github.com/lidofinance/tee-signer/trusted-time/clock"
	"github.com/lidofinance/tee-signer/trusted-time/nts"
)

// A runner built with -tags nts links the Rust NTS library (nts/) and has
// the NTS clock (platforms_nts.go, RUNNER_NTS_CLOCK=1). Two flags of its own,
// each alone on the command line, run a check and exit:
//
//	runner -nts-selftest     prints the library version and runs its AES-SIV
//	                         self-test: the library is in the binary and runs
//	                         on this architecture. No network.
//	runner -nts-clock-check  one round of the NTS clock as the runner would run
//	                         it: the HTTPS-date coarse reading
//	                         (RUNNER_NTS_COARSE_URLS; RUNNER_NTS_REGION fills
//	                         in {region}), the start round of the runner's
//	                         schedule (one NTS-KE and one query per public
//	                         server, with RUNNER_CLOCK_PROTOCOL=ntp one plain
//	                         NTP query and no NTS-KE; the 1 s query timeout),
//	                         the quorum. Prints the status
//	                         and exits 0 if a quorum formed with a bound under
//	                         the limit. For a pre-flight from the network the
//	                         runner will run in.
//
// Builds without the tag have neither this file nor the flags.
func init() {
	if len(os.Args) != 2 {
		return
	}
	switch os.Args[1] {
	case "-nts-selftest":
		if err := nts.AESSIVSelfTest(); err != nil {
			fmt.Fprintln(os.Stderr, "runner:", nts.Version()+":", err)
			os.Exit(1)
		}
		fmt.Println(nts.Version() + ": AES-SIV self-test ok")
		os.Exit(0)
	case "-nts-clock-check":
		os.Exit(ntsClockCheck())
	}
}

func ntsClockCheck() int {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	// A pinned pool, as a cloud runner's client has: each coarse source then
	// trusts its catalog entry's roots only (coarseClient).
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{RootCAs: cloudroots.Pool(cloudroots.AWS, cloudroots.Google, cloudroots.Azure)}
	return ntsClockCheckWith(&http.Client{Transport: t}, nil, log)
}

// ntsCheckClock is the clock of -nts-clock-check: the runner's clock on the
// runner's schedule, without a seed. Its one Refresh is the start round,
// which asks every server once with the 1 s query timeout of the shift
// schedule, so a server that answers in 1 to 5 s fails here as it would in
// the runner. It refuses the server counts the runner refuses at start,
// and has no start wait, so it contacts the servers at once.
func ntsCheckClock(client *http.Client, dial nts.DialFunc, protocol clock.Protocol, log *slog.Logger) (*clock.NTS, *clock.Anchored, error) {
	n, coarse, err := newNTSClock(client, dial, os.Getenv("RUNNER_NTS_REGION"), protocol, log)
	if err != nil {
		return nil, nil, err
	}
	if err := ntsSchedule(n, nil); err != nil {
		return nil, nil, err
	}
	n.StartDelay = -1
	return n, coarse, nil
}

// ntsClockCheckWith is ntsClockCheck with the coarse client and the dialer
// as parameters, for the test.
func ntsClockCheckWith(client *http.Client, dial nts.DialFunc, log *slog.Logger) int {
	// The pre-flight signs nothing, so it takes the variable in any build.
	protocol, err := clockProtocol(true)
	if err != nil {
		fmt.Fprintln(os.Stderr, "runner:", err)
		return 2
	}
	if protocol == clock.ProtocolNTP {
		log.Warn(plainNTPWarning)
	}
	n, coarse, err := ntsCheckClock(client, dial, protocol, log)
	if err != nil {
		fmt.Fprintln(os.Stderr, "runner:", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := coarse.Refresh(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "runner: coarse clock:", err)
		return 1
	}
	rerr := n.Refresh(ctx)
	st := n.Status()
	fmt.Println(nts.Version(), "protocol="+string(protocol))
	for _, s := range n.Servers {
		p := st.Peers[s.Operator]
		line := fmt.Sprintf("%-10s %-20s ke=%d queries=%d samples=%d", s.Operator, s.Host, p.Stats.KEOK, p.Stats.Queries, p.Stats.Samples)
		if p.Sample != nil {
			line += fmt.Sprintf(" delay=%v bound=%v offset_from_host=%v stratum=%d cookies=%d",
				p.Sample.Delay.Round(time.Microsecond), p.Sample.Bound.Round(time.Microsecond),
				p.Stats.LastOffsetFromHost.Round(time.Microsecond), p.Sample.Stratum, p.Sample.CookiesHeld)
		}
		if p.LastErr != "" {
			line += " error=" + p.LastErr
		}
		fmt.Println(line)
	}
	_, bound, berr := n.Bounded()
	fmt.Printf("quorum members=%v bound=%v offset_from_host=%v coarse_diff=%v\n", st.Members, bound,
		st.OffsetFromHost.Round(time.Microsecond), st.CoarseDiff.Round(time.Millisecond))
	if rerr != nil || berr != nil {
		fmt.Fprintln(os.Stderr, "runner: nts clock check failed:", rerr, berr)
		return 1
	}
	return 0
}
