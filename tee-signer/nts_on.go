//go:build nts

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/nts"
)

// A runner built with -tags nts has the NTS client (trusted-time/nts) and
// the NTS clock (platforms_nts.go, RUNNER_NTS_CLOCK=1). Two flags of its own,
// each alone on the command line, run a check and exit:
//
//	runner -nts-selftest     prints the client version and runs its AES-SIV
//	                         self-test: the client is in the binary and runs
//	                         on this architecture. No network.
//	runner -nts-clock-check  one round of the NTS clock as the runner would run
//	                         it: the HTTPS-date coarse reading
//	                         (RUNNER_NTS_COARSE_URLS; RUNNER_NTS_REGION fills
//	                         in {region}), one NTS-KE and one query
//	                         per public server, the quorum. Prints the status
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
	n, coarse, err := newNTSClock(http.DefaultClient, nil, os.Getenv("RUNNER_NTS_REGION"), log)
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
	fmt.Println(nts.Version())
	for _, s := range nts.PublicServers {
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
