package main

import (
	"io"
	"slices"
	"strings"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/trusted-time/ntscatalog"
)

// minTimeServers is tee-signer/server.MinTimeServers: the fewest servers a
// runner takes with the default set and time_servers together.
const minTimeServers = 4

// checkTimeServersNote prints what the NTS catalog of this signer-admin
// build says about the time_servers of next, an open group, when they
// differ from those of active (nil: no active values known). The runner
// refuses a list its image's catalog does not take (server.CheckTimeServers):
// an unknown or withdrawn entry, an alt host without a Nitro port, fewer
// than minTimeServers servers or more than the quorum takes with the
// default set. The catalog is checked here, not in governance, which does
// not depend on trusted-time. This build's catalog may differ from the
// signers' images, so this is a warning, and the runner's check decides.
func checkTimeServersNote(out io.Writer, active, next *setupwire.Open) {
	if next == nil || active != nil && slices.Equal(active.TimeServers, next.TimeServers) {
		return
	}
	eps, err := ntscatalog.Builtin.WithConfirmed(next.TimeServers)
	switch {
	case err != nil:
		fprintf(out, "warning: time_servers: the NTS catalog of this signer-admin build refuses the list: %v; a runner whose image has this catalog refuses the update\n", err)
	case len(eps) < minTimeServers:
		fprintf(out, "warning: time_servers: %d servers with the default set of this build's catalog, a runner takes at least %d\n", len(eps), minTimeServers)
	default:
		fprintf(out, "time_servers: the NTS catalog of this signer-admin build takes the list (%d servers with the default set: %s)\n", len(eps), strings.Join(endpointIDs(eps), ","))
	}
}

func endpointIDs(eps []ntscatalog.Endpoint) []string {
	out := make([]string, len(eps))
	for i, e := range eps {
		out[i] = e.ID
	}
	return out
}
