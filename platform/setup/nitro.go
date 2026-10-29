package setup

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// The Nitro port map, fixed in the image (setup-phase.md, section 1). The
// enclave has no network: the parent forwards each of these vsock ports to
// one host (vsock-proxy) or to the NTP servers (udprelay). Port 8003, the
// DynamoDB clone guard of the old images, is gone.
const (
	NitroAgent       = "vsock:3:7101" // host agent: store, credentials, the setup
	NitroNTPRelay    = "vsock:3:7102" // udprelay, NTP of the NTS clock
	NitroRecordCreds = "record/writer-credentials.kms"

	nitroParentCID = 3
	PortKMS        = 8000
	PortSTS        = 8001
	PortCoarse     = 8002 // the third coarse-time host
	PortMarkBucket = 8004
	// The peer endpoint block: the setup's peer_attestation_hosts, in their sorted
	// order, on 8010 up to 8025. The handover verifier fetches its key
	// sets through these (an Azure peer's MAA host, Google's Confidential
	// Space hosts).
	PortPeerFirst  = 8010
	NitroPeerPorts = 16
)

// NitroNTSKE are the NTS-KE servers of the NTS clock (runner/nts.
// PublicServers) on their fixed ports 8005 to 8008. A test of the nts build
// checks that the two lists name the same hosts.
var NitroNTSKE = []Route{
	{Port: 8005, Host: "time.cloudflare.com", HostPort: 4460},
	{Port: 8006, Host: "nts.netnod.se", HostPort: 4460},
	{Port: 8007, Host: "ptbtime1.ptb.de", HostPort: 4460},
	{Port: 8008, Host: "ntppool1.time.nl", HostPort: 4460},
}

// CoarseHost is the coarse-time host that names no region.
const CoarseHost = "www.cloudflare.com"

// Route is one vsock-proxy route: the enclave dials vsock port Port on the
// parent, which connects to Host:HostPort.
type Route struct {
	Port     uint32
	Host     string
	HostPort int
}

func (r Route) hostPort() string { return r.Host + ":" + strconv.Itoa(r.HostPort) }

// NitroRoutes is the proxy route list of a setup's platform part: KMS and
// STS in the key release region, the coarse-time host, the mark bucket and
// the NTS-KE servers, each on its fixed port, then the peer attestation hosts on
// the peer block. It refuses more peer attestation hosts than the block holds and
// a peer endpoint that a fixed route already serves. Nothing else gets a
// route.
func NitroRoutes(p *setupwire.PlatformConfig) ([]Route, error) {
	region := p.SealingKeyRelease.Region
	routes := []Route{
		{Port: PortKMS, Host: "kms." + region + ".amazonaws.com", HostPort: 443},
		{Port: PortSTS, Host: "sts." + region + ".amazonaws.com", HostPort: 443},
		{Port: PortCoarse, Host: CoarseHost, HostPort: 443},
		{Port: PortMarkBucket, Host: MarkBucketHost(&p.SlashingLogStore), HostPort: 443},
	}
	routes = append(routes, NitroNTSKE...)
	if n := len(p.PeerAttestationHosts); n > NitroPeerPorts {
		return nil, fmt.Errorf("setup: %d peer_attestation_hosts, but the nitro port map has %d ports for them (%d to %d)",
			n, NitroPeerPorts, PortPeerFirst, PortPeerFirst+NitroPeerPorts-1)
	}
	fixed := map[string]uint32{}
	for _, r := range routes {
		fixed[r.hostPort()] = r.Port
	}
	for i, e := range p.PeerAttestationHosts {
		if err := setupwire.CheckEndpoint(e); err != nil {
			return nil, fmt.Errorf("setup: %w", err)
		}
		if port, ok := fixed[e]; ok {
			return nil, fmt.Errorf("setup: peer_attestation_hosts %s is the fixed route of port %d; leave it out", e, port)
		}
		host, portText, _ := strings.Cut(e, ":")
		port, _ := strconv.Atoi(portText)
		routes = append(routes, Route{Port: uint32(PortPeerFirst + i), Host: host, HostPort: port})
	}
	return routes, nil
}

// MarkBucketHost is the virtual-hosted S3 name of the mark bucket, the
// host the S3 mark log dials (runner/markstore/s3log).
func MarkBucketHost(mark *setupwire.Store) string {
	return mark.Bucket + ".s3." + mark.Region + ".amazonaws.com"
}

// RouteOption writes routes as the nitro platform's proxy option:
// host:port=vsock:3:PORT, comma-separated.
func RouteOption(routes []Route) string {
	parts := make([]string, len(routes))
	for i, r := range routes {
		parts[i] = fmt.Sprintf("%s=vsock:%d:%d", r.hostPort(), nitroParentCID, r.Port)
	}
	return strings.Join(parts, ",")
}

// NitroProxyLines are the lines the parent's start script reads to start
// one vsock-proxy per route: "PORT HOST HOSTPORT".
func NitroProxyLines(s *Setup) (string, error) {
	if s.Wire.Platform.Platform != setupwire.PlatformNitro {
		return "", fmt.Errorf("setup is for %s, not nitro", s.Wire.Platform.Platform)
	}
	routes, err := NitroRoutes(&s.Wire.Platform)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, r := range routes {
		fmt.Fprintf(&b, "%d %s %d\n", r.Port, r.Host, r.HostPort)
	}
	return b.String(), nil
}
