package setup

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// The Nitro port map, fixed in the image. The
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
)

// NitroNTSKE are the NTS-KE servers of the NTS clock (trusted-time/ntscatalog,
// the entries a runner dials) on their fixed ports 8005 to 8008. A test of
// the nts build (tee-signer) checks hosts and ports against the catalog.
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
// the NTS-KE servers, each on its fixed port. Nothing else gets a route.
func NitroRoutes(p *setupwire.PlatformConfig) []Route {
	region := p.SealingKeyRelease.Region
	routes := []Route{
		{Port: PortKMS, Host: "kms." + region + ".amazonaws.com", HostPort: 443},
		{Port: PortSTS, Host: "sts." + region + ".amazonaws.com", HostPort: 443},
		{Port: PortCoarse, Host: CoarseHost, HostPort: 443},
		{Port: PortMarkBucket, Host: MarkBucketHost(&p.SlashingLogStore), HostPort: 443},
	}
	return append(routes, NitroNTSKE...)
}

// MarkBucketHost is the virtual-hosted S3 name of the mark bucket, the
// host the S3 mark log dials (platform-aws/s3log).
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
	routes := NitroRoutes(&s.Wire.Platform)
	var b strings.Builder
	for _, r := range routes {
		fmt.Fprintf(&b, "%d %s %d\n", r.Port, r.Host, r.HostPort)
	}
	return b.String(), nil
}
