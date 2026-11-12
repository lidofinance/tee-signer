package setup

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/trusted-time/ntscatalog"
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

// NitroNTSKE are the NTS-KE hosts a runner of this image may dial
// (trusted-time/ntscatalog Endpoints) on their fixed catalog ports. The
// parent routes all of them, since it cannot see which ones the enclave's
// command chose (-nts-terms-confirmed); the enclave dials only its own
// choice. A port belongs to its catalog host for good. The routes of hosts
// outside the default set (ntscatalog Dialed) are Optional.
var NitroNTSKE = nitroNTSKE()

func nitroNTSKE() []Route {
	def := map[string]bool{}
	for _, e := range ntscatalog.Builtin.Dialed() {
		def[e.Host] = true
	}
	var out []Route
	for _, e := range ntscatalog.Builtin.Endpoints() {
		out = append(out, Route{Port: e.NitroPort, Host: e.Host, HostPort: 4460, Optional: !def[e.Host]})
	}
	return out
}

// CoarseHost is the coarse-time host that names no region.
const CoarseHost = "www.cloudflare.com"

// Route is one vsock-proxy route: the enclave dials vsock port Port on the
// parent, which connects to Host:HostPort.
type Route struct {
	Port     uint32
	Host     string
	HostPort int
	// Optional: a runner of the default set does not dial it (an NTS-KE
	// host only a -nts-terms-confirmed deployment names). The parent goes
	// on if its proxy does not start.
	Optional bool
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
// one vsock-proxy per route: "PORT HOST HOSTPORT", and " optional" after
// an Optional route.
func NitroProxyLines(s *Setup) (string, error) {
	if s.Wire.Platform.Platform != setupwire.PlatformNitro {
		return "", fmt.Errorf("setup is for %s, not nitro", s.Wire.Platform.Platform)
	}
	routes := NitroRoutes(&s.Wire.Platform)
	var b strings.Builder
	for _, r := range routes {
		fmt.Fprintf(&b, "%d %s %d", r.Port, r.Host, r.HostPort)
		if r.Optional {
			b.WriteString(" optional")
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}
