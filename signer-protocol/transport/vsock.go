//go:build platform_aws

package transport

import (
	"net"

	"github.com/mdlayher/vsock"
)

// Only the AWS build has vsock (see the package comment): the other builds
// do not link github.com/mdlayher/vsock or the socket and x/sys code under it.
func init() {
	vsockDial = func(cid, port uint32) (net.Conn, error) { return vsock.Dial(cid, port, nil) }
	vsockListen = func(cid, port uint32) (net.Listener, error) { return vsock.ListenContextID(cid, port, nil) }
}
