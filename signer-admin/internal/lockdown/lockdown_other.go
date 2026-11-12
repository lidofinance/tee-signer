//go:build !linux

package lockdown

import (
	"fmt"
	"io"
)

// Secrets on an OS other than Linux: nothing stops a core dump or swap
// of the keys here, so it only says so.
func Secrets(warn io.Writer) error {
	fmt.Fprintln(warn, "warning: core dumps and swap are not turned off on this OS; the keys can reach a disk")
	return nil
}
