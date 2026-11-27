//go:build darwin

package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

// osSwaps is empty: macOS has no /proc/swaps and no supported way to turn
// swap off. lockdown.Secrets reports whether the swap is encrypted.
const osSwaps = ""

// checkOutFS refuses a folder on a volume of the startup disk: the system
// volume or one under /System/Volumes (Data, where the home folders and
// /tmp are). It cannot tell a RAM disk from another disk, so for any other
// volume it prints a note on stderr and goes on.
func checkOutFS(dir string) error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return err
	}
	on, from := statfsString(st.Mntonname[:]), statfsString(st.Mntfromname[:])
	if on == "/" || strings.HasPrefix(on, "/System/Volumes/") {
		return fmt.Errorf("%s is on the startup disk (%s); split writes the shares only to a RAM disk", dir, on)
	}
	fmt.Fprintf(os.Stderr, "signer-admin split: note: %s is on %s (%s); split does not check that it is a RAM disk\n", dir, on, from)
	return nil
}

// statfsString is the C string in a name field of syscall.Statfs_t.
func statfsString(f []int8) string {
	b := make([]byte, 0, len(f))
	for _, c := range f {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}
