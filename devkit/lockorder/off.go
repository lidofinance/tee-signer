//go:build !lockcheck

package lockorder

func acquire(any, string) {}
func held(any, string)    {}
func release(any)         {}

// Enabled reports whether this build checks the lock order.
const Enabled = false
