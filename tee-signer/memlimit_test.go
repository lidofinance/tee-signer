package main

import (
	"math"
	"runtime/debug"
	"testing"
)

const meminfo = "MemTotal:         491520 kB\nMemFree:          400000 kB\nMemAvailable:     420000 kB\n"

// cgroupV1None is what cgroup v1 shows for a cgroup without a limit.
const cgroupV1None = "9223372036854771712\n"

// The limit is 3/4 of the smallest of the memory the kernel has and the
// cgroup limits; without any of them, none.
func TestMemoryLimit(t *testing.T) {
	for _, c := range []struct {
		name    string
		meminfo string
		cgroups []string
		want    int64
	}{
		{"enclave of 512 MiB, no cgroup limit", meminfo, []string{"max\n", ""}, 491520 << 10 * 3 / 4},
		{"no cgroup files", meminfo, []string{"", ""}, 491520 << 10 * 3 / 4},
		{"cgroup v1 without a limit", meminfo, []string{"", cgroupV1None}, 491520 << 10 * 3 / 4},
		{"v2 container of 1 GiB on a larger host", "MemTotal: 4194304 kB\n", []string{"1073741824\n", ""}, 768 << 20},
		{"v1 container of 1 GiB on a larger host", "MemTotal: 4194304 kB\n", []string{"", "1073741824\n"}, 768 << 20},
		{"cgroup above the host", "MemTotal: 1048576 kB\n", []string{"8589934592\n", ""}, 768 << 20},
		{"no meminfo, cgroup of 1 GiB", "", []string{"1073741824\n", ""}, 768 << 20},
		{"nothing readable", "", []string{"", ""}, 0},
		{"garbage", "MemTotal: lots kB\n", []string{"many\n", "-1\n"}, 0},
	} {
		var cg [][]byte
		for _, s := range c.cgroups {
			cg = append(cg, []byte(s))
		}
		if got := memoryLimit([]byte(c.meminfo), cg...); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
}

// setMemoryLimit sets the derived limit, keeps one GOMEMLIMIT gives, and
// sets none when nothing gives a size.
func TestSetMemoryLimit(t *testing.T) {
	old := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(old) })

	t.Setenv("GOMEMLIMIT", "")
	debug.SetMemoryLimit(math.MaxInt64)
	want := int64(491520 << 10 * 3 / 4)
	if got := setMemoryLimitFrom([]byte(meminfo), []byte("max")); got != want || debug.SetMemoryLimit(-1) != want {
		t.Fatalf("derived limit: %d, runtime %d, want %d", got, debug.SetMemoryLimit(-1), want)
	}

	debug.SetMemoryLimit(math.MaxInt64)
	if got := setMemoryLimitFrom(nil, nil); got != 0 || debug.SetMemoryLimit(-1) != math.MaxInt64 {
		t.Fatalf("nothing readable: %d, runtime %d", got, debug.SetMemoryLimit(-1))
	}

	t.Setenv("GOMEMLIMIT", "300MiB")
	debug.SetMemoryLimit(300 << 20)
	if got := setMemoryLimitFrom([]byte(meminfo), []byte("max")); got != 0 || debug.SetMemoryLimit(-1) != 300<<20 {
		t.Fatalf("GOMEMLIMIT set: %d, runtime %d", got, debug.SetMemoryLimit(-1))
	}
}
