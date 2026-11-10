package main

import (
	"bufio"
	"bytes"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
)

const (
	meminfoPath = "/proc/meminfo"
	// cgroupV2Max and cgroupV1Max hold the memory limit of this process's
	// cgroup; "max" or a very large number means none.
	cgroupV2Max = "/sys/fs/cgroup/memory.max"
	cgroupV1Max = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
)

// setMemoryLimit gives the Go runtime a soft memory limit of 3/4 of the
// memory the runner may use: the smallest of the kernel's MemTotal and
// the cgroup limit. The rest is for the kernel, the in-memory root file
// system of an enclave image and the core's C allocations. Without a
// limit the heap may grow to twice its live size before the next
// collection (GOGC 100). An enclave has no swap, so the kernel could
// kill the runner for memory that is garbage; with the limit the runtime
// collects first. A GOMEMLIMIT in the environment takes precedence.
// It returns the limit it set, 0 if it set none.
func setMemoryLimit() int64 {
	meminfo, _ := os.ReadFile(meminfoPath)
	v2, _ := os.ReadFile(cgroupV2Max)
	v1, _ := os.ReadFile(cgroupV1Max)
	return setMemoryLimitFrom(meminfo, v2, v1)
}

// setMemoryLimitFrom sets memoryLimit(meminfo, cgroups...) as the
// runtime's limit and returns it. With GOMEMLIMIT set, or a limit of 0,
// it sets nothing and returns 0.
func setMemoryLimitFrom(meminfo []byte, cgroups ...[]byte) int64 {
	if os.Getenv("GOMEMLIMIT") != "" {
		return 0
	}
	limit := memoryLimit(meminfo, cgroups...)
	if limit > 0 {
		debug.SetMemoryLimit(limit)
	}
	return limit
}

// memoryLimit is 3/4 of the smallest of MemTotal in meminfo and the
// cgroup limits; 0 if none of them has a number.
func memoryLimit(meminfo []byte, cgroups ...[]byte) int64 {
	var total int64
	sc := bufio.NewScanner(bytes.NewReader(meminfo))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 3 && f[0] == "MemTotal:" && f[2] == "kB" {
			if kb, err := strconv.ParseInt(f[1], 10, 64); err == nil && kb > 0 && kb < 1<<40 {
				total = kb << 10
			}
		}
	}
	for _, c := range cgroups {
		if b, err := strconv.ParseInt(strings.TrimSpace(string(c)), 10, 64); err == nil && b > 0 && (total == 0 || b < total) {
			total = b
		}
	}
	return total / 4 * 3
}
