# The C core on its own, as a trusted application would build it: C11,
# freestanding, every warning an error, and no outside symbol but memcpy,
# memset and memcmp. The Go tests build the same sources through cgo
# (ntscore.go) and are the core's test suite; this Makefile is the build
# check that cgo's flags do not give.
#
#   make check     build the library freestanding and check its symbols
#   make clean
CC ?= cc
BUILD ?= build
WARN := -Wall -Wextra -Werror -Wshadow -Wvla -Wstrict-prototypes -Wmissing-prototypes
CORE_CFLAGS := -std=c11 -O2 -ffreestanding -fno-builtin -fno-common -fno-stack-protector -U_FORTIFY_SOURCE $(WARN) -I. $(CFLAGS)
SRCS := siv.c ntp.c sample.c quorum.c ke.c client.c
OBJS := $(SRCS:%.c=$(BUILD)/%.o)

.PHONY: check lib symbols clean

check: symbols

lib: $(BUILD)/libnts_core.a

$(BUILD)/%.o: %.c nts_core.h
	@mkdir -p $(BUILD)
	$(CC) $(CORE_CFLAGS) -c -o $@ $<

$(BUILD)/libnts_core.a: $(OBJS)
	rm -f $@
	ar rcs $@ $^

# Undefined symbols of the archive, minus those it defines itself, minus
# the three allowed: the same rule as signer-core's.
symbols: $(BUILD)/libnts_core.a
	@nm -u $(BUILD)/libnts_core.a | awk 'NF==2{print $$2}' | sort -u > $(BUILD)/undef.txt; \
	nm --defined-only $(BUILD)/libnts_core.a | awk 'NF==3{print $$3}' | sort -u > $(BUILD)/def.txt; \
	comm -23 $(BUILD)/undef.txt $(BUILD)/def.txt | grep -v '^memcpy$$\|^memset$$\|^memmove$$\|^memchr$$\|^memcmp$$\|^_GLOBAL_OFFSET_TABLE_$$\|^__stack_chk_fail$$' > $(BUILD)/symbols.txt; \
	if [ -s $(BUILD)/symbols.txt ]; then cat $(BUILD)/symbols.txt; echo "ntscore: the core references the symbols above" >&2; exit 1; else echo "ntscore: memcpy, memmove, memchr, memset, memcmp only"; fi

clean:
	rm -rf $(BUILD)
