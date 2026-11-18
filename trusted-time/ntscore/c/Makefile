# The NTS core on its own, as a trusted application would build it: C11,
# freestanding, every warning an error, with the stack protector, and no
# outside symbol but memcpy, memmove, memchr, memset and memcmp and the
# stack protector's __stack_chk_fail and __stack_chk_guard. The archive built here is the one
# the Go binding (../go) links, so the core in a runner is the core this
# file checks; the Go tests are the core's test suite.
#
#   make            the library for this machine: build/<arch>/libnts_core.a
#   make check      the library, then the symbol check (and that the stack
#                   protector reached the objects)
#   make noplain    the library with NTS_NO_PLAIN_NTP (a build that refuses
#                   plain NTP), build/<arch>/noplain/; go test -tags
#                   nts,ntsnoplain links it (../go/link_noplain.go)
#   make asan       the library with ASan and UBSan, build/<arch>/asan/;
#                   go test -asan links it (../go/link_asan.go)
#   make cov        the library instrumented for gcov, build/<arch>/cov/;
#                   go test -tags nts,ntscov links it (../go/link_cov.go)
#   make cov-report line coverage of the C by the tests run since make cov
#   make fuzz       the fuzz targets of fuzz/ with ASan, UBSan and coverage,
#                   build/<arch>/fuzz/ (fuzz/fuzz.sh builds and runs them)
#   make ARCH=aarch64 CC=aarch64-linux-gnu-gcc   a cross build (scripts/build-core.sh)
#   make clean
ARCH ?= $(shell uname -m | sed -e 's/arm64/aarch64/' -e 's/amd64/x86_64/')
CC ?= cc
AR := $(patsubst %gcc,%ar,$(CC))
NM := $(patsubst %gcc,%nm,$(CC))
ifeq ($(AR),$(CC))
AR := ar
NM := nm
endif
BUILD ?= build/$(ARCH)
OBJ := $(BUILD)/obj
LIB := $(BUILD)/libnts_core.a

WARN := -Wall -Wextra -Werror -Wshadow -Wvla -Wstrict-prototypes -Wmissing-prototypes
# -D_FORTIFY_SOURCE=0: Darwin's headers turn fortification on unless it is
# defined, and -U alone leaves them to it (then memcpy becomes
# __memcpy_chk). -fPIC as signer-core: the archive links into any
# build mode.
# -mno-outline-atomics: gcc on aarch64 otherwise calls its runtime for the
# poll counter's atomics (__aarch64_ldadd4_acq_rel); inline, they are
# instructions. A trusted application's build needs the same.
# -fstack-protector-strong: -ffreestanding drops the distro's default stack
# protector, so it is turned on here, as for signer-core. The objects then
# need __stack_chk_fail (and __stack_chk_guard where the canary is a
# global: aarch64), which libc supplies on the runners and a trusted
# application must supply itself. Every variant has it: the sanitizer,
# coverage, noplain and fuzz builds too.
STACK_PROTECTOR ?= -fstack-protector-strong
ARCH_CFLAGS := $(if $(filter aarch64,$(ARCH)),-mno-outline-atomics,)
CORE_CFLAGS := -std=c11 -O2 -fPIC -ffreestanding -fno-builtin -fno-common $(STACK_PROTECTOR) -D_FORTIFY_SOURCE=0 $(ARCH_CFLAGS) $(WARN) -I. $(CFLAGS)
SAN_CFLAGS := -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g -O1
COV_CFLAGS := --coverage -g -O0
SRCS := siv.c ntp.c sample.c quorum.c ke.c client.c
OBJS := $(SRCS:%.c=$(OBJ)/%.o)

.PHONY: lib check asan cov cov-report noplain symbols clean

lib: $(LIB)

check: symbols

asan:
	$(MAKE) BUILD=$(BUILD)/asan CFLAGS="$(SAN_CFLAGS)" lib

noplain:
	$(MAKE) BUILD=$(BUILD)/noplain CFLAGS="-DNTS_NO_PLAIN_NTP" check

cov:
	rm -rf $(BUILD)/cov
	$(MAKE) BUILD=$(BUILD)/cov CFLAGS="$(COV_CFLAGS)" lib

# gcov reads the counts the test binaries wrote next to the objects.
cov-report:
	@cd $(BUILD)/cov/obj && gcov -n $(SRCS:%.c=%.gcno) 2>/dev/null | awk '/^File/ { f = $$2; next } /^Lines executed/ { if (f == "") f = "total"; printf "  %-12s %s\n", f, $$0; f = "" }'

$(OBJ)/%.o: %.c nts_core.h Makefile
	@mkdir -p $(OBJ)
	$(CC) $(CORE_CFLAGS) -c -o $@ $<

$(LIB): $(OBJS)
	rm -f $@
	$(AR) rcs $@ $^

# The undefined symbols of the archive, minus the ones it defines itself,
# minus the five allowed, the stack protector's two and
# _GLOBAL_OFFSET_TABLE_ (the linker's own, from -fPIC on x86_64). The
# archive must reference __stack_chk_fail: if it does not, the stack
# protector flag did not reach the objects (scripts/build-core.sh checks
# the same). nm prints the symbol last on GNU and on Darwin, where
# C symbols also carry a leading underscore; lines naming an object end
# with a colon.
NM_SYMBOLS = $(NM) $(1) $(LIB) | awk '/:$$/ || NF == 0 { next } { print $$NF }' | $(if $(filter Darwin,$(shell uname -s)),sed 's/^_//',cat) | sort -u
symbols: $(LIB)
	@$(call NM_SYMBOLS,-u) > $(OBJ)/undef.txt; \
	$(call NM_SYMBOLS,--defined-only) > $(OBJ)/def.txt; \
	comm -23 $(OBJ)/undef.txt $(OBJ)/def.txt | grep -vx -e memcpy -e memmove -e memchr -e memset -e memcmp -e __stack_chk_fail -e __stack_chk_guard -e _GLOBAL_OFFSET_TABLE_ > $(OBJ)/symbols.txt; \
	if [ -s $(OBJ)/symbols.txt ]; then cat $(OBJ)/symbols.txt; echo "ntscore: the core references the symbols above" >&2; exit 1; fi; \
	if ! grep -qx __stack_chk_fail $(OBJ)/undef.txt; then echo "ntscore: the archive has no stack protector (__stack_chk_fail)" >&2; exit 1; fi; \
	echo "ntscore: memcpy, memmove, memchr, memset, memcmp, __stack_chk_fail, __stack_chk_guard only; stack protector on"

clean:
	rm -rf build

# ---- fuzzing (fuzz/fuzz.h) -----------------------------------------------
# One binary per target, with ASan and UBSan, as signer-core builds its own:
#   FUZZ_ENGINE=libfuzzer  clang -fsanitize=fuzzer
#   FUZZ_ENGINE=driver     gcc with devkit/cfuzz/driver.c and -fsanitize-coverage
#   FUZZ_ENGINE=auto       libfuzzer if $(FUZZ_CLANG) can link a fuzzer, else driver
FUZZ_ENGINE ?= auto
FUZZ_CLANG ?= $(firstword $(foreach c,clang clang-21 clang-20 clang-19 clang-18 clang-17 clang-16 clang-15 clang-14,$(shell command -v $(c) 2>/dev/null)) clang)
FUZZ_BUILD := $(BUILD)/fuzz
ifeq ($(FUZZ_ENGINE),auto)
override FUZZ_ENGINE := $(shell printf 'int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { (void)d; (void)n; return 0; }\n' | $(FUZZ_CLANG) -x c -fsanitize=fuzzer - -o /dev/null >/dev/null 2>&1 && echo libfuzzer || echo driver)
endif
FUZZ_SAN := -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g -O1
ifeq ($(FUZZ_ENGINE),libfuzzer)
FUZZ_CC := $(FUZZ_CLANG)
FUZZ_INSTR := $(FUZZ_SAN) -fsanitize=fuzzer-no-link
FUZZ_LINK := $(FUZZ_SAN) -fsanitize=fuzzer
FUZZ_MAIN :=
else
FUZZ_CC := $(CC)
FUZZ_INSTR := $(FUZZ_SAN) -fsanitize-coverage=trace-pc,trace-cmp
FUZZ_LINK := $(FUZZ_SAN)
FUZZ_MAIN := $(FUZZ_BUILD)/obj-driver/driver.o
endif
FUZZ_DRIVER ?= $(abspath ../../../devkit/cfuzz/driver.c)
FUZZ_CORE_CFLAGS := -std=c11 -ffreestanding -fno-builtin -fno-common $(STACK_PROTECTOR) -D_FORTIFY_SOURCE=0 $(ARCH_CFLAGS) -Wall -Wextra -I. $(FUZZ_INSTR)
FUZZ_CFLAGS := -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -I. -Ifuzz $(FUZZ_INSTR)
FUZZ_CORE_OBJS := $(SRCS:%.c=$(FUZZ_BUILD)/obj-$(FUZZ_ENGINE)/%.o)
FUZZ_TARGETS := ke verify siv measure plain client
FUZZ_BINS := $(addprefix $(FUZZ_BUILD)/fuzz_,$(FUZZ_TARGETS))

.PHONY: fuzz fuzz-targets
fuzz-targets:
	@printf '%s\n' $(FUZZ_TARGETS)

fuzz: $(FUZZ_BINS) $(FUZZ_BUILD)/mkseeds
	@echo $(FUZZ_ENGINE) >$(FUZZ_BUILD)/engine
	@echo "fuzz: $(words $(FUZZ_BINS)) targets in $(FUZZ_BUILD) (engine $(FUZZ_ENGINE))"

$(FUZZ_CORE_OBJS): $(FUZZ_BUILD)/obj-$(FUZZ_ENGINE)/%.o: %.c nts_core.h Makefile
	@mkdir -p $(dir $@)
	$(FUZZ_CC) $(FUZZ_CORE_CFLAGS) -c $< -o $@

$(FUZZ_BUILD)/obj-driver/driver.o: $(FUZZ_DRIVER)
	@mkdir -p $(dir $@)
	$(FUZZ_CC) -std=c11 -Wall -Wextra $(FUZZ_SAN) -c $< -o $@

# The seed writer, against the plain core, without sanitizers.
$(FUZZ_BUILD)/mkseeds: fuzz/mkseeds.c fuzz/fuzz.h nts_core.h $(LIB)
	@mkdir -p $(dir $@)
	$(CC) -std=c11 -O2 -D_DEFAULT_SOURCE -Wall -Wextra -I. -Ifuzz $< -o $@ $(LIB)

$(FUZZ_BUILD)/fuzz_%: fuzz/target_%.c fuzz/fuzz.h nts_core.h $(FUZZ_CORE_OBJS) $(FUZZ_MAIN)
	$(FUZZ_CC) $(FUZZ_CFLAGS) $< $(FUZZ_CORE_OBJS) $(FUZZ_MAIN) -o $@ $(FUZZ_LINK)
