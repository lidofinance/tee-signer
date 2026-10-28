# signer-core build. Plain GNU make, no other build tool.
#
#   make                         native build: core library + test binaries
#   make ARCH=aarch64 CC=aarch64-linux-gnu-gcc LDFLAGS=-static
#                                cross build (see scripts/cross-aarch64.sh)
#   make symbols                 list undefined symbols of the core objects
#   make fuzz                    fuzz targets with ASan and UBSan (scripts/fuzz.sh runs them)
#   make clean
#
# Tests are run by scripts/test.sh, which knows where the vectors are.

ARCH ?= $(shell uname -m | sed -e 's/arm64/aarch64/' -e 's/amd64/x86_64/')
CC ?= cc
AR := $(patsubst %gcc,%ar,$(CC))
NM := $(patsubst %gcc,%nm,$(CC))
ifeq ($(AR),$(CC))
AR := ar
NM := nm
endif

BLST_SRC ?= $(abspath third_party/blst)
BUILD ?= build/$(ARCH)
BLST_LIB ?= $(BUILD)/blst/libblst.a
CORE_LIB := $(BUILD)/libsigner_core.a

# blst picks ADX instructions at build time from /proc/cpuinfo unless asked
# to detect them at run time. Run-time detection keeps x86_64 binaries
# portable between machines.
BLST_FLAGS :=
ifeq ($(ARCH),x86_64)
BLST_FLAGS += -D__BLST_PORTABLE__
endif

INCLUDES := -Iinclude -I$(BLST_SRC)/bindings
WARN := -Wall -Wextra -Werror -Wshadow -Wstrict-prototypes -Wmissing-prototypes
# The core is built freestanding: no hosted libc assumptions. It still
# calls memcpy/memset/memcmp, which every TA environment provides.
CORE_CFLAGS := -std=c11 -O2 -fPIC -ffreestanding -fno-common $(WARN) $(INCLUDES) $(CFLAGS)
TEST_CFLAGS := -std=c11 -O2 -D_DEFAULT_SOURCE -Wall -Wextra -Werror -Wno-format-truncation \
               -Isrc $(INCLUDES) $(CFLAGS)

CORE_SRCS := src/ssz.c src/bls.c src/slashing.c src/policy.c src/signer.c src/typed.c
CORE_OBJS := $(patsubst src/%.c,$(BUILD)/obj/%.o,$(CORE_SRCS))
TESTS := test_unit test_ssz_static test_bls_sign test_eip3076
TEST_BINS := $(addprefix $(BUILD)/,$(TESTS))

.PHONY: all lib tests blst symbols clean
all: lib tests
lib: $(CORE_LIB)
tests: $(TEST_BINS)
blst: $(BLST_LIB)

$(BLST_LIB):
	@test -f $(BLST_SRC)/build.sh || { echo "blst not found at $(BLST_SRC) (vendored in third_party/blst)" >&2; exit 1; }
	mkdir -p $(BUILD)/blst
	cd $(BUILD)/blst && CC=$(CC) $(BLST_SRC)/build.sh $(BLST_FLAGS) >build.log 2>&1 || { cat build.log; exit 1; }

$(BUILD)/obj/%.o: src/%.c include/signer_core.h src/sc_internal.h | $(BLST_LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CORE_CFLAGS) -c $< -o $@

$(CORE_LIB): $(CORE_OBJS)
	rm -f $@
	$(AR) rcs $@ $^

$(BUILD)/test_%: tests/test_%.c tests/testutil.h $(CORE_LIB) $(BLST_LIB)
	$(CC) $(TEST_CFLAGS) $< -o $@ $(CORE_LIB) $(BLST_LIB) $(LDFLAGS)

# ---- fuzzing (fuzz/README.md) ---------------------------------------------
# make fuzz builds one binary per decoder entry point, with ASan and UBSan,
# into $(BUILD)/fuzz/, plus the seed generator. scripts/fuzz.sh runs them.
#   FUZZ_ENGINE=libfuzzer  clang -fsanitize=fuzzer (needs clang's runtime)
#   FUZZ_ENGINE=driver     gcc with fuzz/driver.c and -fsanitize-coverage
#   FUZZ_ENGINE=auto       libfuzzer if $(FUZZ_CLANG) can link a fuzzer, else driver
FUZZ_ENGINE ?= auto
# The first clang on PATH: plain clang, else a versioned one (Ubuntu installs
# clang-18 without the plain name unless the clang package is there too).
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
FUZZ_CORE_CFLAGS := -std=c11 -ffreestanding -fno-common -Wall -Wextra $(INCLUDES) $(FUZZ_INSTR)
FUZZ_CFLAGS := -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Isrc -Ifuzz $(INCLUDES) $(FUZZ_INSTR)
# Objects per engine, so a change of engine rebuilds and relinks everything.
FUZZ_CORE_OBJS := $(patsubst src/%.c,$(FUZZ_BUILD)/obj-$(FUZZ_ENGINE)/%.o,$(CORE_SRCS))
FUZZ_SSZ := checkpoint attestation_data beacon_block_header voluntary_exit \
            validator_registration fork_data signing_data payload_attestation_data \
            proposer_preferences
# Targets built from fuzz/target_ssz.c, one per fixed-size decoder.
FUZZ_FIXED := $(addprefix ssz_,$(FUZZ_SSZ)) payload_envelope watermark repeat_roots
FUZZ_TARGETS := $(FUZZ_FIXED) builder_request_auth aggregate_and_proof \
                contribution_and_proof bls config signer
FUZZ_BINS := $(addprefix $(FUZZ_BUILD)/fuzz_,$(FUZZ_TARGETS))
FUZZ_HDRS := fuzz/fuzz.h fuzz/ref_ssz.h fuzz/base_config.h fuzz/signer_ops.h include/signer_core.h
fuzz_src = $(if $(filter $(1),$(FUZZ_FIXED)),fuzz/target_ssz.c,fuzz/target_$(1).c)
fuzz_def = $(if $(filter $(1),$(FUZZ_FIXED)),-DT_$(shell echo $(1) | sed 's/^ssz_//' | tr a-z A-Z))

.PHONY: fuzz
fuzz: $(FUZZ_BINS) $(FUZZ_BUILD)/mkseeds
	@echo $(FUZZ_ENGINE) >$(FUZZ_BUILD)/engine
	@echo "fuzz: $(words $(FUZZ_BINS)) targets in $(FUZZ_BUILD) (engine $(FUZZ_ENGINE))"

# A static pattern rule: the objects are explicit targets, not intermediate
# files, so a missing one (after a change of engine) relinks the binaries.
$(FUZZ_CORE_OBJS): $(FUZZ_BUILD)/obj-$(FUZZ_ENGINE)/%.o: src/%.c include/signer_core.h src/sc_internal.h | $(BLST_LIB)
	@mkdir -p $(dir $@)
	$(FUZZ_CC) $(FUZZ_CORE_CFLAGS) -c $< -o $@

$(FUZZ_BUILD)/obj-driver/driver.o: fuzz/driver.c
	@mkdir -p $(dir $@)
	$(FUZZ_CC) -std=c11 -Wall -Wextra $(FUZZ_SAN) -c $< -o $@

$(FUZZ_BUILD)/mkseeds: fuzz/mkseeds.c fuzz/signer_ops.h tests/testutil.h $(CORE_LIB) $(BLST_LIB)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $< -o $@ $(CORE_LIB) $(BLST_LIB) $(LDFLAGS)

.SECONDEXPANSION:
$(FUZZ_BUILD)/fuzz_%: $$(call fuzz_src,$$*) $(FUZZ_HDRS) $(FUZZ_CORE_OBJS) $(FUZZ_MAIN) $(BLST_LIB)
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(call fuzz_def,$*) $< $(FUZZ_CORE_OBJS) $(FUZZ_MAIN) $(BLST_LIB) \
	  $(FUZZ_LINK) -o $@

# Symbols the core objects reference but do not define themselves.
symbols: $(CORE_OBJS)
	@$(NM) -u $(CORE_OBJS) | awk 'NF==2 {print $$2}' | sort -u >$(BUILD)/undefined.txt
	@$(NM) --defined-only $(CORE_OBJS) | awk 'NF==3 {print $$3}' | sort -u >$(BUILD)/defined.txt
	@comm -23 $(BUILD)/undefined.txt $(BUILD)/defined.txt

clean:
	rm -rf build
