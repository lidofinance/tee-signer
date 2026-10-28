# Simulator and fuzzer for signer-core's slashing protection (test code only;
# the core sources are compiled from ../src unchanged).
#
#   make              build/sim (fast BLS stand-in), build/sim-real (real blst),
#                     build/covfuzz (coverage-guided), build/sim-asan
#   make check        negative controls, scenarios, 200 seeded runs per profile
#   make cov          gcov line coverage of the core over the fuzz corpus
#
#   build/sim scen [name|all] [profile|all]
#   build/sim seed FIRST COUNT [profile|all] [max_slots]
#   build/sim nc                       negative controls
#   build/sim run FILE...              replay inputs; SIM_TRACE=1 logs events
#   build/covfuzz -t SECONDS -o DIR [-s SEED]
#   build/findings                     minimal repros (EXPECTED-FAIL lines)
#
# blst comes from scripts/build-core.sh (build/x86_64/lib/libblst.a at the
# repo root); set BLST_LIB for another build.

BLST_SRC ?= $(abspath ../third_party/blst)
BLST_LIB ?= $(abspath ../../build/x86_64/lib/libblst.a)
CC ?= cc
B := build
CORE_SRCS := ../src/ssz.c ../src/bls.c ../src/slashing.c ../src/policy.c ../src/signer.c ../src/typed.c
INC := -I../include -I../src -I$(BLST_SRC)/bindings
CORE_FLAGS := -std=c11 -O2 -g -fno-common $(INC)
SIM_FLAGS := -std=c11 -O2 -g -D_DEFAULT_SOURCE -Wall -Wextra -Wno-unused-function $(INC)
WRAP := -Wl,--wrap=blst_hash_to_g2,--wrap=blst_sign_pk_in_g1,--wrap=blst_p2_compress,--wrap=blst_sk_to_pk_in_g1,--wrap=blst_p1_compress
COV := -fsanitize-coverage=trace-pc

.PHONY: all check cov clean
all: $(B)/sim $(B)/sim-real $(B)/covfuzz $(B)/sim-asan $(B)/findings

$(B):
	mkdir -p $(B)

$(B)/sim: sim.c sim.h blst_fast.c $(CORE_SRCS) | $(B)
	$(CC) $(SIM_FLAGS) sim.c blst_fast.c $(CORE_SRCS) -o $@ $(WRAP) $(BLST_LIB)

$(B)/sim-real: sim.c sim.h $(CORE_SRCS) | $(B)
	$(CC) $(SIM_FLAGS) sim.c $(CORE_SRCS) -o $@ $(BLST_LIB)

$(B)/sim-asan: sim.c sim.h blst_fast.c $(CORE_SRCS) | $(B)
	$(CC) $(SIM_FLAGS) -O1 -fsanitize=address,undefined -fno-sanitize-recover=undefined \
	  sim.c blst_fast.c $(CORE_SRCS) -o $@ $(WRAP) $(BLST_LIB)

# Minimal repros of the findings (real blst).
$(B)/findings: findings.c $(CORE_SRCS) | $(B)
	$(CC) $(SIM_FLAGS) findings.c $(CORE_SRCS) -o $@ $(BLST_LIB)

# Instrumented: sim.c and the core; covfuzz.c and blst stay plain.
$(B)/covfuzz: covfuzz.c sim.c sim.h blst_fast.c $(CORE_SRCS) | $(B)
	$(CC) $(SIM_FLAGS) $(COV) -DSIM_NO_MAIN -c sim.c -o $(B)/sim-cov.o
	for f in $(CORE_SRCS); do $(CC) $(CORE_FLAGS) $(COV) -c $$f -o $(B)/cov-$$(basename $$f .c).o || exit 1; done
	$(CC) $(SIM_FLAGS) covfuzz.c blst_fast.c $(B)/sim-cov.o $(B)/cov-*.o -o $@ $(WRAP) $(BLST_LIB)

# gcov build: replays a corpus and reports line coverage of the core.
$(B)/sim-gcov: sim.c sim.h blst_fast.c $(CORE_SRCS) | $(B)
	mkdir -p $(B)/gcov
	cd $(B)/gcov && for f in $(CORE_SRCS); do $(CC) $(CORE_FLAGS) -I../../../include -I../../../src -O0 --coverage -c ../../$$f || exit 1; done
	cd $(B)/gcov && $(CC) $(SIM_FLAGS) -I../../../include -I../../../src -O0 --coverage -c ../../sim.c ../../blst_fast.c
	cd $(B)/gcov && $(CC) --coverage *.o -o ../sim-gcov $(WRAP) $(BLST_LIB)

check: $(B)/sim $(B)/findings
	$(B)/findings
	$(B)/sim nc
	$(B)/sim scen all all
	$(B)/sim seed 1 200 all 6000

CORPUS ?= $(B)/fuzz/corpus
cov: $(B)/sim-gcov
	rm -f $(B)/gcov/*.gcda
	find $(CORPUS) -type f | xargs -r $(B)/sim-gcov run >/dev/null || true
	$(B)/sim-gcov scen all all >/dev/null || true
	cd $(B)/gcov && gcov -n slashing.o signer.o policy.o | grep -A1 "File '.*src/"

clean:
	rm -rf $(B)
