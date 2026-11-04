# tee-signer: build and test every module. Run inside the Ubuntu workbench
# (scripts/deps.sh lists what it needs). Each target calls a script in
# scripts/ or a module's own script.

SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
ROOT := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
export PATH := /usr/local/go/bin:$(PATH)
export GOWORK := off
# Every go test runs under the race detector; make RACE= turns it off.
RACE ?= -race
export RACE
FUZZ_TIME ?= 3s
FUZZ_SECONDS ?= 3
MODEL_RUNS ?= 500
# Exits 0 when FUZZ_MODULES is unset or ALL: the C fuzz targets run (scripts/common.sh).
FUZZ_EVERYTHING := bash -c '. "$$1"; fuzz_everything' _ $(ROOT)/scripts/common.sh

.DEFAULT_GOAL := help
.PHONY: help deps check core nts build test test-modules e2e e2e-nonprod test-core test-rust fuzz fuzz-core model race release-gate loc clean

help: ## list targets
	@grep -E '^[a-z][a-z0-9-]+:.*## ' $(firstword $(MAKEFILE_LIST)) | \
		awk -F':.*## ' '{printf "  make %-14s %s\n", $$1, $$2}'

deps: ## apt packages (build tools, cross gcc, qemu-user, clang, cloc, jq)
	bash $(ROOT)/scripts/deps.sh

check: ## guards: module boundaries, secret scan, release gate, eif-check and affected.sh self-tests, gofmt
	bash $(ROOT)/scripts/check-imports.sh
	bash $(ROOT)/scripts/check-forbidden.sh
	bash $(ROOT)/scripts/fetch-nts.sh --check
	bash $(ROOT)/scripts/affected-test.sh
	bash $(ROOT)/scripts/nts-verify-crates-test.sh
	bash $(ROOT)/scripts/release-gate-test.sh
	bash $(ROOT)/scripts/eif-check-test.sh
	python3 -B $(ROOT)/scripts/bundle-licenses-test.py
	@for m in */go.mod; do d=$${m%/go.mod}; out=$$(cd $$d && gofmt -l . | grep -v '^third_party/' || true); \
		[ -z "$$out" ] || { echo "gofmt: $$d: $$out"; exit 1; }; done; echo "gofmt: clean"

core: ## the C signer core and the vendored blst, static libraries for cgo (build/<arch>/lib)
	bash $(ROOT)/scripts/build-core.sh

nts: ## the Rust NTS library (trusted-time/rust) for both arches: crates fetched once (network), then checked and built offline in its toolchain image, with its tests
	bash $(ROOT)/scripts/build-nts.sh

build: ## static runners (one per cloud), host tools; runs the release gate and the dependency check on each
	bash $(ROOT)/scripts/build-runner.sh

test-modules: core nts ## gofmt, vet and unit tests of every Go module (or those of CI_MODULES), each on its own go.mod
	bash $(ROOT)/scripts/test-modules.sh

race: test-modules ## same as test-modules (the race detector is on unless RACE=)

# The runners make build puts in build/<arch>/bin, named as scripts/test.sh
# names them (bin_env), so tests/e2e checks those and not its own builds.
E2E_BIN := $(ROOT)/build/$(shell uname -m)/bin
E2E_ENV := RUNNER_BIN=$(E2E_BIN)/runner-dev RUNNER_DEBUG_BIN=$(E2E_BIN)/runner-dev-debugimport \
  RUNNER_AWS_BIN=$(E2E_BIN)/runner-aws RUNNER_AWS_DEBUG_BIN=$(E2E_BIN)/runner-aws-debugimport \
  RUNNER_AZURE_BIN=$(E2E_BIN)/runner-azure RUNNER_AZURE_DEBUG_BIN=$(E2E_BIN)/runner-azure-debugimport \
  RUNNER_GCP_BIN=$(E2E_BIN)/runner-gcp RUNNER_GCP_DEBUG_BIN=$(E2E_BIN)/runner-gcp-debugimport

e2e: build ## tests/e2e against the built runners
	cd $(ROOT)/tests && $(E2E_ENV) go test $(RACE) -count=1 -v -timeout 40m -tags platform_aws ./e2e/

e2e-nonprod: core nts ## tests/e2e of the non-prod builds: each starts on its own chain only; a ci-test runner's 7-minute images wait
	cd $(ROOT)/tests && go test $(RACE) -count=1 -v -timeout 30m -tags platform_aws,nonprod,chain_ci_test -run 'TestE2ENonProd' ./e2e/

test: ## everything: guards, build, release gate, modules, e2e, signer-core suites, fuzz (FUZZ_TIME)
	bash $(ROOT)/scripts/test.sh

test-core: ## signer-core's own suites (VECTORS_DIR names fetched vectors when offline); its short fuzz run as for fuzz-core
	$(FUZZ_EVERYTHING) || export FUZZ=0; bash $(ROOT)/signer-core/scripts/test.sh

test-rust: ## the Rust NTS crate's tests and checks (same as nts)
	bash $(ROOT)/scripts/build-nts.sh

fuzz: core nts ## every Go fuzz target for FUZZ_TIME each; FUZZ_MODULES="a b" fuzzes only those modules
	FUZZ_TIME=$(FUZZ_TIME) bash $(ROOT)/scripts/fuzz.sh

fuzz-core: ## the C fuzz targets (ASan, UBSan): regression inputs, then FUZZ_SECONDS each; skipped when FUZZ_MODULES is set and not ALL
	if $(FUZZ_EVERYTHING); then \
		FUZZ_SECONDS=$(FUZZ_SECONDS) bash $(ROOT)/signer-core/scripts/fuzz.sh ci && \
		$(MAKE) -C $(ROOT)/markformat fuzz FUZZ_SECONDS=$(FUZZ_SECONDS); \
	else echo "fuzz-core: skipped, FUZZ_MODULES=$$FUZZ_MODULES leaves out signer-core and markformat"; fi

model: core ## the slashing model test (tee-signer/server) with MODEL_RUNS seeds
	cd $(ROOT)/tee-signer && SLASHMODEL_RUNS=$(MODEL_RUNS) go test $(RACE) -count=1 -v -timeout 60m \
		-tags "$$(bash -c '. $(ROOT)/scripts/common.sh; runner_tags runner-dev')" -run '^TestSlashingModel$$' ./server

release-gate: ## the release gate: its self-test, the tree check, and every runner build checked by build-runner.sh
	bash $(ROOT)/scripts/release-gate-test.sh
	bash $(ROOT)/scripts/release-gate.sh tree $(ROOT)
	bash $(ROOT)/scripts/build-runner.sh

loc: ## code lines per module and per runner build (cloc; not recorded in the repo)
	bash $(ROOT)/scripts/loc.sh
	bash $(ROOT)/scripts/loc.sh builds

clean: ## remove build/ and logs/ (and the Rust crate cache in build/nts/cargo-home)
	rm -rf $(ROOT)/build $(ROOT)/logs
