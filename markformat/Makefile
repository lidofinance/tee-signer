CC ?= cc
CLANG ?= $(firstword $(foreach c,clang clang-21 clang-20 clang-19 clang-18 clang-17 clang-16 clang-15 clang-14,$(shell command -v $(c) 2>/dev/null)) clang)
FUZZ_DRIVER ?= ../devkit/cfuzz/driver.c
FUZZ_ENGINE ?= $(shell printf "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return 0; }" | $(CLANG) -x c -fsanitize=fuzzer - -o /dev/null >/dev/null 2>&1 && echo libfuzzer || echo driver)
BUILD ?= ../build/markformat
FUZZ_SECONDS ?= 5
CFLAGS := -std=c11 -O2 -Wall -Wextra -Werror -Wshadow -Wstrict-prototypes -Wmissing-prototypes $(CFLAGS)

.PHONY: test fuzz

test: $(BUILD)/test_markformat
	$(BUILD)/test_markformat

$(BUILD)/test_markformat: tests/test_markformat.c markformat.c markformat.h
	mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -I. tests/test_markformat.c markformat.c -o $@

FUZZ_BUILD := $(BUILD)/$(FUZZ_ENGINE)
SAN := -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g -O1
ifeq ($(FUZZ_ENGINE),libfuzzer)
$(FUZZ_BUILD)/fuzz_markformat: fuzz/fuzz_markformat.c markformat.c markformat.h
	mkdir -p $(FUZZ_BUILD)
	$(CLANG) -std=c11 -I. $(SAN) -fsanitize=fuzzer fuzz/fuzz_markformat.c markformat.c -o $@
else
$(FUZZ_BUILD)/driver.o: $(FUZZ_DRIVER)
	mkdir -p $(FUZZ_BUILD)
	$(CC) -std=c11 $(SAN) -c $< -o $@

$(FUZZ_BUILD)/fuzz_markformat: fuzz/fuzz_markformat.c markformat.c markformat.h $(FUZZ_BUILD)/driver.o
	$(CC) -std=c11 -I. $(SAN) -fsanitize-coverage=trace-pc,trace-cmp -c markformat.c -o $(FUZZ_BUILD)/markformat-fuzz.o
	$(CC) -std=c11 -I. $(SAN) -fsanitize-coverage=trace-pc,trace-cmp -c fuzz/fuzz_markformat.c -o $(FUZZ_BUILD)/target.o
	$(CC) $(SAN) $(FUZZ_BUILD)/markformat-fuzz.o $(FUZZ_BUILD)/target.o $(FUZZ_BUILD)/driver.o -o $@
endif

fuzz: $(FUZZ_BUILD)/fuzz_markformat
	mkdir -p $(BUILD)/corpus
	cp fuzz/corpus/* $(BUILD)/corpus/
	$(FUZZ_BUILD)/fuzz_markformat -max_total_time=$(FUZZ_SECONDS) -max_len=64 $(BUILD)/corpus
