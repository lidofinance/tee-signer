# markformat

The portable C implementation of the SCW1 slashing watermark storage record,
with a thin Go binding. It has no dependency on the signing core, blst, storage,
an allocator or an operating system.

A watermark holds the highest block slot, source epoch and target epoch covered
by a durable promise, plus flags saying whether the block and attestation bounds
exist. The cloud mark log (`slashing-log`) encodes and decodes it through cgo.
C hosts, including the OP-TEE trusted app, can compile `markformat.c` and include
`markformat.h` to use the same implementation. The OP-TEE integration lives in
`lidofinance/threshold-signer-poc`; that repository must adopt this module before
the audit scope is frozen.

The signing core only works with watermark values in memory and storage
callbacks. Keeping serialization here lets storage users share one codec without
linking the signer or introducing another implementation of a security relevant
format. The core's test hosts adapt their in-memory values to this module; the
core library contains no watermark encoder or decoder.

The existing storage format is unchanged:

| Bytes | Value |
| --- | --- |
| 0–3 | ASCII `SCW1` |
| 4 | Bit 0: block bound present; bit 1: attestation bounds present |
| 5–7 | Zero, reserved |
| 8–15 | Block slot, little endian uint64 |
| 16–23 | Source epoch, little endian uint64 |
| 24–31 | Target epoch, little endian uint64 |

Decode rejects unknown flags, nonzero reserved bytes, a wrong magic or length,
and null pointers. It leaves the output unchanged on failure. It preserves all
counter values, including fields whose presence flag is unset; checking signing
policy belongs to the core. Encode masks unknown flags, as the original C codec
did.

Run `make -C markformat test` for the standalone C golden and malformed-record
tests, and `(cd markformat && go test -race ./...)` for the Go binding tests.
`make -C markformat fuzz` exercises the decoder with libFuzzer (or the shared `devkit/cfuzz` driver), ASan and UBSan.
The C and Go tests pin the same original golden record; there is only one codec.
