/*
 * ContributionAndProof (kind 10): SSZ of the preset size, as the Go runner
 * passes it to sc_decode_contribution_and_proof. The first byte picks the
 * preset (bit 0: minimal).
 *
 * Oracles: only the preset size decodes; the aggregation bits past the
 * subcommittee size must be zero; the fields come from the right offsets;
 * the root matches the reference merkleization.
 */
#include "ref_ssz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const sc_preset *p;
    sc_contribution_info c;
    uint8_t *ssz, want[32], cf[5][32], f[3][32];
    size_t len, need, bits_len;
    uint64_t nbits;
    int rc, valid;

    if (size < 1)
        return 0;
    p = data[0] & 1 ? &SC_PRESET_MINIMAL : &SC_PRESET_MAINNET;
    len = size - 1;
    ssz = fz_dup(data + 1, len);
    nbits = p->sync_committee_size / p->sync_committee_subnet_count;
    bits_len = (size_t)((nbits + 7) / 8);
    need = 8 + 8 + 32 + 8 + bits_len + 96 + 96;
    FUZZ_CHECK(sc_contribution_and_proof_len(p) == need);

    memset(&c, 0xa5, sizeof c);
    rc = sc_decode_contribution_and_proof(ssz, len, p, &c);
    valid = len == need && ref_bitvector(ssz + 56, bits_len, nbits, cf[3]);
    FUZZ_CHECK(rc == (valid ? SC_OK : SC_ERR_DECODE));
    if (rc == SC_OK) {
        FUZZ_CHECK(c.aggregator_index == fz_get_u64(ssz));
        FUZZ_CHECK(c.slot == fz_get_u64(ssz + 8));
        FUZZ_CHECK(memcmp(c.beacon_block_root, ssz + 16, 32) == 0);
        FUZZ_CHECK(c.subcommittee_index == fz_get_u64(ssz + 48));
        FUZZ_CHECK(memcmp(c.selection_proof, ssz + 56 + bits_len + 96, 96) == 0);
        ref_u64_chunk(c.slot, cf[0]);
        memcpy(cf[1], ssz + 16, 32);
        ref_u64_chunk(c.subcommittee_index, cf[2]);
        ref_bytes96(ssz + 56 + bits_len, cf[4]);
        ref_u64_chunk(c.aggregator_index, f[0]);
        ref_merkle(&cf[0][0], 5, 3, f[1]);
        ref_bytes96(c.selection_proof, f[2]);
        ref_merkle(&f[0][0], 3, 2, want);
        FUZZ_CHECK(memcmp(c.object_root, want, 32) == 0);
    }
    FUZZ_CHECK(sc_decode_contribution_and_proof(NULL, len, p, &c) == SC_ERR_ARG);
    free(ssz);
    return 0;
}
