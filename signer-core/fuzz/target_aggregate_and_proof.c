/*
 * AggregateAndProof (kind 9): the wire payload is form:u8 | SSZ, as the Go
 * runner sends it to sc_decode_aggregate_and_proof. One more leading byte
 * picks the preset (bit 0: minimal), which the runner takes from its config.
 *
 * Oracles: a form above 2 is SC_ERR_ARG; the decoder accepts exactly the
 * inputs the reference checks accept; the fields come from the right
 * offsets; the root matches the reference merkleization (binary for phase0
 * and Electra, progressive for Gloas); Electra and Gloas accept the same
 * bytes.
 */
#include "ref_ssz.h"

static uint8_t g_scratch[SC_TYPED_SCRATCH_LEN];

/* Reference decode and root. Returns SC_OK or SC_ERR_DECODE. */
static int ref_aggregate(const uint8_t *s, size_t len, int form, const sc_preset *p,
                         uint8_t root[32])
{
    const int electra = form != SC_AGGREGATE_PHASE0, gloas = form == SC_AGGREGATE_GLOAS;
    const size_t cb_len = electra ? (size_t)((p->max_committees_per_slot + 7) / 8) : 0;
    const size_t att_fixed = 4 + 128 + 96 + cb_len;
    const uint64_t limit = p->max_validators_per_committee * (electra ? p->max_committees_per_slot : 1);
    const uint8_t *att;
    uint8_t af[4][32], f[3][32], data_root[32];
    sc_attestation_data d;

    if (len < 108 + att_fixed || fz_get_u32(s + 8) != 108)
        return SC_ERR_DECODE;
    att = s + 108;
    if (fz_get_u32(att) != att_fixed)
        return SC_ERR_DECODE;
    if (!ref_bitlist(att + att_fixed, len - 108 - att_fixed, limit, gloas, af[0]))
        return SC_ERR_DECODE;
    if (electra && !ref_bitvector(att + 4 + 128 + 96, cb_len, p->max_committees_per_slot, af[3]))
        return SC_ERR_DECODE;
    FUZZ_CHECK(sc_ssz_decode_attestation_data(att + 4, 128, &d) == SC_OK);
    sc_htr_attestation_data(&d, data_root);
    memcpy(af[1], data_root, 32);
    ref_bytes96(att + 4 + 128, af[2]);
    ref_u64_chunk(fz_get_u64(s), f[0]);
    if (gloas) {
        uint8_t pr[32], active[32] = {0x0f};
        ref_progressive(&af[0][0], 4, 0, pr);
        ref_hash(pr, active, f[1]);
    } else {
        ref_merkle(&af[0][0], electra ? 4 : 3, 2, f[1]);
    }
    ref_bytes96(s + 12, f[2]);
    ref_merkle(&f[0][0], 3, 2, root);
    return SC_OK;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const sc_preset *p;
    sc_aggregate_info a, b;
    uint8_t want[32], *ssz;
    size_t len;
    int form, rc;

    if (size < 2)
        return 0;
    p = data[0] & 1 ? &SC_PRESET_MINIMAL : &SC_PRESET_MAINNET;
    form = data[1]; /* the runner passes C.int(m.Form), Form a uint8 */
    len = size - 2;
    ssz = fz_dup(data + 2, len);

    memset(&a, 0xa5, sizeof a);
    rc = sc_decode_aggregate_and_proof(ssz, len, form, p, g_scratch, &a);
    if (form > SC_AGGREGATE_GLOAS) {
        FUZZ_CHECK(rc == SC_ERR_ARG);
        /* Look at the bytes as every valid form anyway. */
        form = form % 3;
        rc = sc_decode_aggregate_and_proof(ssz, len, form, p, g_scratch, &a);
    }
    FUZZ_CHECK(rc == ref_aggregate(ssz, len, form, p, want));
    if (rc == SC_OK) {
        sc_attestation_data d;
        FUZZ_CHECK(memcmp(a.object_root, want, 32) == 0);
        FUZZ_CHECK(a.aggregator_index == fz_get_u64(ssz));
        FUZZ_CHECK(memcmp(a.selection_proof, ssz + 12, 96) == 0);
        FUZZ_CHECK(sc_ssz_decode_attestation_data(ssz + 112, 128, &d) == SC_OK);
        FUZZ_CHECK(memcmp(&d, &a.data, sizeof d) == 0);
    }
    if (form != SC_AGGREGATE_PHASE0) {
        int other = form == SC_AGGREGATE_GLOAS ? SC_AGGREGATE_ELECTRA : SC_AGGREGATE_GLOAS;
        int rc2 = sc_decode_aggregate_and_proof(ssz, len, other, p, g_scratch, &b);
        FUZZ_CHECK(rc2 == rc);
        if (rc == SC_OK) {
            FUZZ_CHECK(b.aggregator_index == a.aggregator_index);
            FUZZ_CHECK(memcmp(&b.data, &a.data, sizeof a.data) == 0);
        }
    }
    FUZZ_CHECK(sc_decode_aggregate_and_proof(NULL, len, 0, p, g_scratch, &b) == SC_ERR_ARG);
    FUZZ_CHECK(sc_decode_aggregate_and_proof(ssz, len, -1, p, g_scratch, &b) == SC_ERR_ARG);
    free(ssz);
    return 0;
}
