/*
 * BuilderRequestAuth (kind 14): sc_ssz_decode_builder_request_auth, then
 * the data root and the message root. Oracles: the decoder accepts exactly
 * the strict encoding (offset 12, 0 to 4096 data bytes), its data points
 * into the input, and both roots match the reference merkleization.
 */
#include "ref_ssz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    sc_builder_request_auth r;
    uint8_t got[32], want[32], slot[32];
    int rc, valid;

    memset(&r, 0xa5, sizeof r);
    rc = sc_ssz_decode_builder_request_auth(data, size, &r);
    valid = size >= 12 && size <= 12 + SC_BUILDER_AUTH_MAX_DATA && fz_get_u32(data) == 12;
    FUZZ_CHECK(rc == (valid ? SC_OK : SC_ERR_DECODE));
    FUZZ_CHECK(sc_ssz_decode_builder_request_auth(NULL, size, &r) == SC_ERR_DECODE);
    if (rc != SC_OK) {
        /* The data root takes any buffer up to 4096 bytes. */
        rc = sc_htr_builder_auth_data(data, size, got);
        FUZZ_CHECK(rc == (size <= SC_BUILDER_AUTH_MAX_DATA ? SC_OK : SC_ERR_ARG));
        if (rc == SC_OK) {
            ref_bytelist(data, size, SC_BUILDER_AUTH_MAX_DATA, want);
            FUZZ_CHECK(memcmp(got, want, 32) == 0);
        }
        return 0;
    }
    FUZZ_CHECK(r.data == data + 12 && r.data_len == size - 12);
    FUZZ_CHECK(r.slot == fz_get_u64(data + 4));

    FUZZ_CHECK(sc_htr_builder_request_auth(&r, got) == SC_OK);
    ref_bytelist(r.data, r.data_len, SC_BUILDER_AUTH_MAX_DATA, want);
    ref_u64_chunk(r.slot, slot);
    ref_hash(want, slot, want);
    FUZZ_CHECK(memcmp(got, want, 32) == 0);
    return 0;
}
