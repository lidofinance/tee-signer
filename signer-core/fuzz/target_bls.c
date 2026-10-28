/*
 * BLS byte inputs the runner passes over cgo: sc_bls_verify (pubkey,
 * signature and message, as for selection proofs) and sc_bls_pubkey /
 * sc_bls_sign with a secret (validator shares).
 *
 * Input: pubkey (48) | signature (96) | secret (32) | message (rest, up to
 * 256 bytes). Oracles: no sanitizer report; a secret that sc_bls_pubkey
 * accepts signs a message that then verifies, and a flipped signature byte
 * does not.
 */
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fz_in in = {data, size};
    uint8_t pk[48], sig[96], sk[32], mypk[48], mysig[96];
    const uint8_t *msg;
    size_t msg_len;
    uint8_t *m;
    int rc;

    fz_bytes(&in, pk, sizeof pk);
    fz_bytes(&in, sig, sizeof sig);
    fz_bytes(&in, sk, sizeof sk);
    msg = fz_take(&in, 256, &msg_len);
    m = fz_dup(msg, msg_len);

    (void)sc_bls_verify(pk, m, msg_len, sig); /* any status; must not crash */

    rc = sc_bls_check_secret(sk);
    FUZZ_CHECK(rc == SC_OK || rc == SC_ERR_BAD_KEY);
    FUZZ_CHECK(sc_bls_pubkey(sk, mypk) == rc);
    if (rc == SC_OK) {
        FUZZ_CHECK(sc_bls_sign(sk, m, msg_len, mysig) == SC_OK);
        FUZZ_CHECK(sc_bls_verify(mypk, m, msg_len, mysig) == SC_OK);
        mysig[size % 96] ^= (uint8_t)(1u << (size % 8));
        FUZZ_CHECK(sc_bls_verify(mypk, m, msg_len, mysig) != SC_OK);
    }
    free(m);
    return 0;
}
