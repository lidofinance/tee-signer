/*
 * Fixed-size decoders: one target per decoder, picked at build time with
 * -DT_<NAME>. Oracles: a wrong length or NULL argument is SC_ERR_DECODE;
 * an accepted input encodes back to the same bytes and hashes without a
 * sanitizer report.
 */
#include "fuzz.h"

#if defined(T_CHECKPOINT)
#define TYPE sc_checkpoint
#define LEN SC_SSZ_CHECKPOINT_LEN
#define DEC sc_ssz_decode_checkpoint
#define ENC sc_ssz_encode_checkpoint
#define HTR sc_htr_checkpoint
#elif defined(T_ATTESTATION_DATA)
#define TYPE sc_attestation_data
#define LEN SC_SSZ_ATTESTATION_DATA_LEN
#define DEC sc_ssz_decode_attestation_data
#define ENC sc_ssz_encode_attestation_data
#define HTR sc_htr_attestation_data
#elif defined(T_BEACON_BLOCK_HEADER)
#define TYPE sc_beacon_block_header
#define LEN SC_SSZ_BEACON_BLOCK_HEADER_LEN
#define DEC sc_ssz_decode_beacon_block_header
#define ENC sc_ssz_encode_beacon_block_header
#define HTR sc_htr_beacon_block_header
#elif defined(T_VOLUNTARY_EXIT)
#define TYPE sc_voluntary_exit
#define LEN SC_SSZ_VOLUNTARY_EXIT_LEN
#define DEC sc_ssz_decode_voluntary_exit
#define ENC sc_ssz_encode_voluntary_exit
#define HTR sc_htr_voluntary_exit
#elif defined(T_VALIDATOR_REGISTRATION)
#define TYPE sc_validator_registration
#define LEN SC_SSZ_VALIDATOR_REGISTRATION_LEN
#define DEC sc_ssz_decode_validator_registration
#define ENC sc_ssz_encode_validator_registration
#define HTR sc_htr_validator_registration
#elif defined(T_FORK_DATA)
#define TYPE sc_fork_data
#define LEN SC_SSZ_FORK_DATA_LEN
#define DEC sc_ssz_decode_fork_data
#define ENC sc_ssz_encode_fork_data
#define HTR sc_htr_fork_data
#elif defined(T_SIGNING_DATA)
#define TYPE sc_signing_data
#define LEN SC_SSZ_SIGNING_DATA_LEN
#define DEC sc_ssz_decode_signing_data
#define ENC sc_ssz_encode_signing_data
#define HTR sc_htr_signing_data
#elif defined(T_PAYLOAD_ATTESTATION_DATA)
#define TYPE sc_payload_attestation_data
#define LEN SC_SSZ_PAYLOAD_ATTESTATION_DATA_LEN
#define DEC sc_ssz_decode_payload_attestation_data
#define ENC sc_ssz_encode_payload_attestation_data
#define HTR sc_htr_payload_attestation_data
#elif defined(T_PROPOSER_PREFERENCES)
#define TYPE sc_proposer_preferences
#define LEN SC_SSZ_PROPOSER_PREFERENCES_LEN
#define DEC sc_ssz_decode_proposer_preferences
#define ENC sc_ssz_encode_proposer_preferences
#define HTR sc_htr_proposer_preferences
#elif defined(T_PAYLOAD_ENVELOPE)
#define TYPE sc_payload_envelope
#define LEN SC_PAYLOAD_ENVELOPE_ENCODED_LEN
#define DEC sc_decode_payload_envelope
#define ENC sc_encode_payload_envelope
#define HTR sc_htr_payload_envelope
#else
#error "define one T_<NAME>"
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    TYPE v, w;
    uint8_t enc[LEN], again[LEN];
    int rc;

    memset(&v, 0xa5, sizeof v);
    rc = DEC(data, size, &v);
    FUZZ_CHECK(rc == SC_OK || rc == SC_ERR_DECODE);
    if (size != LEN)
        FUZZ_CHECK(rc == SC_ERR_DECODE);
    FUZZ_CHECK(DEC(NULL, size, &w) == SC_ERR_DECODE);
    FUZZ_CHECK(DEC(data, size, NULL) == SC_ERR_DECODE);
    if (rc != SC_OK)
        return 0;

    /* Round trip: decode, encode, same bytes; decode again, same encoding. */
    ENC(&v, enc);
    FUZZ_CHECK(memcmp(enc, data, LEN) == 0);
    memset(&w, 0x5a, sizeof w);
    FUZZ_CHECK(DEC(enc, LEN, &w) == SC_OK);
    ENC(&w, again);
    FUZZ_CHECK(memcmp(again, enc, LEN) == 0);
#ifdef HTR
    {
        uint8_t r1[SC_ROOT_LEN], r2[SC_ROOT_LEN];
        HTR(&v, r1);
        HTR(&w, r2);
        FUZZ_CHECK(memcmp(r1, r2, SC_ROOT_LEN) == 0);
    }
#endif
    return 0;
}
