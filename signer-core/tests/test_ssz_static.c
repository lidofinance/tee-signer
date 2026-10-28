/*
 * Runs consensus-spec-tests ssz_static vectors for the containers the core
 * implements. For each case: snappy-decode serialized.ssz_snappy, SSZ-decode,
 * re-encode (must match byte for byte), hash_tree_root (must match roots.yaml).
 *
 * usage: test_ssz_static <path to tests/minimal or tests/mainnet>
 */
#include "testutil.h"

typedef int (*run_fn)(const uint8_t *ssz, size_t len, uint8_t root[32]);

#define DEFINE_RUN(NAME, TYPE, LEN)                                                \
    static int run_##NAME(const uint8_t *ssz, size_t len, uint8_t root[32])        \
    {                                                                              \
        TYPE v;                                                                    \
        uint8_t enc[LEN];                                                          \
        if (sc_ssz_decode_##NAME(ssz, len, &v) != SC_OK)                           \
            return -1;                                                             \
        sc_ssz_encode_##NAME(&v, enc);                                             \
        if (memcmp(enc, ssz, LEN) != 0)                                            \
            return -2;                                                             \
        sc_htr_##NAME(&v, root);                                                   \
        return 0;                                                                  \
    }

DEFINE_RUN(checkpoint, sc_checkpoint, SC_SSZ_CHECKPOINT_LEN)
DEFINE_RUN(attestation_data, sc_attestation_data, SC_SSZ_ATTESTATION_DATA_LEN)
DEFINE_RUN(beacon_block_header, sc_beacon_block_header, SC_SSZ_BEACON_BLOCK_HEADER_LEN)
DEFINE_RUN(voluntary_exit, sc_voluntary_exit, SC_SSZ_VOLUNTARY_EXIT_LEN)
DEFINE_RUN(fork_data, sc_fork_data, SC_SSZ_FORK_DATA_LEN)
DEFINE_RUN(signing_data, sc_signing_data, SC_SSZ_SIGNING_DATA_LEN)
DEFINE_RUN(payload_attestation_data, sc_payload_attestation_data, SC_SSZ_PAYLOAD_ATTESTATION_DATA_LEN)

static const struct {
    const char *name;
    run_fn run;
} CONTAINERS[] = {
    {"Checkpoint", run_checkpoint},
    {"AttestationData", run_attestation_data},
    {"BeaconBlockHeader", run_beacon_block_header},
    {"VoluntaryExit", run_voluntary_exit},
    {"ForkData", run_fork_data},
    {"SigningData", run_signing_data},
    {"PayloadAttestationData", run_payload_attestation_data}, /* gloas only */
};
#define N_CONTAINERS (sizeof CONTAINERS / sizeof CONTAINERS[0])

static int run_case(const char *dir, run_fn run, char *why, size_t why_len)
{
    char path[4096];
    size_t clen = 0, slen = 0, ylen = 0;
    uint8_t *comp, *ssz = NULL, want[32], got[32];
    char *yaml;
    const char *v;
    int rc = -1;

    snprintf(path, sizeof path, "%s/serialized.ssz_snappy", dir);
    comp = read_file(path, &clen);
    snprintf(path, sizeof path, "%s/roots.yaml", dir);
    yaml = (char *)read_file(path, &ylen);
    if (!comp || !yaml) {
        snprintf(why, why_len, "missing files");
        goto out;
    }
    ssz = snappy_decompress(comp, clen, &slen);
    if (!ssz) {
        snprintf(why, why_len, "snappy decode failed");
        goto out;
    }
    v = yaml_value(yaml, "root");
    if (!v || parse_hex(v, want, 32) != 0) {
        snprintf(why, why_len, "bad roots.yaml");
        goto out;
    }
    int r = run(ssz, slen, got);
    if (r == -1) {
        snprintf(why, why_len, "decode failed (len %zu)", slen);
    } else if (r == -2) {
        snprintf(why, why_len, "re-encode mismatch");
    } else if (memcmp(got, want, 32) != 0) {
        char h[65];
        to_hex(got, 32, h);
        snprintf(why, why_len, "root mismatch, got %s", h);
    } else {
        rc = 0;
    }
out:
    free(comp);
    free(ssz);
    free(yaml);
    return rc;
}

int main(int argc, char **argv)
{
    struct dirent **forks;
    int nforks, total = 0, failed = 0;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <tests/minimal dir>\n", argv[0]);
        return 2;
    }
    nforks = list_dir(argv[1], &forks);
    if (nforks < 0) {
        perror(argv[1]);
        return 2;
    }
    for (int f = 0; f < nforks; f++) {
        const char *fork = forks[f]->d_name;
        if (is_dot(fork))
            continue;
        for (size_t c = 0; c < N_CONTAINERS; c++) {
            char cdir[4096];
            struct dirent **suites;
            int nsuites, cpass = 0, cfail = 0;
            snprintf(cdir, sizeof cdir, "%s/%s/ssz_static/%s", argv[1], fork,
                     CONTAINERS[c].name);
            nsuites = list_dir(cdir, &suites);
            if (nsuites < 0)
                continue;
            for (int s = 0; s < nsuites; s++) {
                char sdir[4096];
                struct dirent **cases;
                int ncases;
                if (is_dot(suites[s]->d_name)) {
                    free(suites[s]);
                    continue;
                }
                snprintf(sdir, sizeof sdir, "%s/%s", cdir, suites[s]->d_name);
                ncases = list_dir(sdir, &cases);
                for (int k = 0; k < ncases; k++) {
                    char kdir[4096], why[256];
                    if (!is_dot(cases[k]->d_name)) {
                        snprintf(kdir, sizeof kdir, "%s/%s", sdir, cases[k]->d_name);
                        if (run_case(kdir, CONTAINERS[c].run, why, sizeof why) == 0) {
                            cpass++;
                        } else {
                            cfail++;
                            fprintf(stderr, "FAIL %s: %s\n", kdir, why);
                        }
                    }
                    free(cases[k]);
                }
                if (ncases >= 0)
                    free(cases);
                free(suites[s]);
            }
            free(suites);
            printf("ssz_static %-10s %-18s pass=%d fail=%d\n", fork, CONTAINERS[c].name,
                   cpass, cfail);
            total += cpass + cfail;
            failed += cfail;
        }
        free(forks[f]);
    }
    free(forks);
    printf("SSZ_STATIC total=%d pass=%d fail=%d\n", total, total - failed, failed);
    return (failed || total == 0) ? 1 : 0;
}
