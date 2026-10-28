/*
 * Runs consensus-spec-tests general/phase0/bls/sign vectors.
 * Each case is checked three ways: sc_bls_sign must produce the expected
 * signature (or fail when output is null), the signature must verify, and
 * the cached hash_to_G2 path the signer uses must give the same bytes.
 *
 * usage: test_bls_sign <path to tests/general/phase0/bls/sign>
 */
#include "testutil.h"
#include "sc_internal.h"

static int total, failed;

static void run_case(const char *path)
{
    size_t len = 0;
    char *yaml = (char *)read_file(path, &len);
    const char *pk_s, *msg_s, *out_s;
    uint8_t sk[32], msg[256], want[96], got[96], pub[48];
    long msg_len;
    int expect_null, ok = 1;

    total++;
    if (!yaml) {
        fprintf(stderr, "FAIL %s: unreadable\n", path);
        failed++;
        return;
    }
    pk_s = yaml_value(yaml, "privkey");
    msg_s = yaml_value(yaml, "message");
    out_s = yaml_value(yaml, "output");
    if (!pk_s || !msg_s || !out_s || parse_hex(pk_s, sk, 32) != 0 ||
        (msg_len = parse_hex_any(msg_s, msg, sizeof msg)) < 0) {
        fprintf(stderr, "FAIL %s: cannot parse\n", path);
        failed++;
        free(yaml);
        return;
    }
    expect_null = strncmp(out_s, "null", 4) == 0;
    if (!expect_null && parse_hex(out_s, want, 96) != 0) {
        fprintf(stderr, "FAIL %s: cannot parse output\n", path);
        failed++;
        free(yaml);
        return;
    }

    int rc = sc_bls_sign(sk, msg, (size_t)msg_len, got);
    if (expect_null) {
        ok = rc != SC_OK;
    } else {
        ok = rc == SC_OK && memcmp(got, want, 96) == 0;
        ok = ok && sc_bls_pubkey(sk, pub) == SC_OK &&
             sc_bls_verify(pub, msg, (size_t)msg_len, got) == SC_OK;
        if (ok && msg_len == 32) {
            /* Signer path: two lookups through a 2-entry cache. */
            sc_h2g2_entry entries[2];
            sc_h2g2_cache cache;
            blst_scalar s;
            blst_p2 scratch;
            uint8_t sig2[96];
            sc_h2g2_cache_init(&cache, entries, 2);
            ok = sc_bls_load_secret(&s, sk) == SC_OK;
            for (int i = 0; ok && i < 2; i++) {
                const blst_p2 *h = sc_h2g2_cache_get(&cache, msg, &scratch);
                sc_bls_sign_hashed(&s, h, sig2);
                ok = memcmp(sig2, want, 96) == 0;
            }
            ok = ok && cache.hits == 1 && cache.misses == 1;
        }
    }
    printf("bls_sign %s %s\n", ok ? "PASS" : "FAIL", path);
    if (!ok)
        failed++;
    free(yaml);
}

static void walk(const char *dir)
{
    struct dirent **ents;
    int n = list_dir(dir, &ents);
    if (n < 0)
        return;
    for (int i = 0; i < n; i++) {
        char p[4096];
        if (!is_dot(ents[i]->d_name)) {
            snprintf(p, sizeof p, "%s/%s", dir, ents[i]->d_name);
            if (strcmp(ents[i]->d_name, "data.yaml") == 0)
                run_case(p);
            else
                walk(p);
        }
        free(ents[i]);
    }
    free(ents);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <bls/sign dir>\n", argv[0]);
        return 2;
    }
    walk(argv[1]);
    printf("BLS_SIGN total=%d pass=%d fail=%d\n", total, total - failed, failed);
    return (failed || total == 0) ? 1 : 0;
}
