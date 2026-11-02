/*
 * Writes the seed corpora of the fuzz targets from the test vectors:
 * consensus-spec-tests ssz_static and bls/sign, tests/data (go-eth2-client
 * and go-builder-client vectors), and inputs built the way
 * tests/test_unit.c builds them.
 *
 *   mkseeds OUT_DIR TESTS_DATA_DIR SSZ_STATIC_MINIMAL_DIR BLS_SIGN_DIR
 *
 * Writes OUT_DIR/<target>/<name>. Built like the tests, without sanitizers.
 */
#include <errno.h>
#include <sys/stat.h>

#include "../tests/testutil.h"
#include "signer_ops.h"

static const char *g_out;
static int g_written;

static void put(const char *target, const char *name, const uint8_t *d, size_t n)
{
    char path[4096];
    FILE *f;
    snprintf(path, sizeof path, "%s/%s", g_out, target);
    mkdir(path, 0755);
    snprintf(path, sizeof path, "%s/%s/%s", g_out, target, name);
    f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "mkseeds: %s: %s\n", path, strerror(errno));
        exit(1);
    }
    if (n)
        fwrite(d, 1, n, f);
    fclose(f);
    g_written++;
}

static void put64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

/* ---- consensus-spec-tests ssz_static ------------------------------------- */

static const struct {
    const char *container, *target;
} SSZ_TARGETS[] = {
    {"Checkpoint", "ssz_checkpoint"},
    {"AttestationData", "ssz_attestation_data"},
    {"BeaconBlockHeader", "ssz_beacon_block_header"},
    {"VoluntaryExit", "ssz_voluntary_exit"},
    {"ForkData", "ssz_fork_data"},
    {"SigningData", "ssz_signing_data"},
    {"PayloadAttestationData", "ssz_payload_attestation_data"},
};

static void ssz_static(const char *root)
{
    struct dirent **forks;
    int nf = list_dir(root, &forks);
    if (nf < 0) {
        fprintf(stderr, "mkseeds: no ssz_static vectors at %s\n", root);
        exit(1);
    }
    for (int f = 0; f < nf; f++) {
        if (is_dot(forks[f]->d_name))
            continue;
        for (size_t c = 0; c < sizeof SSZ_TARGETS / sizeof SSZ_TARGETS[0]; c++) {
            char cdir[4096];
            struct dirent **suites;
            int ns;
            snprintf(cdir, sizeof cdir, "%s/%s/ssz_static/%s", root, forks[f]->d_name,
                     SSZ_TARGETS[c].container);
            if ((ns = list_dir(cdir, &suites)) < 0)
                continue;
            for (int s = 0; s < ns; s++) {
                char sdir[4096];
                struct dirent **cases;
                int nc;
                if (is_dot(suites[s]->d_name))
                    continue;
                snprintf(sdir, sizeof sdir, "%s/%s", cdir, suites[s]->d_name);
                if ((nc = list_dir(sdir, &cases)) < 0)
                    continue;
                /* A few cases per suite and fork are plenty for a fixed size. */
                for (int k = 0, taken = 0; k < nc && taken < 3; k++) {
                    char path[4096], name[512];
                    size_t clen, slen;
                    uint8_t *comp, *ssz;
                    if (is_dot(cases[k]->d_name))
                        continue;
                    snprintf(path, sizeof path, "%s/%s/serialized.ssz_snappy", sdir,
                             cases[k]->d_name);
                    if (!(comp = read_file(path, &clen)))
                        continue;
                    if ((ssz = snappy_decompress(comp, clen, &slen))) {
                        snprintf(name, sizeof name, "cst-%s-%s-%s", forks[f]->d_name,
                                 suites[s]->d_name, cases[k]->d_name);
                        put(SSZ_TARGETS[c].target, name, ssz, slen);
                        taken++;
                    }
                    free(comp);
                    free(ssz);
                }
                for (int k = 0; k < nc; k++)
                    free(cases[k]);
                free(cases);
            }
            for (int s = 0; s < ns; s++)
                free(suites[s]);
            free(suites);
        }
    }
    for (int f = 0; f < nf; f++)
        free(forks[f]);
    free(forks);
}

/* ---- tests/data ------------------------------------------------------------ */

static void gloas_go(const char *dir)
{
    char path[4096], line[16384], kind[8], a[8192], name[64];
    uint8_t in[4096];
    int n = 0;
    FILE *f;
    snprintf(path, sizeof path, "%s/gloas_go.txt", dir);
    if (!(f = fopen(path, "r"))) {
        perror(path);
        exit(1);
    }
    while (fgets(line, sizeof line, f)) {
        long len;
        if (line[0] == '#' || sscanf(line, "%7s %8191s", kind, a) != 2)
            continue;
        if ((len = parse_hex_any(a, in + 2, sizeof in - 2)) < 0)
            continue;
        snprintf(name, sizeof name, "go-%s-%d", kind, n++);
        if (!strcmp(kind, "ptc"))
            put("ssz_payload_attestation_data", name, in + 2, (size_t)len);
        else if (!strcmp(kind, "pref"))
            put("ssz_proposer_preferences", name, in + 2, (size_t)len);
        else if (!strcmp(kind, "env"))
            put("payload_envelope", name, in + 2, (size_t)len);
        else if (!strcmp(kind, "agg")) {
            /* preset byte, form byte, SSZ: as Electra and as Gloas */
            in[0] = 0;
            in[1] = SC_AGGREGATE_GLOAS;
            put("aggregate_and_proof", name, in, (size_t)len + 2);
            in[1] = SC_AGGREGATE_ELECTRA;
            snprintf(name, sizeof name, "go-agg-electra-%d", n);
            put("aggregate_and_proof", name, in, (size_t)len + 2);
        }
    }
    fclose(f);
}

static void builder_auth_go(const char *dir)
{
    char path[4096], line[16384], kind[8], a[9000], name[64];
    uint8_t in[4200];
    int n = 0;
    FILE *f;
    snprintf(path, sizeof path, "%s/builder_auth_go.txt", dir);
    if (!(f = fopen(path, "r"))) {
        perror(path);
        exit(1);
    }
    while (fgets(line, sizeof line, f)) {
        long len;
        if (line[0] == '#' || sscanf(line, "%7s %8999s", kind, a) != 2 || strcmp(kind, "bra"))
            continue;
        if ((len = parse_hex_any(a, in, sizeof in)) < 0)
            continue;
        snprintf(name, sizeof name, "go-bra-%d", n++);
        put("builder_request_auth", name, in, (size_t)len);
    }
    fclose(f);
}

static void registration_go(const char *dir)
{
    char path[4096], line[4096], fee[64], pk[128], name[64];
    unsigned long long gas, ts;
    int n = 0;
    FILE *f;
    snprintf(path, sizeof path, "%s/registration_go.txt", dir);
    if (!(f = fopen(path, "r"))) {
        perror(path);
        exit(1);
    }
    while (fgets(line, sizeof line, f)) {
        sc_validator_registration r;
        uint8_t enc[SC_SSZ_VALIDATOR_REGISTRATION_LEN];
        if (line[0] == '#' || sscanf(line, "%63s %llu %llu %127s", fee, &gas, &ts, pk) != 4)
            continue;
        if (parse_hex(fee, r.fee_recipient, 20) || parse_hex(pk, r.pubkey, 48))
            continue;
        r.gas_limit = gas;
        r.timestamp = ts;
        sc_ssz_encode_validator_registration(&r, enc);
        snprintf(name, sizeof name, "go-reg-%d", n++);
        put("ssz_validator_registration", name, enc, sizeof enc);
        if (n >= 16)
            break;
    }
    fclose(f);
}

/* ---- built inputs ---------------------------------------------------------- */

/* As tests/test_unit.c contribution_ssz, behind a preset byte. */
static void contributions(void)
{
    const sc_preset *ps[2] = {&SC_PRESET_MAINNET, &SC_PRESET_MINIMAL};
    for (int k = 0; k < 2; k++) {
        uint8_t in[1 + 512];
        size_t n = sc_contribution_and_proof_len(ps[k]), bl = n - 248;
        char name[32];
        memset(in, 0, sizeof in);
        in[0] = (uint8_t)k;
        put64(in + 1, 777);
        put64(in + 9, 420000ull * 32 + 9);
        memset(in + 17, 0x3c, 32);
        put64(in + 49, 2);
        in[57] = 0x05;
        memset(in + 57 + bl, 0x66, 96);
        memset(in + 57 + bl + 96, 0x99, 96);
        snprintf(name, sizeof name, "built-%s", k ? "minimal" : "mainnet");
        put("contribution_and_proof", name, in, n + 1);
    }
}

/* As tests/test_unit.c aggregate_ssz, phase0 and Electra. */
static void aggregates(void)
{
    for (int form = 0; form < 3; form++) {
        uint8_t in[2 + 512];
        sc_attestation_data d;
        size_t cb = form ? 8 : 0, n;
        char name[32];
        memset(&d, 0, sizeof d);
        d.slot = 420000ull * 32 + 9;
        d.source.epoch = 419999;
        d.target.epoch = 420000;
        memset(in, 0, sizeof in);
        in[0] = 0;
        in[1] = (uint8_t)form;
        put64(in + 2, 7);
        in[2 + 8] = 108;
        memset(in + 2 + 12, 0x99, 96);
        n = 2 + 108;
        in[n] = (uint8_t)(4 + 128 + 96 + cb);
        sc_ssz_encode_attestation_data(&d, in + n + 4);
        memset(in + n + 4 + 128, 0x77, 96);
        if (cb)
            in[n + 4 + 128 + 96] = 1;
        n += 4 + 128 + 96 + cb;
        in[n++] = 0x03;
        snprintf(name, sizeof name, "built-form%d", form);
        put("aggregate_and_proof", name, in, n);
    }
}

/* Walks dir for data.yaml files (the tarball nests them one level deeper
 * than the case folders on some releases). */
static int bls_vectors(const char *dir, int taken)
{
    struct dirent **cases;
    int nc = list_dir(dir, &cases);
    if (nc < 0)
        return taken;
    for (int i = 0; i < nc && taken < 24; i++) {
        char path[4096], name[300];
        size_t ylen;
        char *yaml;
        const char *sk_s, *msg_s, *out_s;
        uint8_t in[48 + 96 + 32 + 256];
        long msg_len;
        if (is_dot(cases[i]->d_name))
            continue;
        snprintf(path, sizeof path, "%s/%s/data.yaml", dir, cases[i]->d_name);
        if (!(yaml = (char *)read_file(path, &ylen))) {
            snprintf(path, sizeof path, "%s/%s", dir, cases[i]->d_name);
            taken = bls_vectors(path, taken);
            continue;
        }
        sk_s = yaml_value(yaml, "privkey");
        msg_s = yaml_value(yaml, "message");
        out_s = yaml_value(yaml, "output");
        memset(in, 0, sizeof in);
        if (sk_s && msg_s && out_s && !parse_hex(sk_s, in + 144, 32) &&
            (msg_len = parse_hex_any(msg_s, in + 176, 256)) >= 0) {
            sc_bls_pubkey(in + 144, in);
            if (strncmp(out_s, "null", 4) != 0)
                parse_hex(out_s, in + 48, 96);
            snprintf(name, sizeof name, "cst-%s", cases[i]->d_name);
            put("bls", name, in, 176 + (size_t)msg_len);
            taken++;
        }
        free(yaml);
    }
    for (int i = 0; i < nc; i++)
        free(cases[i]);
    free(cases);
    return taken;
}

static void configs(void)
{
    /* flags, patch count, maxv, cache, slot times count, clock sel, then steps */
    static const uint8_t c0[] = {0, 0, 3, 2, 0, 0, 0};
    static const uint8_t c1[] = {0, 1, 3, 2, 6, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    static const uint8_t c2[] = {0, 0, 3, 2, 1, 0x40, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0,
                                 2, 1, 20, 0, 1};
    static const uint8_t c3[] = {0x20, 2, 3, 2, 19, 0x80, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0x40, 4, 0, 3, 0, 1, 2, 3, 0};
    put("config", "base", c0, sizeof c0);
    put("config", "schedule", c1, sizeof c1);
    put("config", "slot-times", c2, sizeof c2);
    put("config", "patched", c3, sizeof c3);
}

/* Signer op streams: a header, two validators, then one kind of request
 * several times around a restart. 0x18 in every argument picks the clock
 * epoch, so the requests start inside the horizon. */
/* Appends one operation with its argument block: args, then 0x18 bytes. */
static size_t op_block(uint8_t *in, size_t n, int op, int v, const uint8_t *args, size_t nargs)
{
    in[n++] = (uint8_t)op;
    in[n++] = (uint8_t)v;
    memset(in + n, 0x18, ARGS_LEN);
    if (nargs)
        memcpy(in + n, args, nargs);
    return n + ARGS_LEN;
}

static void signer_seeds(void)
{
    static const uint8_t flag_sets[] = {0, F_VERIFY, F_DEVICE, F_DEVICE | F_VERIFY};
    static const uint8_t add[] = {0}, gloas[] = {0x40, 20}, next[] = {0x40, 1};
    for (size_t fs = 0; fs < sizeof flag_sets; fs++) {
        for (int op = 0; op < OP_COUNT; op++) {
            uint8_t in[HEADER_LEN + 20 * (2 + ARGS_LEN)];
            size_t n = HEADER_LEN;
            char name[64];
            memset(in, 0, HEADER_LEN);
            in[0] = flag_sets[fs];
            in[1] = 0; /* no patches */
            in[2] = 3; /* 4 validators */
            in[3] = 2; /* hash cache */
            in[4] = 7; /* clock offset */
            n = op_block(in, n, OP_ADD, 0, add, sizeof add);
            n = op_block(in, n, OP_ADD, 1, add, sizeof add);
            if ((op >= OP_PTC && op <= OP_PREFERENCES) || op == OP_BUILDER_AUTH)
                n = op_block(in, n, OP_TIME, 0, gloas, sizeof gloas); /* past the Gloas fork */
            for (int rep = 0; rep < 4; rep++) {
                if (rep == 2)
                    n = op_block(in, n, OP_RESTART, 0, NULL, 0);
                if (op == OP_ENVELOPE) /* the block it belongs to */
                    n = op_block(in, n, OP_BLOCK, rep & 1, NULL, 0);
                n = op_block(in, n, op, rep & 1, NULL, 0);
                n = op_block(in, n, OP_TIME, 0, next, sizeof next);
            }
            snprintf(name, sizeof name, "ops-f%zu-op%02d", fs, op);
            put("signer", name, in, n);
        }
    }
    /* A request, an import of its slot or vote (block and attestation flags,
     * the same picks), then the request again: the import drops the repeat
     * roots, so the marks refuse it. */
    static const uint8_t imp[] = {SC_WM_HAS_BLOCK | SC_WM_HAS_ATTESTATION};
    static const struct {
        const char *name;
        int op;
    } kinds[] = {{"attestation", OP_ATTESTATION},
                 {"block", OP_BLOCK},
                 {"ptc", OP_PTC},
                 {"envelope", OP_ENVELOPE}};
    for (size_t fs = 0; fs < sizeof flag_sets; fs++) {
        for (size_t i = 0; i < sizeof kinds / sizeof kinds[0]; i++) {
            uint8_t in[HEADER_LEN + 8 * (2 + ARGS_LEN)];
            size_t n = HEADER_LEN;
            char name[64];
            memset(in, 0, HEADER_LEN);
            in[0] = flag_sets[fs];
            in[2] = 3;
            in[3] = 2;
            in[4] = 7;
            n = op_block(in, n, OP_TIME, 0, gloas, sizeof gloas);
            n = op_block(in, n, OP_ADD, 0, add, sizeof add);
            if (kinds[i].op == OP_ENVELOPE)
                n = op_block(in, n, OP_BLOCK, 0, NULL, 0);
            n = op_block(in, n, kinds[i].op, 0, NULL, 0);
            n = op_block(in, n, OP_IMPORT, 0, imp, sizeof imp);
            n = op_block(in, n, kinds[i].op, 0, NULL, 0);
            snprintf(name, sizeof name, "import-f%zu-%s", fs, kinds[i].name);
            put("signer", name, in, n);
        }
    }
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: %s OUT_DIR TESTS_DATA_DIR SSZ_STATIC_MINIMAL_DIR BLS_SIGN_DIR\n",
                argv[0]);
        return 2;
    }
    g_out = argv[1];
    mkdir(g_out, 0755);
    ssz_static(argv[3]);
    gloas_go(argv[2]);
    builder_auth_go(argv[2]);
    registration_go(argv[2]);
    contributions();
    aggregates();
    if (bls_vectors(argv[4], 0) == 0) {
        fprintf(stderr, "mkseeds: no bls/sign vectors under %s\n", argv[4]);
        return 1;
    }
    configs();
    signer_seeds();
    printf("mkseeds: %d seed files in %s\n", g_written, g_out);
    return 0;
}
