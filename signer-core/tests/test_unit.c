/*
 * Unit tests: domains, policy, slashing protection through the signer,
 * Gloas messages (roots against go-eth2-client vectors, fork gate,
 * equivocation, restart), fork schedule and slot time updates,
 * commit-ahead writes and restart behaviour, hash_to_G2 cache, validator
 * table, and a randomized restart-safety property test.
 *
 * usage: test_unit [data dir with registration_go.txt]   (default tests/data)
 */
#include "../tests/markformat_host.h"
#include <time.h>

#include "testutil.h"

/* ---- fake host ---------------------------------------------------------- */

/* Per validator: the encoded mark, only once written. One device mark.
 * Mark writes are counted. */
#define HOST_MAX 512
typedef struct {
    struct {
        uint8_t pk[48];
        uint8_t enc[SC_WATERMARK_ENCODED_LEN];
        int has_wm;
    } rec[HOST_MAX];
    int n;
    uint8_t device[SC_WATERMARK_ENCODED_LEN];
    int has_device;
    uint64_t now;
    int fail_store, fail_clock, fail_load;
    int writes; /* mark writes, per validator or device */
} host_t;

static int h_find(host_t *h, const uint8_t pk[48], int create)
{
    for (int i = 0; i < h->n; i++)
        if (!memcmp(h->rec[i].pk, pk, 48))
            return i;
    if (!create || h->n == HOST_MAX)
        return -1;
    memset(&h->rec[h->n], 0, sizeof h->rec[0]);
    memcpy(h->rec[h->n].pk, pk, 48);
    return h->n++;
}

static int h_load(void *ctx, const uint8_t pk[48], sc_watermark *out)
{
    host_t *h = ctx;
    int i = h_find(h, pk, 0);
    if (h->fail_load)
        return SC_ERR_STORAGE;
    if (i < 0 || !h->rec[i].has_wm)
        return SC_ERR_UNKNOWN_VALIDATOR;
    return test_watermark_decode(h->rec[i].enc, SC_WATERMARK_ENCODED_LEN, out) == SC_OK
               ? SC_OK
               : SC_ERR_STORAGE;
}

static int h_store(void *ctx, const uint8_t pk[48], const sc_watermark *wm)
{
    host_t *h = ctx;
    int i;
    if (h->fail_store || (i = h_find(h, pk, 1)) < 0)
        return SC_ERR_STORAGE;
    test_watermark_encode(wm, h->rec[i].enc);
    h->rec[i].has_wm = 1;
    h->writes++;
    return SC_OK;
}

static int h_now(void *ctx, uint64_t *t)
{
    host_t *h = ctx;
    if (h->fail_clock)
        return SC_ERR_CLOCK;
    *t = h->now;
    return SC_OK;
}

static int h_load_device(void *ctx, sc_watermark *out)
{
    host_t *h = ctx;
    if (h->fail_load)
        return SC_ERR_STORAGE;
    if (!h->has_device)
        return SC_ERR_UNKNOWN_VALIDATOR;
    return test_watermark_decode(h->device, SC_WATERMARK_ENCODED_LEN, out) == SC_OK ? SC_OK
                                                                                 : SC_ERR_STORAGE;
}

static int h_store_device(void *ctx, const sc_watermark *wm)
{
    host_t *h = ctx;
    if (h->fail_store)
        return SC_ERR_STORAGE;
    test_watermark_encode(wm, h->device);
    h->has_device = 1;
    h->writes++;
    return SC_OK;
}

static sc_host_ops host_ops(host_t *h)
{
    sc_host_ops ops = {.ctx = h,
                       .load_watermark = h_load,
                       .store_watermark = h_store,
                       .now = h_now,
                       .load_device_mark = h_load_device,
                       .store_device_mark = h_store_device};
    return ops;
}

/* ---- config and helpers ------------------------------------------------- */

#define GENESIS_TIME 1606824023ull
#define EPOCH_SECONDS (12ull * 32ull)
#define E 420000ull /* a Fulu-era epoch in the mainnet-like config below */

static const uint8_t V_GENESIS[4] = {0, 0, 0, 0};
static const uint8_t V_CAPELLA[4] = {3, 0, 0, 0};
static const uint8_t V_DENEB[4] = {4, 0, 0, 0};
static const uint8_t V_ELECTRA[4] = {5, 0, 0, 0};
static const uint8_t V_FULU[4] = {6, 0, 0, 0};

static void make_config(sc_config *c)
{
    static const struct {
        uint64_t epoch;
        uint8_t v;
    } forks[] = {{74240, 1}, {144896, 2}, {194048, 3}, {269568, 4}, {364032, 5}, {411392, 6}};
    memset(c, 0, sizeof *c);
    parse_hex("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
              c->genesis_validators_root, 32);
    for (size_t i = 0; i < sizeof forks / sizeof forks[0]; i++) {
        c->forks[i].epoch = forks[i].epoch;
        c->forks[i].version[0] = forks[i].v;
    }
    c->fork_count = sizeof forks / sizeof forks[0];
    memcpy(c->voluntary_exit_fork_version, V_CAPELLA, 4);
    c->genesis_time = GENESIS_TIME;
    c->seconds_per_slot = 12;
    c->slots_per_epoch = 32;
    c->max_epochs_ahead = 2;
    c->exit_allowlist[0] = 100;
    c->exit_allowlist[1] = 200;
    c->exit_allowlist_count = 2;
    memset(c->fee_recipients[0], 0x11, 20);
    memset(c->fee_recipients[1], 0x22, 20);
    c->fee_recipient_count = 2;
    c->gas_limit_min = 30000000;
    c->gas_limit_max = 60000000;
    c->registration_max_future_seconds = 3600;
    c->commit_ahead.block_slots = 32;
    c->commit_ahead.source_epochs = 1;
    c->commit_ahead.target_epochs = 1;
}

static void set_epoch(host_t *h, uint64_t epoch) { h->now = GENESIS_TIME + epoch * EPOCH_SECONDS + 7; }

static void *g_mem[64];
static int g_nmem;

static sc_signer *new_signer(host_t *h, const sc_config *cfg, uint32_t maxv, uint32_t cache)
{
    size_t sz = sc_signer_mem_size(maxv, cache);
    void *mem = malloc(sz);
    sc_host_ops ops = host_ops(h);
    sc_signer *s = NULL;
    CHECK(sz > 0 && mem != NULL);
    CHECK_RC(sc_signer_init(mem, sz, maxv, cache, cfg, &ops, &s), SC_OK);
    if (g_nmem < 64)
        g_mem[g_nmem++] = mem;
    return s;
}

/* Deterministic valid secret: first byte 0x11 keeps it below the group order. */
static void secret_for(uint32_t i, uint8_t sk[32])
{
    for (int k = 0; k < 32; k++)
        sk[k] = (uint8_t)(i * 31u + (uint32_t)k * 7u + 1u);
    sk[0] = 0x11;
    sk[1] = (uint8_t)(i >> 8);
    sk[2] = (uint8_t)i;
}

typedef struct {
    uint8_t pk[48];       /* account pubkey */
    uint8_t share_pk[48]; /* pubkey of the loaded share */
} vkeys;

/* Loads validator i with account key i and share key 10000+i, as a
 * threshold node would hold a share rather than the full key. */
static vkeys add_validator(sc_signer *s, uint32_t i, uint64_t index)
{
    vkeys k;
    uint8_t acct[32], share[32];
    secret_for(i, acct);
    secret_for(10000 + i, share);
    CHECK_RC(sc_bls_pubkey(acct, k.pk), SC_OK);
    CHECK_RC(sc_signer_add_validator(s, k.pk, share, index, k.share_pk), SC_OK);
    return k;
}

static void root_with(const uint8_t dtype[4], const uint8_t version[4], const uint8_t gvr[32],
                      const uint8_t obj[32], uint8_t out[32])
{
    uint8_t domain[32];
    sc_compute_domain(dtype, version, gvr, domain);
    sc_compute_signing_root(obj, domain, out);
}

static sc_attestation_data att(uint64_t source, uint64_t target, uint8_t tag)
{
    sc_attestation_data a;
    memset(&a, 0, sizeof a);
    a.slot = target * 32 + 3;
    a.index = 0;
    memset(a.beacon_block_root, tag, 32);
    a.source.epoch = source;
    memset(a.source.root, 0xa0 ^ tag, 32);
    a.target.epoch = target;
    memset(a.target.root, 0xb0 ^ tag, 32);
    return a;
}

/* ---- tests -------------------------------------------------------------- */

static void test_domains(void)
{
    uint8_t d[32], want[32], fdr[32], gvr[32] = {0};
    /* Mainnet builder domain as used by mev-boost and relays. */
    parse_hex("00000001f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a9", want, 32);
    sc_compute_builder_domain(V_GENESIS, d);
    CHECK(memcmp(d, want, 32) == 0);

    parse_hex("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95", gvr, 32);
    sc_compute_domain(SC_DOMAIN_BEACON_ATTESTER, V_ELECTRA, gvr, d);
    sc_compute_fork_data_root(V_ELECTRA, gvr, fdr);
    CHECK(memcmp(d, SC_DOMAIN_BEACON_ATTESTER, 4) == 0 && memcmp(d + 4, fdr, 28) == 0);

    uint8_t u[32] = {0}, w[32] = {5};
    sc_htr_uint64(5, u);
    CHECK(memcmp(u, w, 32) == 0);

    sc_checkpoint cp;
    uint8_t buf[200] = {0};
    CHECK_RC(sc_ssz_decode_checkpoint(buf, 39, &cp), SC_ERR_DECODE);
    CHECK_RC(sc_ssz_decode_attestation_data(buf, 129, NULL), SC_ERR_DECODE);
    CHECK_RC(sc_ssz_decode_validator_registration(buf, 83, NULL), SC_ERR_DECODE);
}

static void test_registration_go(const char *dir)
{
    char path[1024], line[512];
    int n = 0, ok = 0;
    snprintf(path, sizeof path, "%s/registration_go.txt", dir);
    FILE *f = fopen(path, "r");
    CHECK(f != NULL);
    if (!f)
        return;
    while (fgets(line, sizeof line, f)) {
        char fee[64], pk[128], htr_s[80], sr_s[80];
        unsigned long long gas, ts;
        sc_validator_registration r;
        uint8_t want_htr[32], want_sr[32], htr[32], sr[32], dom[32];
        if (line[0] == '#' || sscanf(line, "%63s %llu %llu %127s %79s %79s", fee, &gas, &ts, pk,
                                     htr_s, sr_s) != 6)
            continue;
        n++;
        if (parse_hex(fee, r.fee_recipient, 20) || parse_hex(pk, r.pubkey, 48) ||
            parse_hex(htr_s, want_htr, 32) || parse_hex(sr_s, want_sr, 32))
            continue;
        r.gas_limit = gas;
        r.timestamp = ts;
        sc_htr_validator_registration(&r, htr);
        sc_compute_builder_domain(V_GENESIS, dom);
        sc_compute_signing_root(htr, dom, sr);
        ok += memcmp(htr, want_htr, 32) == 0 && memcmp(sr, want_sr, 32) == 0;
    }
    fclose(f);
    printf("registration_go vectors: %d/%d match\n", ok, n);
    CHECK(n > 0 && ok == n);
}

static void test_attestations(void)
{
    host_t h = {0};
    sc_config cfg;
    uint8_t sig[96], root[32], obj[32], unknown[48] = {0xc0};
    make_config(&cfg);
    set_epoch(&h, E);
    sc_signer *s = new_signer(&h, &cfg, 8, 4);
    vkeys k = add_validator(s, 1, 1000);
    CHECK(memcmp(k.pk, k.share_pk, 48) != 0);

    sc_attestation_data a = att(E - 1, E, 1);
    CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig), SC_OK);
    sc_htr_attestation_data(&a, obj);
    root_with(SC_DOMAIN_BEACON_ATTESTER, V_FULU, cfg.genesis_validators_root, obj, root);
    CHECK_RC(sc_bls_verify(k.share_pk, root, 32, sig), SC_OK);
    CHECK_RC(sc_bls_verify(k.pk, root, 32, sig), SC_ERR_ARG); /* share, not account key */

    a = att(E - 1, E, 2); /* double vote */
    CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig), SC_ERR_SLASH_TARGET);
    /* Exact repeat: the same signature again (sc_slashing_* alone, the
     * minimal strategy, refuses it; the signer remembers the root). */
    uint8_t sig2[96];
    a = att(E - 1, E, 1);
    CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig2), SC_OK);
    CHECK(memcmp(sig, sig2, 96) == 0); /* the refusal above left sig untouched */
    a = att(E - 2, E + 1, 1); /* would surround (E-1, E) */
    CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig), SC_ERR_SLASH_SOURCE);
    a = att(E - 1, E + 1, 1);
    CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig), SC_OK);
    a = att(E, E + 3, 1); /* clock epoch E, horizon 2 */
    CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig), SC_ERR_POLICY_FUTURE);
    a = att(E, E + 2, 1);
    CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig), SC_OK);
    a = att(E + 2, E + 1, 1);
    CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig), SC_ERR_SLASH_SOURCE_GT_TARGET);
    h.fail_clock = 1;
    a = att(E, E + 2, 3);
    CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig), SC_ERR_CLOCK);
    h.fail_clock = 0;
    CHECK_RC(sc_sign_attestation(s, unknown, &a, sig), SC_ERR_UNKNOWN_VALIDATOR);

    /* RANDAO: not slashable, but bounded by the clock. */
    CHECK_RC(sc_sign_randao_reveal(s, k.pk, E + 2, sig), SC_OK);
    sc_htr_uint64(E + 2, obj);
    root_with(SC_DOMAIN_RANDAO, V_FULU, cfg.genesis_validators_root, obj, root);
    CHECK_RC(sc_bls_verify(k.share_pk, root, 32, sig), SC_OK);
    CHECK_RC(sc_sign_randao_reveal(s, k.pk, E + 3, sig), SC_ERR_POLICY_FUTURE);
}

/* An attestation whose target epoch is not the epoch of its slot can never
 * be included: process_attestation asserts target.epoch ==
 * compute_epoch_at_slot(slot). Signed, it would only raise the target
 * mark, and the honest vote of the slot's epoch would then be refused. The
 * signer refuses it before the repeat shortcut and before any mark moves. */
static void test_attestation_slot(void)
{
    host_t h = {0};
    sc_config cfg;
    sc_slashing_state st;
    sc_repeat_roots rr;
    uint8_t sig[96], root[32], obj[32];
    make_config(&cfg);
    set_epoch(&h, E);
    sc_signer *s = new_signer(&h, &cfg, 8, 4);
    vkeys k = add_validator(s, 1, 1000);

    sc_attestation_data a = att(E - 1, E, 1);
    CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig), SC_OK);
    int writes = h.writes;

    /* Target above the slot's epoch, inside the clock horizon. */
    sc_attestation_data above = att(E, E + 2, 2);
    above.slot = (E + 1) * 32 + 3;
    CHECK(sc_sign_attestation(s, k.pk, &above, sig) != SC_OK);
    /* Target below the slot's epoch. */
    sc_attestation_data below = att(E, E + 1, 3);
    below.slot = (E + 2) * 32;
    CHECK(sc_sign_attestation(s, k.pk, &below, sig) != SC_OK);

    /* Nothing moved: the marks, the write count and the repeat root are
     * those of the first vote. */
    CHECK_RC(sc_signer_get_state(s, k.pk, &st), SC_OK);
    CHECK(st.ram.target_epoch == E && st.ram.source_epoch == E - 1);
    CHECK(h.writes == writes);
    sc_htr_attestation_data(&a, obj);
    root_with(SC_DOMAIN_BEACON_ATTESTER, V_FULU, cfg.genesis_validators_root, obj, root);
    CHECK_RC(sc_signer_get_repeat_roots(s, k.pk, &rr), SC_OK);
    CHECK((rr.flags & SC_REPEAT_HAS_ATTESTATION) && memcmp(rr.attestation_root, root, 32) == 0);

    /* The honest votes of those epochs sign, at either edge of the epoch. */
    a = att(E, E + 1, 1);
    a.slot = (E + 1) * 32;
    CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig), SC_OK);
    a = att(E + 1, E + 2, 1);
    a.slot = (E + 3) * 32 - 1;
    CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig), SC_OK);
}

/* sc_sign_root: the six domain types that need no slashing protection sign
 * under the fork version of their epoch, within the clock horizon; RANDAO
 * only with hash_tree_root(epoch); every other domain type is refused. */
static void test_sign_root(void)
{
    static const uint8_t allowed[][4] = {
        {0x02, 0, 0, 0}, {0x05, 0, 0, 0}, {0x06, 0, 0, 0},
        {0x07, 0, 0, 0}, {0x08, 0, 0, 0}, {0x09, 0, 0, 0},
    };
    static const uint8_t other[][4] = {
        {0x00, 0, 0, 0}, /* beacon proposer */
        {0x01, 0, 0, 0}, /* beacon attester */
        {0x03, 0, 0, 0}, /* deposit */
        {0x04, 0, 0, 0}, /* voluntary exit */
        {0x0a, 0, 0, 0}, /* BLS to execution change */
        {0x00, 0, 0, 1}, /* application builder */
        {0x02, 0, 0, 1}, /* allowed first byte, other bytes not zero */
        {0x05, 0, 1, 0},
        {0x09, 1, 0, 0},
        {0xff, 0xff, 0xff, 0xff},
    };
    host_t h = {0};
    sc_config cfg;
    uint8_t sig[96], keep[96], root[32], obj[32], dt[4] = {0}, unknown[48] = {0xc0};
    make_config(&cfg);
    set_epoch(&h, E);
    sc_signer *s = new_signer(&h, &cfg, 8, 4);
    vkeys k = add_validator(s, 7, 1000);
    int writes = h.writes;
    const uint64_t electra = 380000; /* an earlier epoch, Electra fork version */

    for (size_t i = 0; i < sizeof allowed / sizeof allowed[0]; i++) {
        uint64_t ep[2] = {E, electra};
        const uint8_t *ver[2] = {V_FULU, V_ELECTRA};
        for (int j = 0; j < 2; j++) {
            if (allowed[i][0] == 0x02)
                sc_htr_uint64(ep[j], obj);
            else
                memset(obj, 0x40 + (int)i, 32);
            CHECK_RC(sc_sign_root(s, k.pk, allowed[i], ep[j], obj, sig), SC_OK);
            root_with(allowed[i], ver[j], cfg.genesis_validators_root, obj, root);
            CHECK_RC(sc_bls_verify(k.share_pk, root, 32, sig), SC_OK);
        }
        /* Clock horizon: clock epoch E, max_epochs_ahead 2. */
        if (allowed[i][0] == 0x02)
            sc_htr_uint64(E + 2, obj);
        CHECK_RC(sc_sign_root(s, k.pk, allowed[i], E + 2, obj, sig), SC_OK);
        if (allowed[i][0] == 0x02)
            sc_htr_uint64(E + 3, obj);
        CHECK_RC(sc_sign_root(s, k.pk, allowed[i], E + 3, obj, sig), SC_ERR_POLICY_FUTURE);
    }
    /* The RANDAO root must be hash_tree_root(epoch); the same signature as
     * sc_sign_randao_reveal. */
    uint8_t sig2[96];
    sc_htr_uint64(E + 1, obj);
    CHECK_RC(sc_sign_root(s, k.pk, SC_DOMAIN_RANDAO, E, obj, sig), SC_ERR_ARG);
    memset(obj, 0, 32);
    CHECK_RC(sc_sign_root(s, k.pk, SC_DOMAIN_RANDAO, E, obj, sig), SC_ERR_ARG);
    sc_htr_uint64(E, obj);
    CHECK_RC(sc_sign_root(s, k.pk, SC_DOMAIN_RANDAO, E, obj, sig), SC_OK);
    CHECK_RC(sc_sign_randao_reveal(s, k.pk, E, sig2), SC_OK);
    CHECK(memcmp(sig, sig2, 96) == 0);

    /* Every other domain type is refused, before the clock is read, and the
     * signature buffer is left as it was. The Gloas types (0x0b to 0x0d,
     * test_gloas_sign_root) are refused here too: this chain has no Gloas. */
    memset(obj, 0x55, 32);
    memset(keep, 0xee, 96);
    int refused = 0;
    for (int b = 0; b < 256; b++) {
        int ok = 0;
        dt[0] = (uint8_t)b;
        for (size_t i = 0; i < sizeof allowed / sizeof allowed[0]; i++)
            ok |= allowed[i][0] == b;
        if (ok)
            continue;
        memcpy(sig, keep, 96);
        CHECK_RC(sc_sign_root(s, k.pk, dt, E, obj, sig),
                 b >= 0x0b && b <= 0x0d ? SC_ERR_POLICY_FORK : SC_ERR_POLICY_DOMAIN);
        CHECK(memcmp(sig, keep, 96) == 0);
        refused++;
    }
    CHECK(refused == 250);
    h.fail_clock = 1;
    for (size_t i = 0; i < sizeof other / sizeof other[0]; i++)
        CHECK_RC(sc_sign_root(s, k.pk, other[i], E + 1000, obj, sig), SC_ERR_POLICY_DOMAIN);
    CHECK_RC(sc_sign_root(s, k.pk, allowed[1], E, obj, sig), SC_ERR_CLOCK);
    h.fail_clock = 0;

    CHECK_RC(sc_sign_root(s, unknown, allowed[1], E, obj, sig), SC_ERR_UNKNOWN_VALIDATOR);
    CHECK_RC(sc_sign_root(s, k.pk, NULL, E, obj, sig), SC_ERR_ARG);
    CHECK_RC(sc_sign_root(s, k.pk, allowed[1], E, NULL, sig), SC_ERR_ARG);
    CHECK_RC(sc_sign_root(s, k.pk, allowed[1], E, obj, NULL), SC_ERR_ARG);
    CHECK_RC(sc_sign_root(NULL, k.pk, allowed[1], E, obj, sig), SC_ERR_ARG);

    /* No slashing state: no mark writes. */
    CHECK(h.writes == writes);
    CHECK(strcmp(sc_status_name(SC_ERR_POLICY_DOMAIN), "SC_ERR_POLICY_DOMAIN") == 0);
}

static void test_blocks(void)
{
    host_t h = {0};
    sc_config cfg;
    uint8_t sig[96], root[32], obj[32];
    make_config(&cfg);
    set_epoch(&h, E);
    sc_signer *s = new_signer(&h, &cfg, 8, 4);
    vkeys k = add_validator(s, 2, 1000);

    sc_beacon_block_header b;
    memset(&b, 0, sizeof b);
    b.slot = E * 32 + 5;
    b.proposer_index = 1000;
    memset(b.parent_root, 1, 32);
    memset(b.state_root, 2, 32);
    memset(b.body_root, 3, 32);
    CHECK_RC(sc_sign_block(s, k.pk, &b, sig), SC_OK);
    sc_htr_beacon_block_header(&b, obj);
    root_with(SC_DOMAIN_BEACON_PROPOSER, V_FULU, cfg.genesis_validators_root, obj, root);
    CHECK_RC(sc_bls_verify(k.share_pk, root, 32, sig), SC_OK);

    b.body_root[0] = 9; /* double proposal */
    CHECK_RC(sc_sign_block(s, k.pk, &b, sig), SC_ERR_SLASH_BLOCK);
    b.slot -= 1;
    CHECK_RC(sc_sign_block(s, k.pk, &b, sig), SC_ERR_SLASH_BLOCK);
    b.slot += 2;
    b.proposer_index = 999;
    CHECK_RC(sc_sign_block(s, k.pk, &b, sig), SC_ERR_POLICY_INDEX);
    b.proposer_index = 1000;
    CHECK_RC(sc_sign_block(s, k.pk, &b, sig), SC_OK);
    b.slot = (E + 3) * 32;
    CHECK_RC(sc_sign_block(s, k.pk, &b, sig), SC_ERR_POLICY_FUTURE);
}

static void test_exits(void)
{
    host_t h = {0};
    sc_config cfg;
    uint8_t sig[96], root[32], obj[32];
    make_config(&cfg);
    set_epoch(&h, E);
    sc_signer *s = new_signer(&h, &cfg, 8, 0);
    vkeys k100 = add_validator(s, 3, 100);
    vkeys k300 = add_validator(s, 4, 300);
    vkeys kany = add_validator(s, 5, SC_INDEX_UNKNOWN);

    sc_voluntary_exit ex = {E, 100};
    CHECK_RC(sc_sign_voluntary_exit(s, k100.pk, &ex, sig), SC_OK);
    sc_htr_voluntary_exit(&ex, obj);
    root_with(SC_DOMAIN_VOLUNTARY_EXIT, V_CAPELLA, cfg.genesis_validators_root, obj, root);
    CHECK_RC(sc_bls_verify(k100.share_pk, root, 32, sig), SC_OK);

    ex.validator_index = 200; /* allowlisted, but not this validator */
    CHECK_RC(sc_sign_voluntary_exit(s, k100.pk, &ex, sig), SC_ERR_POLICY_INDEX);
    ex.validator_index = 300;
    CHECK_RC(sc_sign_voluntary_exit(s, k300.pk, &ex, sig), SC_ERR_POLICY_EXIT);
    ex.validator_index = 200;
    CHECK_RC(sc_sign_voluntary_exit(s, kany.pk, &ex, sig), SC_OK);
    ex.validator_index = 300;
    CHECK_RC(sc_sign_voluntary_exit(s, kany.pk, &ex, sig), SC_ERR_POLICY_EXIT);
}

static void test_registrations(void)
{
    host_t h = {0};
    sc_config cfg;
    uint8_t sig[96], root[32], obj[32];
    make_config(&cfg);
    set_epoch(&h, E);
    sc_signer *s = new_signer(&h, &cfg, 8, 0);
    vkeys k = add_validator(s, 6, 1000);
    vkeys other = add_validator(s, 7, 1001);

    sc_validator_registration r;
    memset(r.fee_recipient, 0x11, 20);
    r.gas_limit = 36000000;
    r.timestamp = h.now;
    memcpy(r.pubkey, k.pk, 48);
    CHECK_RC(sc_sign_validator_registration(s, k.pk, &r, sig), SC_OK);
    uint8_t zero[32] = {0};
    sc_htr_validator_registration(&r, obj);
    root_with(SC_DOMAIN_APPLICATION_BUILDER, V_GENESIS, zero, obj, root);
    CHECK_RC(sc_bls_verify(k.share_pk, root, 32, sig), SC_OK);

    sc_validator_registration bad = r;
    memset(bad.fee_recipient, 0x33, 20);
    CHECK_RC(sc_sign_validator_registration(s, k.pk, &bad, sig), SC_ERR_POLICY_FEE_RECIPIENT);
    bad = r;
    memset(bad.fee_recipient, 0x22, 20);
    CHECK_RC(sc_sign_validator_registration(s, k.pk, &bad, sig), SC_OK);
    bad = r;
    bad.gas_limit = 29999999;
    CHECK_RC(sc_sign_validator_registration(s, k.pk, &bad, sig), SC_ERR_POLICY_GAS_LIMIT);
    bad.gas_limit = 60000001;
    CHECK_RC(sc_sign_validator_registration(s, k.pk, &bad, sig), SC_ERR_POLICY_GAS_LIMIT);
    bad.gas_limit = 60000000;
    CHECK_RC(sc_sign_validator_registration(s, k.pk, &bad, sig), SC_OK);
    bad = r;
    memcpy(bad.pubkey, other.pk, 48);
    CHECK_RC(sc_sign_validator_registration(s, k.pk, &bad, sig), SC_ERR_POLICY_PUBKEY);
    bad = r;
    bad.timestamp = h.now + 3601;
    CHECK_RC(sc_sign_validator_registration(s, k.pk, &bad, sig), SC_ERR_POLICY_TIMESTAMP);
    bad.timestamp = h.now + 3600;
    CHECK_RC(sc_sign_validator_registration(s, k.pk, &bad, sig), SC_OK);
}

/* sc_signer_set_policy: a running signer takes a new allowlist and gas range
 * and keeps its validators, their slashing state and the stored mark. */
static void test_set_policy(void)
{
    host_t h = {0};
    sc_config cfg, pol;
    uint8_t sig[96];
    make_config(&cfg);
    set_epoch(&h, E);
    sc_signer *s = new_signer(&h, &cfg, 4, 0);
    vkeys k = add_validator(s, 9, 100);
    sc_attestation_data a = att(E - 1, E, 1);
    CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig), SC_OK);
    int writes = h.writes;

    sc_validator_registration r;
    memset(r.fee_recipient, 0x11, 20);
    r.gas_limit = 36000000;
    r.timestamp = h.now;
    memcpy(r.pubkey, k.pk, 48);
    sc_voluntary_exit ex = {E, 100};

    pol = cfg;
    memset(pol.fee_recipients, 0, sizeof pol.fee_recipients);
    memset(pol.fee_recipients[0], 0x44, 20);
    pol.fee_recipient_count = 1;
    pol.exit_allowlist_count = 0;
    pol.gas_limit_min = 40000000;
    pol.gas_limit_max = 50000000;
    pol.max_epochs_ahead = 1000; /* not a policy field: ignored */
    CHECK_RC(sc_signer_set_policy(s, &pol), SC_OK);
    CHECK_RC(sc_sign_validator_registration(s, k.pk, &r, sig), SC_ERR_POLICY_FEE_RECIPIENT);
    memset(r.fee_recipient, 0x44, 20);
    CHECK_RC(sc_sign_validator_registration(s, k.pk, &r, sig), SC_ERR_POLICY_GAS_LIMIT);
    r.gas_limit = 45000000;
    CHECK_RC(sc_sign_validator_registration(s, k.pk, &r, sig), SC_OK);
    CHECK_RC(sc_sign_voluntary_exit(s, k.pk, &ex, sig), SC_ERR_POLICY_EXIT);
    /* The clock horizon stayed at 2 epochs. */
    sc_attestation_data far = att(E, E + 10, 2);
    CHECK_RC(sc_sign_attestation(s, k.pk, &far, sig), SC_ERR_POLICY_FUTURE);
    /* Slashing state and the repeat memory survived the update. */
    sc_attestation_data dbl = att(E - 1, E, 3);
    CHECK_RC(sc_sign_attestation(s, k.pk, &dbl, sig), SC_ERR_SLASH_TARGET);
    CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig), SC_OK);
    CHECK(h.writes == writes);

    /* A policy that fails the config checks changes nothing. */
    pol.gas_limit_min = 60000000;
    pol.gas_limit_max = 50000000;
    CHECK_RC(sc_signer_set_policy(s, &pol), SC_ERR_ARG);
    CHECK_RC(sc_sign_validator_registration(s, k.pk, &r, sig), SC_OK);
    pol = cfg;
    pol.fee_recipient_count = SC_MAX_FEE_RECIPIENTS + 1;
    CHECK_RC(sc_signer_set_policy(s, &pol), SC_ERR_ARG);
    CHECK_RC(sc_signer_set_policy(NULL, &pol), SC_ERR_ARG);
    CHECK_RC(sc_signer_set_policy(s, NULL), SC_ERR_ARG);
    /* Back to the first policy: the old allowlist works again. */
    CHECK_RC(sc_signer_set_policy(s, &cfg), SC_OK);
    CHECK_RC(sc_sign_voluntary_exit(s, k.pk, &ex, sig), SC_OK);
}

static int count_writes(sc_commit_ahead ahead, int epochs)
{
    host_t h = {0};
    sc_config cfg;
    uint8_t sig[96];
    make_config(&cfg);
    cfg.commit_ahead = ahead;
    sc_signer *s = new_signer(&h, &cfg, 1, 0);
    vkeys k = add_validator(s, 8, 1000);
    h.writes = 0;
    for (int i = 0; i < epochs; i++) {
        set_epoch(&h, E + (uint64_t)i);
        sc_attestation_data a = att(E + (uint64_t)i - 1, E + (uint64_t)i, 1);
        CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig), SC_OK);
    }
    return h.writes;
}

static void test_commit_ahead_writes(void)
{
    sc_commit_ahead none = {0, 0, 0}, one = {0, 1, 1}, four = {0, 4, 4};
    int w0 = count_writes(none, 20), w1 = count_writes(one, 20), w4 = count_writes(four, 20);
    printf("commit-ahead writes for 20 epochs of attestations: ahead=0 -> %d, ahead=1 -> %d, "
           "ahead=4 -> %d\n", w0, w1, w4);
    CHECK(w0 == 20);
    CHECK(w1 == 10);
    CHECK(w4 == 4);

    /* Blocks: window of 32 slots -> slots S..S+40 need 2 writes. */
    host_t h = {0};
    sc_config cfg;
    uint8_t sig[96];
    make_config(&cfg);
    set_epoch(&h, E + 2);
    sc_signer *s = new_signer(&h, &cfg, 1, 0);
    vkeys k = add_validator(s, 9, SC_INDEX_UNKNOWN);
    sc_beacon_block_header b;
    memset(&b, 0, sizeof b);
    h.writes = 0;
    for (uint64_t slot = E * 32; slot <= E * 32 + 40; slot++) {
        b.slot = slot;
        CHECK_RC(sc_sign_block(s, k.pk, &b, sig), SC_OK);
    }
    printf("commit-ahead writes for 41 consecutive blocks, window 32: %d\n", h.writes);
    CHECK(h.writes == 2);
}

static void test_restart(void)
{
    host_t h = {0};
    sc_config cfg;
    uint8_t sig[96];
    sc_slashing_state st;
    make_config(&cfg);
    set_epoch(&h, E);

    sc_signer *s1 = new_signer(&h, &cfg, 4, 0);
    vkeys k = add_validator(s1, 10, SC_INDEX_UNKNOWN);
    sc_attestation_data a = att(E - 1, E, 1);
    CHECK_RC(sc_sign_attestation(s1, k.pk, &a, sig), SC_OK);
    sc_beacon_block_header b;
    memset(&b, 0, sizeof b);
    b.slot = E * 32;
    CHECK_RC(sc_sign_block(s1, k.pk, &b, sig), SC_OK);
    CHECK_RC(sc_signer_get_state(s1, k.pk, &st), SC_OK);
    CHECK(st.committed.target_epoch == E + 1 && st.committed.source_epoch == E);
    CHECK(st.committed.block_slot == E * 32 + 32);
    CHECK(st.ram.target_epoch == E && st.ram.source_epoch == E - 1 && st.ram.block_slot == E * 32);
    /* Before the restart, (E-1, E+1) is fine: it is inside the window. */
    CHECK_RC(sc_slashing_check_attestation(&st, E - 1, E + 1), SC_OK);

    /* Restart: a new signer over the same storage. */
    sc_signer_wipe(s1);
    CHECK_RC(sc_sign_attestation(s1, k.pk, &a, sig), SC_ERR_UNKNOWN_VALIDATOR);
    sc_signer *s2 = new_signer(&h, &cfg, 4, 0);
    vkeys k2 = add_validator(s2, 10, SC_INDEX_UNKNOWN);
    CHECK(memcmp(k.pk, k2.pk, 48) == 0);
    CHECK_RC(sc_signer_get_state(s2, k.pk, &st), SC_OK);
    CHECK(st.ram.target_epoch == E + 1 && st.ram.source_epoch == E &&
          st.ram.block_slot == E * 32 + 32);

    a = att(E - 1, E + 1, 1);
    CHECK_RC(sc_sign_attestation(s2, k.pk, &a, sig), SC_ERR_SLASH_SOURCE);
    a = att(E, E + 1, 1);
    CHECK_RC(sc_sign_attestation(s2, k.pk, &a, sig), SC_ERR_SLASH_TARGET);
    a = att(E, E + 2, 1);
    CHECK_RC(sc_sign_attestation(s2, k.pk, &a, sig), SC_OK);
    b.slot = E * 32 + 32;
    CHECK_RC(sc_sign_block(s2, k.pk, &b, sig), SC_ERR_SLASH_BLOCK);
    b.slot = E * 32 + 33;
    CHECK_RC(sc_sign_block(s2, k.pk, &b, sig), SC_OK);
}

static void test_store_failure(void)
{
    host_t h = {0};
    sc_config cfg;
    uint8_t sig[96];
    sc_slashing_state st;
    make_config(&cfg);
    set_epoch(&h, E + 2);
    sc_signer *s = new_signer(&h, &cfg, 2, 0);
    vkeys k = add_validator(s, 11, SC_INDEX_UNKNOWN);

    sc_attestation_data a = att(E - 1, E, 1);
    CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig), SC_OK); /* window s<=E, t<=E+1 */
    h.fail_store = 1;
    a = att(E, E + 1, 1); /* inside the window: no write needed */
    CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig), SC_OK);
    a = att(E + 1, E + 2, 1); /* needs a write, which fails */
    CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig), SC_ERR_STORAGE);
    CHECK_RC(sc_signer_get_state(s, k.pk, &st), SC_OK);
    CHECK(st.ram.target_epoch == E + 1 && st.committed.target_epoch == E + 1);
    h.fail_store = 0;
    CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig), SC_OK);
}

static void test_import(void)
{
    host_t h = {0};
    sc_config cfg;
    uint8_t sig[96];
    sc_slashing_state st;
    make_config(&cfg);
    set_epoch(&h, E);
    sc_signer *s = new_signer(&h, &cfg, 2, 0);
    vkeys k = add_validator(s, 12, SC_INDEX_UNKNOWN);

    sc_watermark imp = {500, 10, 20, SC_WM_HAS_BLOCK | SC_WM_HAS_ATTESTATION};
    uint8_t wrong_gvr[32];
    memcpy(wrong_gvr, cfg.genesis_validators_root, 32);
    wrong_gvr[31] ^= 1;
    h.writes = 0;
    CHECK_RC(sc_signer_import(s, k.pk, wrong_gvr, &imp), SC_ERR_ARG);
    CHECK(h.writes == 0);
    CHECK_RC(sc_signer_import(s, k.pk, cfg.genesis_validators_root, &imp), SC_OK);
    CHECK(h.writes == 1);
    sc_attestation_data a = att(9, 21, 1);
    CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig), SC_ERR_SLASH_SOURCE);
    a = att(10, 20, 1);
    CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig), SC_ERR_SLASH_TARGET);
    a = att(10, 21, 1);
    CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig), SC_OK);

    sc_watermark lower = {1, 1, 1, SC_WM_HAS_BLOCK | SC_WM_HAS_ATTESTATION};
    CHECK_RC(sc_signer_import(s, k.pk, cfg.genesis_validators_root, &lower), SC_OK);
    CHECK_RC(sc_signer_get_state(s, k.pk, &st), SC_OK);
    CHECK(st.ram.block_slot == 500 && st.ram.target_epoch == 21 && st.ram.source_epoch == 10);
}

static void test_hash_cache(void)
{
    host_t h = {0};
    sc_config cfg;
    sc_signer_stats stats;
    enum { NV = 64 };
    static vkeys keys[NV];
    static uint8_t sigs[NV][96];
    uint8_t root[32], obj[32];
    make_config(&cfg);
    set_epoch(&h, E);
    sc_signer *s = new_signer(&h, &cfg, NV, 16);
    for (int i = 0; i < NV; i++)
        keys[i] = add_validator(s, 100 + (uint32_t)i, SC_INDEX_UNKNOWN);
    sc_attestation_data a = att(E - 1, E, 7);
    for (int i = 0; i < NV; i++)
        CHECK_RC(sc_sign_attestation(s, keys[i].pk, &a, sigs[i]), SC_OK);
    sc_signer_get_stats(s, &stats);
    printf("hash cache: %d validators signing one root -> misses=%llu hits=%llu\n", NV,
           (unsigned long long)stats.hash_cache_misses, (unsigned long long)stats.hash_cache_hits);
    CHECK(stats.hash_cache_misses == 1 && stats.hash_cache_hits == NV - 1);
    CHECK(stats.signatures == NV);
    sc_htr_attestation_data(&a, obj);
    root_with(SC_DOMAIN_BEACON_ATTESTER, V_FULU, cfg.genesis_validators_root, obj, root);
    int verified = 0;
    for (int i = 0; i < NV; i++)
        verified += sc_bls_verify(keys[i].share_pk, root, 32, sigs[i]) == SC_OK;
    CHECK(verified == NV);
}

static double now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

/* Times NV attestation signatures over one root, with and without the cache. */
static void bench_cache(void)
{
    enum { NV = 128 };
    static vkeys keys[NV];
    uint8_t sig[96];
    for (int pass = 0; pass < 2; pass++) {
        host_t h = {0};
        sc_config cfg;
        make_config(&cfg);
        set_epoch(&h, E);
        sc_signer *s = new_signer(&h, &cfg, NV, pass ? 16 : 0);
        for (int i = 0; i < NV; i++)
            keys[i] = add_validator(s, 1000 + (uint32_t)i, SC_INDEX_UNKNOWN);
        sc_attestation_data a = att(E - 1, E, 9);
        double t0 = now_us();
        for (int i = 0; i < NV; i++)
            CHECK_RC(sc_sign_attestation(s, keys[i].pk, &a, sig), SC_OK);
        double t1 = now_us();
        printf("bench: %d attestations, one root, cache=%s: %.1f us/signature\n", NV,
               pass ? "16" : "off", (t1 - t0) / NV);
    }
}

static void test_table_and_errors(void)
{
    host_t h = {0};
    sc_config cfg;
    uint8_t sk[32], pk[48], zero[32] = {0}, r_order[32];
    make_config(&cfg);
    set_epoch(&h, E);
    sc_signer *s = new_signer(&h, &cfg, 4, 0);
    for (uint32_t i = 0; i < 4; i++)
        add_validator(s, 200 + i, SC_INDEX_UNKNOWN);
    secret_for(300, sk);
    CHECK_RC(sc_bls_pubkey(sk, pk), SC_OK);
    CHECK_RC(sc_signer_add_validator(s, pk, sk, 1, NULL), SC_ERR_NOMEM);
    secret_for(200, sk);
    CHECK_RC(sc_bls_pubkey(sk, pk), SC_OK);
    CHECK_RC(sc_signer_add_validator(s, pk, sk, 1, NULL), SC_ERR_DUPLICATE);

    sc_signer *s2 = new_signer(&h, &cfg, 4, 0);
    CHECK_RC(sc_signer_add_validator(s2, pk, zero, 1, NULL), SC_ERR_BAD_KEY);
    parse_hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", r_order, 32);
    CHECK_RC(sc_signer_add_validator(s2, pk, r_order, 1, NULL), SC_ERR_BAD_KEY);
    CHECK_RC(sc_bls_check_secret(r_order), SC_ERR_BAD_KEY);
    h.fail_load = 1;
    CHECK_RC(sc_signer_add_validator(s2, pk, sk, 1, NULL), SC_ERR_STORAGE);
    h.fail_load = 0;
    CHECK_RC(sc_signer_add_validator(s2, pk, sk, 1, NULL), SC_OK);

    /* init argument checks */
    sc_host_ops ops = host_ops(&h);
    sc_signer *tmp;
    size_t sz = sc_signer_mem_size(2, 2);
    uint8_t *mem = malloc(sz + 8);
    CHECK_RC(sc_signer_init(mem + 1, sz, 2, 2, &cfg, &ops, &tmp), SC_ERR_ARG);
    CHECK_RC(sc_signer_init(mem, sz - 1, 2, 2, &cfg, &ops, &tmp), SC_ERR_NOMEM);
    sc_config badcfg = cfg;
    badcfg.slots_per_epoch = 0;
    CHECK_RC(sc_signer_init(mem, sz, 2, 2, &badcfg, &ops, &tmp), SC_ERR_ARG);
    badcfg = cfg;
    badcfg.forks[1].epoch = 1;
    CHECK_RC(sc_signer_init(mem, sz, 2, 2, &badcfg, &ops, &tmp), SC_ERR_ARG);
    /* Each storage setting needs its callbacks. */
    badcfg = cfg;
    badcfg.mark_scope = 2;
    CHECK_RC(sc_signer_init(mem, sz, 2, 2, &badcfg, &ops, &tmp), SC_ERR_ARG);
    sc_host_ops part = ops;
    part.load_device_mark = NULL;
    badcfg = cfg;
    badcfg.mark_scope = SC_MARKS_PER_DEVICE;
    CHECK_RC(sc_signer_init(mem, sz, 2, 2, &badcfg, &part, &tmp), SC_ERR_ARG);
    CHECK_RC(sc_signer_init(mem, sz, 2, 2, &cfg, &part, &tmp), SC_OK); /* per validator: not needed */
    part = ops;
    part.store_watermark = NULL;
    CHECK_RC(sc_signer_init(mem, sz, 2, 2, &cfg, &part, &tmp), SC_ERR_ARG);
    CHECK_RC(sc_signer_init(mem, sz, 2, 2, &badcfg, &part, &tmp), SC_OK); /* per device: not needed */
    free(mem);
}

static void test_fork_versions(void)
{
    host_t h = {0};
    sc_config cfg;
    uint8_t obj[32], got[32], want[32];
    make_config(&cfg);
    sc_signer *s = new_signer(&h, &cfg, 1, 0);
    memset(obj, 0x5a, 32);
    struct {
        uint64_t epoch;
        const uint8_t *v;
    } cases[] = {{0, V_GENESIS}, {364031, V_DENEB}, {364032, V_ELECTRA}, {411391, V_ELECTRA},
                 {411392, V_FULU}};
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        sc_signer_signing_root(s, SC_DOMAIN_BEACON_ATTESTER, cases[i].epoch, obj, got);
        root_with(SC_DOMAIN_BEACON_ATTESTER, cases[i].v, cfg.genesis_validators_root, obj, want);
        CHECK(memcmp(got, want, 32) == 0);
    }
    /* EIP-7044: exits use the Capella version whatever the epoch. */
    sc_signer_signing_root(s, SC_DOMAIN_VOLUNTARY_EXIT, 411392, obj, got);
    root_with(SC_DOMAIN_VOLUNTARY_EXIT, V_CAPELLA, cfg.genesis_validators_root, obj, want);
    CHECK(memcmp(got, want, 32) == 0);
}

/* ---- exact repeats ------------------------------------------------------ */

static sc_beacon_block_header blk(uint64_t slot, uint8_t tag)
{
    sc_beacon_block_header b;
    memset(&b, 0, sizeof b);
    b.slot = slot;
    memset(b.body_root, tag, 32);
    return b;
}

/* One run: the last attestation and the last block repeat with the same
 * signature and no write; an older vote or another root does not. */
static void test_repeats_in_run(void)
{
    host_t h = {0};
    sc_config cfg;
    sc_signer_stats st;
    uint8_t sig1[96], sig2[96], bsig[96], sig[96];
    make_config(&cfg);
    set_epoch(&h, E + 1);
    sc_signer *s = new_signer(&h, &cfg, 2, 4);
    vkeys k = add_validator(s, 20, SC_INDEX_UNKNOWN);

    sc_attestation_data a = att(E - 1, E, 1);
    CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig1), SC_OK);
    int writes = h.writes;
    CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig2), SC_OK);
    CHECK(memcmp(sig1, sig2, 96) == 0 && h.writes == writes);
    sc_attestation_data other = att(E - 1, E, 2);
    CHECK_RC(sc_sign_attestation(s, k.pk, &other, sig), SC_ERR_SLASH_TARGET);
    sc_attestation_data next = att(E, E + 1, 1);
    CHECK_RC(sc_sign_attestation(s, k.pk, &next, sig), SC_OK);
    CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig), SC_ERR_SLASH_SOURCE); /* only the last root */
    CHECK_RC(sc_sign_attestation(s, k.pk, &next, sig), SC_OK);

    sc_beacon_block_header b = blk(E * 32 + 1, 1);
    CHECK_RC(sc_sign_block(s, k.pk, &b, bsig), SC_OK);
    CHECK_RC(sc_sign_block(s, k.pk, &b, sig), SC_OK);
    CHECK(memcmp(bsig, sig, 96) == 0);
    sc_beacon_block_header b2 = blk(E * 32 + 1, 2);
    CHECK_RC(sc_sign_block(s, k.pk, &b2, sig), SC_ERR_SLASH_BLOCK);

    /* A repeat still passes the policy checks: here the clock horizon. */
    set_epoch(&h, E - 2);
    CHECK_RC(sc_sign_attestation(s, k.pk, &next, sig), SC_ERR_POLICY_FUTURE);
    set_epoch(&h, E + 1);
    sc_signer_get_stats(s, &st);
    CHECK(st.exact_repeats == 3);
}

/*
 * Restart, for per-validator and per-device marks: the validator loads with
 * no repeat roots, so the repeat is refused after the restart (the marks),
 * as is another root at that target or slot.
 */
static void repeat_restart_case(uint32_t scope)
{
    host_t h = {0};
    sc_config cfg;
    sc_signer_stats st;
    sc_repeat_roots rr;
    uint8_t sig[96];
    int slash_code = scope == SC_MARKS_PER_DEVICE ? SC_ERR_SLASH_TARGET : SC_ERR_SLASH_SOURCE;
    make_config(&cfg);
    cfg.mark_scope = scope;
    set_epoch(&h, E);
    sc_signer *s1 = new_signer(&h, &cfg, 2, 0);
    vkeys k = add_validator(s1, 21, SC_INDEX_UNKNOWN);
    sc_attestation_data a = att(E - 1, E, 1), other = att(E - 1, E, 2);
    sc_beacon_block_header b = blk(E * 32 + 2, 1), b2 = blk(E * 32 + 2, 2);
    CHECK_RC(sc_sign_attestation(s1, k.pk, &a, sig), SC_OK);
    CHECK_RC(sc_sign_block(s1, k.pk, &b, sig), SC_OK);

    sc_signer_wipe(s1);
    sc_signer *s2 = new_signer(&h, &cfg, 2, 0);
    add_validator(s2, 21, SC_INDEX_UNKNOWN);
    CHECK_RC(sc_signer_get_repeat_roots(s2, k.pk, &rr), SC_OK);
    CHECK(rr.flags == 0u);
    /* Per validator the marks start at source E, target E+1: (E-1, E)
     * is below both. The device mark's source bound is the signed source
     * E-1, so there the target refuses it. */
    CHECK_RC(sc_sign_attestation(s2, k.pk, &a, sig), slash_code);
    CHECK_RC(sc_sign_block(s2, k.pk, &b, sig), SC_ERR_SLASH_BLOCK);
    CHECK_RC(sc_sign_attestation(s2, k.pk, &other, sig), slash_code);
    CHECK_RC(sc_sign_block(s2, k.pk, &b2, sig), SC_ERR_SLASH_BLOCK);
    sc_signer_get_stats(s2, &st);
    CHECK(st.exact_repeats == 0u);
    printf("repeat after restart: marks %s -> attestation refused, block refused\n",
           scope == SC_MARKS_PER_DEVICE ? "per device" : "per validator");
}

static void test_repeat_restart(void)
{
    repeat_restart_case(SC_MARKS_PER_VALIDATOR);
    repeat_restart_case(SC_MARKS_PER_DEVICE);
}

/* Per-device marks: one write covers every validator and both message types. */
static void test_device_marks(void)
{
    host_t h = {0};
    sc_config cfg;
    sc_slashing_state st, st2;
    uint8_t sig[96];
    vkeys k[3];
    make_config(&cfg); /* commit_ahead {32, 1, 1} */
    cfg.mark_scope = SC_MARKS_PER_DEVICE;
    set_epoch(&h, E);
    sc_signer *s = new_signer(&h, &cfg, 4, 4);
    for (int i = 0; i < 3; i++)
        k[i] = add_validator(s, 30 + (uint32_t)i, SC_INDEX_UNKNOWN);
    CHECK(h.writes == 0 && !h.has_device);

    sc_attestation_data a = att(E - 1, E, 1);
    for (int i = 0; i < 3; i++)
        CHECK_RC(sc_sign_attestation(s, k[i].pk, &a, sig), SC_OK);
    CHECK(h.writes == 1);
    /* The source bound is the signed source E-1: no window for sources. */
    CHECK_RC(sc_signer_get_state(s, k[2].pk, &st), SC_OK);
    CHECK(st.committed.target_epoch == E + 1 && st.committed.source_epoch == E - 1 &&
          st.committed.block_slot == (E + 2) * 32 - 1);
    CHECK(st.ram.target_epoch == E && st.ram.source_epoch == E - 1 &&
          st.ram.flags == SC_WM_HAS_ATTESTATION);

    /* A block inside the window needs no write; one past it raises the
     * target and block bounds, not the source bound. */
    sc_beacon_block_header b = blk((E + 1) * 32 + 5, 1);
    CHECK_RC(sc_sign_block(s, k[1].pk, &b, sig), SC_OK);
    CHECK(h.writes == 1);
    set_epoch(&h, E + 2);
    b = blk((E + 2) * 32, 1);
    CHECK_RC(sc_sign_block(s, k[0].pk, &b, sig), SC_OK);
    CHECK(h.writes == 2);
    CHECK_RC(sc_signer_get_state(s, k[2].pk, &st), SC_OK);
    CHECK(st.committed.target_epoch == E + 3 && st.committed.source_epoch == E - 1);
    /* A new source is written before the first vote with it signs; the other
     * keys' votes with that source need no write. */
    a = att(E, E + 1, 1);
    for (int i = 0; i < 3; i++)
        CHECK_RC(sc_sign_attestation(s, k[i].pk, &a, sig), SC_OK);
    CHECK(h.writes == 3);
    CHECK_RC(sc_signer_get_state(s, k[2].pk, &st), SC_OK);
    CHECK(st.committed.target_epoch == E + 3 && st.committed.source_epoch == E &&
          st.committed.block_slot == (E + 4) * 32 - 1);

    /* Restart: every validator starts from the device mark, also k[2],
     * which never proposed. */
    sc_signer_wipe(s);
    s = new_signer(&h, &cfg, 4, 4);
    for (int i = 0; i < 3; i++)
        add_validator(s, 30 + (uint32_t)i, SC_INDEX_UNKNOWN);
    CHECK_RC(sc_signer_get_state(s, k[2].pk, &st), SC_OK);
    CHECK(st.ram.target_epoch == E + 3 && st.ram.source_epoch == E &&
          st.ram.block_slot == (E + 4) * 32 - 1);
    b = blk((E + 3) * 32, 2);
    CHECK_RC(sc_sign_block(s, k[2].pk, &b, sig), SC_ERR_SLASH_BLOCK);
    a = att(E + 1, E + 3, 2);
    CHECK_RC(sc_sign_attestation(s, k[2].pk, &a, sig), SC_ERR_SLASH_TARGET);
    a = att(E - 1, E + 4, 2);
    CHECK_RC(sc_sign_attestation(s, k[2].pk, &a, sig), SC_ERR_SLASH_SOURCE);
    a = att(E + 1, E + 4, 2);
    CHECK_RC(sc_sign_attestation(s, k[2].pk, &a, sig), SC_OK);
    CHECK(h.writes == 4);

    /* A failed write refuses and changes nothing. */
    set_epoch(&h, E + 5);
    h.fail_store = 1;
    CHECK_RC(sc_signer_get_state(s, k[1].pk, &st), SC_OK);
    a = att(E + 5, E + 6, 3);
    CHECK_RC(sc_sign_attestation(s, k[1].pk, &a, sig), SC_ERR_STORAGE);
    CHECK_RC(sc_signer_get_state(s, k[1].pk, &st2), SC_OK);
    CHECK(memcmp(&st, &st2, sizeof st) == 0 && h.writes == 4);
    h.fail_store = 0;
    CHECK_RC(sc_sign_attestation(s, k[1].pk, &a, sig), SC_OK);
    CHECK(h.writes == 5);

    /* An EIP-3076 import raises the device mark (one write). */
    sc_watermark imp = {0, E + 10, E + 10, SC_WM_HAS_ATTESTATION};
    CHECK_RC(sc_signer_import(s, k[0].pk, cfg.genesis_validators_root, &imp), SC_OK);
    CHECK(h.writes == 6);
    CHECK_RC(sc_signer_get_state(s, k[0].pk, &st), SC_OK);
    CHECK(st.committed.target_epoch == E + 10 && st.committed.source_epoch == E + 10 &&
          st.ram.target_epoch == E + 10);
    a = att(E + 5, E + 7, 4);
    CHECK_RC(sc_sign_attestation(s, k[1].pk, &a, sig), SC_OK); /* inside the device mark */
    CHECK(h.writes == 6);

    /* The device mark is read once, with the first validator; a failed read
     * refuses that validator. */
    host_t h2 = {0};
    h2.fail_load = 1;
    sc_signer *s2 = new_signer(&h2, &cfg, 2, 0);
    uint8_t share[32];
    secret_for(10000 + 30, share);
    CHECK_RC(sc_signer_add_validator(s2, k[0].pk, share, SC_INDEX_UNKNOWN, NULL), SC_ERR_STORAGE);
    h2.fail_load = 0;
    CHECK_RC(sc_signer_add_validator(s2, k[0].pk, share, SC_INDEX_UNKNOWN, NULL), SC_OK);
}

/*
 * One epoch the way the TA runs it: the first vote (key 0), then the host's
 * once-an-epoch write (here: the clock floor), which goes out with the mark
 * if the vote wrote one and otherwise calls sc_signer_cover_epoch first, then
 * the other votes and a block. Returns the host's writes in the epoch: mark
 * writes plus a floor write that no mark write carried.
 */
static int ta_epoch(sc_signer *s, host_t *h, const vkeys *k, int nkeys, uint64_t source,
                    uint64_t e, int block)
{
    uint8_t sig[96];
    int before = h->writes, floor_writes = 0;
    sc_attestation_data a = att(source, e, (uint8_t)e);
    set_epoch(h, e);
    CHECK_RC(sc_sign_attestation(s, k[0].pk, &a, sig), SC_OK);
    if (h->writes == before) {
        CHECK_RC(sc_signer_cover_epoch(s, e), SC_OK);
        if (h->writes == before)
            floor_writes = 1;
    }
    for (int i = 1; i < nkeys; i++)
        CHECK_RC(sc_sign_attestation(s, k[i].pk, &a, sig), SC_OK);
    if (block) {
        sc_beacon_block_header b = blk(e * 32 + 3, (uint8_t)e);
        CHECK_RC(sc_sign_block(s, k[0].pk, &b, sig), SC_OK);
    }
    return h->writes - before + floor_writes;
}

/* sc_signer_cover_epoch: raises targets and blocks, never the source bound. */
static void test_cover_epoch(void)
{
    host_t h = {0}, h2 = {0};
    sc_config cfg;
    sc_slashing_state st;
    vkeys k[2];
    int max_writes = 0, total = 0;
    make_config(&cfg); /* commit_ahead {32, 1, 1} */
    cfg.mark_scope = SC_MARKS_PER_DEVICE;
    set_epoch(&h, E);
    sc_signer *s = new_signer(&h, &cfg, 2, 4);
    CHECK_RC(sc_signer_cover_epoch(s, E), SC_OK);
    CHECK(h.writes == 0); /* no validator yet */
    for (int i = 0; i < 2; i++)
        k[i] = add_validator(s, 40 + (uint32_t)i, SC_INDEX_UNKNOWN);

    /* A cover before any vote sets targets and blocks; the source bound stays 0. */
    CHECK_RC(sc_signer_cover_epoch(s, E), SC_OK);
    CHECK(h.writes == 1);
    CHECK_RC(sc_signer_get_state(s, k[0].pk, &st), SC_OK);
    CHECK(st.committed.target_epoch == E + 1 && st.committed.source_epoch == 0 &&
          st.committed.block_slot == (E + 2) * 32 - 1);
    CHECK_RC(sc_signer_cover_epoch(s, E + 1), SC_OK); /* covered already */
    CHECK(h.writes == 1);
    CHECK_RC(sc_signer_cover_epoch(s, E + 2), SC_OK);
    CHECK(h.writes == 2);
    CHECK_RC(sc_signer_get_state(s, k[0].pk, &st), SC_OK);
    CHECK(st.committed.target_epoch == E + 3 && st.committed.source_epoch == 0);

    /* Finality: the source moves every epoch, so the first vote writes and the
     * floor goes with it. One write per epoch. */
    for (uint64_t e = E + 3; e < E + 9; e++) {
        int w = ta_epoch(s, &h, k, 2, e - 1, e, 1);
        max_writes = w > max_writes ? w : max_writes;
        total += w;
        if (e == E + 3) {
            /* Target E+3 was covered: the new source moved only the source bound. */
            CHECK_RC(sc_signer_get_state(s, k[0].pk, &st), SC_OK);
            CHECK(st.committed.source_epoch == E + 2 && st.committed.target_epoch == E + 3 &&
                  st.committed.block_slot == (E + 4) * 32 - 1);
        }
    }
    CHECK(max_writes == 1 && total == 6);
    CHECK_RC(sc_signer_get_state(s, k[1].pk, &st), SC_OK);
    CHECK(st.committed.source_epoch == E + 7 && st.committed.target_epoch == E + 9);

    /* No finality: the source stays at E+7. The covers raise the target bound
     * and leave the source bound at the signed source. One write per epoch. */
    max_writes = total = 0;
    for (uint64_t e = E + 9; e < E + 15; e++) {
        int w = ta_epoch(s, &h, k, 2, E + 7, e, 1);
        max_writes = w > max_writes ? w : max_writes;
        total += w;
        CHECK_RC(sc_signer_get_state(s, k[0].pk, &st), SC_OK);
        CHECK(st.committed.source_epoch == E + 7 && st.committed.target_epoch >= e);
    }
    CHECK(max_writes == 1 && total == 6);

    sc_config pv;
    make_config(&pv); /* per-validator marks */
    sc_signer *s2 = new_signer(&h2, &pv, 1, 0);
    CHECK_RC(sc_signer_cover_epoch(s2, E), SC_ERR_ARG);
}

/*
 * A restart after a long period without finality: the chain's source stays
 * at S while the target moves on for LEAK epochs, then the device restarts.
 * It must sign the first vote above its target bound (source S) and still
 * refuse double votes and surround votes, also against votes from before
 * the restart. ahead is the target window: 0 as in the TA's mainnet.conf
 * (the restart refuses no target above the last one signed), or 2. The
 * source window gets the same value; per-device marks do not use it.
 */
static void test_nonfinality_restart(uint64_t ahead)
{
    enum { NK = 3, LEAK = 40 };
    host_t h = {0};
    sc_config cfg;
    sc_slashing_state st;
    uint8_t sig[96];
    vkeys k[NK];
    int max_writes = 0, total = 0, signed_after = 0;
    uint64_t e, S = E + 3, last, bound, src_bound;
    make_config(&cfg);
    cfg.mark_scope = SC_MARKS_PER_DEVICE;
    cfg.commit_ahead.block_slots = 32;
    cfg.commit_ahead.source_epochs = ahead; /* not used with per-device marks */
    cfg.commit_ahead.target_epochs = ahead;
    set_epoch(&h, E);
    sc_signer *s = new_signer(&h, &cfg, NK, 4);
    for (int i = 0; i < NK; i++)
        k[i] = add_validator(s, 60 + (uint32_t)i, SC_INDEX_UNKNOWN);

    /* Four finalizing epochs, every key votes. The last source is S. */
    for (e = E + 1; e <= S + 1; e++)
        CHECK(ta_epoch(s, &h, k, NK, e - 1, e, 0) == 1);
    /* LEAK epochs without finality: source S. Keys 0 and 1 vote, key 2 is
     * offline. */
    for (; e <= S + 1 + LEAK; e++) {
        int w = ta_epoch(s, &h, k, 2, S, e, e % 8 == 0);
        max_writes = w > max_writes ? w : max_writes;
        total += w;
    }
    last = e - 1;
    CHECK(max_writes == 1 && total == LEAK);
    CHECK_RC(sc_signer_get_state(s, k[0].pk, &st), SC_OK);
    CHECK(st.committed.source_epoch == S && st.committed.target_epoch >= last &&
          st.committed.target_epoch <= last + ahead);
    bound = st.committed.target_epoch;
    src_bound = st.committed.source_epoch;

    /* Restart over the same storage. */
    sc_signer_wipe(s);
    s = new_signer(&h, &cfg, NK, 4);
    for (int i = 0; i < NK; i++)
        add_validator(s, 60 + (uint32_t)i, SC_INDEX_UNKNOWN);
    for (int i = 0; i < NK; i++) {
        CHECK_RC(sc_signer_get_state(s, k[i].pk, &st), SC_OK);
        CHECK(st.ram.source_epoch == S && st.ram.target_epoch == bound);
    }
    /* The epochs up to the target bound are the restart's cost. */
    sc_attestation_data a;
    for (e = last + 1; e <= bound; e++) {
        set_epoch(&h, e);
        a = att(S, e, 0x31);
        CHECK_RC(sc_sign_attestation(s, k[0].pk, &a, sig), SC_ERR_SLASH_TARGET);
    }
    /* The next vote, still with source S, signs for every key: no stall. */
    set_epoch(&h, bound + 1);
    a = att(S, bound + 1, 0x32);
    for (int i = 0; i < NK; i++) {
        int rc = sc_sign_attestation(s, k[i].pk, &a, sig);
        CHECK_RC(rc, SC_OK);
        signed_after += rc == SC_OK;
    }
    printf("non-finality restart (epochs from E), target window %llu: %d keys, %d epochs with "
           "source %llu, %d writes (at most %d per epoch), stored source bound %llu; restart after "
           "epoch %llu, refused targets up to %llu, then target %llu with source %llu: %d of %d "
           "keys signed\n",
           (unsigned long long)ahead, NK, LEAK, (unsigned long long)(S - E), total, max_writes,
           (unsigned long long)(src_bound - E), (unsigned long long)(last - E),
           (unsigned long long)(bound - E), (unsigned long long)(bound + 1 - E),
           (unsigned long long)(S - E), signed_after, NK);

    /* Still refused after the restart: */
    /* a double vote, */
    a = att(S, bound + 1, 0x33);
    CHECK_RC(sc_sign_attestation(s, k[0].pk, &a, sig), SC_ERR_SLASH_TARGET);
    /* a vote from before the restart again with another root, */
    a = att(S, last, 0x34);
    CHECK_RC(sc_sign_attestation(s, k[1].pk, &a, sig), SC_ERR_SLASH_TARGET);
    /* a vote that surrounds a vote from before the restart (S, last), */
    a = att(S - 1, bound + 2, 0x35);
    CHECK_RC(sc_sign_attestation(s, k[1].pk, &a, sig), SC_ERR_SLASH_SOURCE);
    /* one that surrounds key 2's last vote (S, S+1), from before the leak, */
    a = att(S - 2, bound + 2, 0x36);
    CHECK_RC(sc_sign_attestation(s, k[2].pk, &a, sig), SC_ERR_SLASH_SOURCE);
    /* and one surrounded by the vote just signed (S, bound+1). */
    a = att(S + 1, bound, 0x37);
    CHECK_RC(sc_sign_attestation(s, k[0].pk, &a, sig), SC_ERR_SLASH_TARGET);

    /* Finality comes back: a new source is written before it signs, and a
     * second restart refuses anything below it. */
    int before = h.writes;
    set_epoch(&h, bound + 2);
    a = att(bound + 1, bound + 2, 0x38);
    CHECK_RC(sc_sign_attestation(s, k[0].pk, &a, sig), SC_OK);
    CHECK(h.writes == before + 1);
    sc_signer_wipe(s);
    s = new_signer(&h, &cfg, NK, 4);
    for (int i = 0; i < NK; i++)
        add_validator(s, 60 + (uint32_t)i, SC_INDEX_UNKNOWN);
    CHECK_RC(sc_signer_get_state(s, k[1].pk, &st), SC_OK);
    CHECK(st.ram.source_epoch == bound + 1);
    set_epoch(&h, bound + 5);
    a = att(S, bound + 5, 0x39);
    CHECK_RC(sc_sign_attestation(s, k[1].pk, &a, sig), SC_ERR_SLASH_SOURCE);
    a = att(bound + 1, bound + 5, 0x39);
    CHECK_RC(sc_sign_attestation(s, k[1].pk, &a, sig), SC_OK);
}

/* ---- write counts: 1, 16 and 1,000 keys --------------------------------- */

/* A host that stores nothing and counts writes. */
typedef struct {
    uint64_t now;
    long marks;
} chost_t;

static int c_load(void *ctx, const uint8_t pk[48], sc_watermark *out)
{
    (void)ctx, (void)pk, (void)out;
    return SC_ERR_UNKNOWN_VALIDATOR;
}
static int c_store(void *ctx, const uint8_t pk[48], const sc_watermark *wm)
{
    (void)pk, (void)wm;
    ((chost_t *)ctx)->marks++;
    return SC_OK;
}
static int c_now(void *ctx, uint64_t *t)
{
    *t = ((chost_t *)ctx)->now;
    return SC_OK;
}
static int c_load_device(void *ctx, sc_watermark *out)
{
    (void)ctx, (void)out;
    return SC_ERR_UNKNOWN_VALIDATOR;
}
static int c_store_device(void *ctx, const sc_watermark *wm)
{
    (void)wm;
    ((chost_t *)ctx)->marks++;
    return SC_OK;
}
#define BIG_KEYS 1000
static uint8_t g_big_pk[BIG_KEYS][48];

/* Every validator signs one attestation per epoch, the way a node does, with
 * source t-1 (finality) or a fixed source (none); returns the mark writes. */
static void vote_writes(uint32_t scope, uint64_t ahead, uint32_t nkeys, int epochs, int finality,
                        long *marks)
{
    chost_t h = {0};
    sc_config cfg;
    sc_host_ops ops = {.ctx = &h,
                       .load_watermark = c_load,
                       .store_watermark = c_store,
                       .now = c_now,
                       .load_device_mark = c_load_device,
                       .store_device_mark = c_store_device};
    sc_signer *s = NULL;
    uint8_t share[32], sig[96];
    size_t sz = sc_signer_mem_size(nkeys, 16);
    void *mem = malloc(sz);
    int signed_ok = 0;

    make_config(&cfg);
    cfg.mark_scope = scope;
    cfg.commit_ahead.source_epochs = cfg.commit_ahead.target_epochs = ahead;
    CHECK(mem != NULL);
    CHECK_RC(sc_signer_init(mem, sz, nkeys, 16, &cfg, &ops, &s), SC_OK);
    for (uint32_t i = 0; i < nkeys; i++) {
        secret_for(10000 + i, share);
        CHECK_RC(sc_signer_add_validator(s, g_big_pk[i], share, SC_INDEX_UNKNOWN, NULL), SC_OK);
    }
    for (int e = 0; e < epochs; e++) {
        uint64_t t = E + (uint64_t)e;
        sc_attestation_data a = att(finality ? t - 1 : E - 1, t, 1);
        h.now = GENESIS_TIME + t * EPOCH_SECONDS + 7;
        for (uint32_t i = 0; i < nkeys; i++)
            signed_ok += sc_sign_attestation(s, g_big_pk[i], &a, sig) == SC_OK;
    }
    CHECK(signed_ok == (int)nkeys * epochs);
    *marks = h.marks;
    sc_signer_wipe(s);
    free(mem);
}

/* One row: runs vote_writes and checks the expected counts. */
static void write_row(const char *who, uint32_t scope, uint64_t ahead, uint32_t nkeys, int epochs,
                      int finality)
{
    long marks;
    long windows = (epochs + (long)ahead) / ((long)ahead + 1); /* writes per mark */
    long want_marks = (long)nkeys * windows;
    /* One device mark; its source bound has no window, so a source that moves
     * every epoch writes it every epoch. */
    if (scope == SC_MARKS_PER_DEVICE)
        want_marks = finality ? epochs : windows;
    vote_writes(scope, ahead, nkeys, epochs, finality, &marks);
    printf("write counts: %-6s %4u keys, %d epochs, %-12s marks %-13s commit-ahead %llu "
           "-> %ld mark writes = %.2f per epoch\n",
           who, nkeys, epochs, finality ? "finality," : "no finality,",
           scope == SC_MARKS_PER_DEVICE ? "per device," : "per validator,",
           (unsigned long long)ahead, marks, (double)marks / epochs);
    CHECK(marks == want_marks);
}

static void test_write_counts(void)
{
    static const uint32_t keys[] = {1, 16, BIG_KEYS};
    uint8_t acct[32];
    for (uint32_t i = 0; i < BIG_KEYS; i++) {
        secret_for(i, acct);
        CHECK_RC(sc_bls_pubkey(acct, g_big_pk[i]), SC_OK);
    }
    for (size_t j = 0; j < sizeof keys / sizeof keys[0]; j++) {
        uint32_t n = keys[j];
        int epochs = n == BIG_KEYS ? 3 : 6;
        /* Board (OP-TEE): one mark per device. With finality
         * the source moves every epoch: one write per epoch, window or not.
         * Without finality: one per epoch with no target window (the TA's
         * mainnet.conf), one per three epochs with a target window of 2. */
        write_row("board", SC_MARKS_PER_DEVICE, 0, n, epochs, 1);
        write_row("board", SC_MARKS_PER_DEVICE, 2, n, epochs, 1);
        write_row("board", SC_MARKS_PER_DEVICE, 0, n, epochs, 0);
        write_row("board", SC_MARKS_PER_DEVICE, 2, n, epochs, 0);
        /* Marks per validator (the cloud runner without the mark log, and the
         * TA before the write-rate change): N/2 writes per epoch with a
         * window of 1. */
        write_row("cloud", SC_MARKS_PER_VALIDATOR, 1, n, epochs, 1);
    }
}

/* ---- randomized restart safety ----------------------------------------- */

static uint64_t rng_state = 0x9e3779b97f4a7c15ull;
static uint64_t rnd(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

typedef struct {
    sc_watermark wm;
    int has;
} store1_t;

static int store1(void *ctx, const uint8_t pk[48], const sc_watermark *wm)
{
    (void)pk;
    store1_t *s = ctx;
    s->wm = *wm;
    s->has = 1;
    return SC_OK;
}

/*
 * Feeds random attestation and block requests through the slashing state,
 * crashing (restore from storage) at random points, with random window
 * sizes. Every accepted message is checked against all earlier accepted
 * messages for double votes, surround votes and double proposals.
 */
static void test_restart_property(void)
{
    enum { TRIALS = 3000, OPS = 60 };
    static uint64_t hs[OPS], ht[OPS], hb[OPS];
    long violations = 0, accepted = 0, refused = 0, crashes = 0;
    uint8_t pk[48] = {0};

    for (int trial = 0; trial < TRIALS; trial++) {
        sc_commit_ahead ahead = {rnd() % 40, rnd() % 4, rnd() % 4};
        store1_t st = {0};
        sc_slashing_state s;
        int nh = 0, nb = 0;
        uint64_t epoch = 10 + rnd() % 5;
        sc_slashing_restore(&s, NULL);
        for (int op = 0; op < OPS; op++) {
            if (rnd() % 8 == 0) {
                sc_slashing_restore(&s, st.has ? &st.wm : NULL);
                crashes++;
            }
            if (rnd() % 3 == 0)
                epoch += rnd() % 3;
            if (rnd() % 4 == 0) {
                uint64_t slot = epoch * 32 + rnd() % 64 - 32;
                if (sc_slashing_approve_block(&s, &ahead, store1, &st, pk, slot) == SC_OK) {
                    for (int j = 0; j < nb; j++)
                        violations += hb[j] == slot;
                    hb[nb++] = slot;
                    accepted++;
                } else {
                    refused++;
                }
                continue;
            }
            /* Mostly honest (source = target-1 or a bit older), sometimes wild. */
            uint64_t t = epoch - rnd() % 3;
            uint64_t sdist = rnd() % 5 == 0 ? rnd() % 8 : 1 + rnd() % 2;
            uint64_t src = t >= sdist ? t - sdist : 0;
            if (sc_slashing_approve_attestation(&s, &ahead, store1, &st, pk, src, t) == SC_OK) {
                for (int j = 0; j < nh; j++) {
                    int dbl = ht[j] == t;
                    int surround = (src < hs[j] && ht[j] < t) || (hs[j] < src && t < ht[j]);
                    violations += dbl || surround;
                }
                hs[nh] = src;
                ht[nh++] = t;
                accepted++;
            } else {
                refused++;
            }
        }
    }
    printf("restart property: %d trials, %ld crashes, %ld accepted, %ld refused, %ld violations\n",
           TRIALS, crashes, accepted, refused, violations);
    CHECK(violations == 0);
    CHECK(accepted > 0 && crashes > 0);
}

static int store_device1(void *ctx, const sc_watermark *wm)
{
    store1_t *s = ctx;
    s->wm = *wm;
    s->has = 1;
    return SC_OK;
}

/*
 * The same with per-device marks: several validators share one mark, each
 * gets random attestations and blocks, and a crash restarts all of them from
 * the stored device mark. Each accepted message is checked against the
 * earlier accepted messages of the same validator.
 */
static void test_device_restart_property(void)
{
    enum { TRIALS = 2000, OPS = 80, NV = 4, SPE = 32 };
    static uint64_t hs[NV][OPS], ht[NV][OPS], hb[NV][OPS];
    long violations = 0, accepted = 0, refused = 0, crashes = 0, writes = 0;

    for (int trial = 0; trial < TRIALS; trial++) {
        sc_commit_ahead ahead = {0, rnd() % 4, rnd() % 4};
        store1_t st = {0};
        sc_watermark device = {0, 0, 0, 0};
        sc_slashing_state v[NV];
        int nh[NV] = {0}, nb[NV] = {0};
        uint64_t epoch = 10 + rnd() % 5;
        for (int i = 0; i < NV; i++)
            sc_slashing_restore(&v[i], NULL);
        for (int op = 0; op < OPS; op++) {
            if (rnd() % 8 == 0) {
                memset(&device, 0, sizeof device);
                if (st.has)
                    device = st.wm;
                for (int i = 0; i < NV; i++)
                    sc_slashing_restore(&v[i], &device);
                crashes++;
            }
            if (rnd() % 3 == 0)
                epoch += rnd() % 3;
            int i = (int)(rnd() % NV);
            sc_watermark before = device;
            if (rnd() % 4 == 0) {
                uint64_t slot = epoch * SPE + rnd() % (2 * SPE) - SPE;
                if (sc_slashing_approve_block_device(&v[i], &device, &ahead, SPE, store_device1, &st,
                                                     slot) == SC_OK) {
                    for (int j = 0; j < nb[i]; j++)
                        violations += hb[i][j] == slot;
                    hb[i][nb[i]++] = slot;
                    accepted++;
                } else {
                    refused++;
                }
            } else {
                uint64_t t = epoch - rnd() % 3;
                uint64_t sdist = rnd() % 5 == 0 ? rnd() % 8 : 1 + rnd() % 2;
                uint64_t src = t >= sdist ? t - sdist : 0;
                if (sc_slashing_approve_attestation_device(&v[i], &device, &ahead, SPE,
                                                           store_device1, &st, src, t) == SC_OK) {
                    for (int j = 0; j < nh[i]; j++) {
                        int dbl = ht[i][j] == t;
                        int surround = (src < hs[i][j] && ht[i][j] < t) ||
                                       (hs[i][j] < src && t < ht[i][j]);
                        violations += dbl || surround;
                    }
                    hs[i][nh[i]] = src;
                    ht[i][nh[i]++] = t;
                    accepted++;
                } else {
                    refused++;
                }
            }
            writes += memcmp(&before, &device, sizeof device) != 0;
        }
    }
    printf("device restart property: %d trials, %d validators per device, %ld crashes, "
           "%ld accepted, %ld refused, %ld device writes, %ld violations\n",
           TRIALS, NV, crashes, accepted, refused, writes, violations);
    CHECK(violations == 0);
    CHECK(accepted > 0 && crashes > 0);
}

/* ---- Gloas ---------------------------------------------------------------- */

#define G (E + 5) /* Gloas fork epoch in make_gloas_config */
static const uint8_t V_GLOAS[4] = {7, 0, 0, 0};

/* make_config plus a Gloas fork at epoch G. */
static void make_gloas_config(sc_config *c)
{
    make_config(c);
    c->forks[c->fork_count].epoch = G;
    memcpy(c->forks[c->fork_count].version, V_GLOAS, 4);
    c->fork_count++;
    c->gloas_scheduled = 1;
    c->gloas_fork_epoch = G;
}

/* Vectors from tools/xcheck-gloas (go-eth2-client v0.30.3): SSZ or the
 * envelope layout, re-encode, and hash_tree_root of the full container. */
static void test_gloas_go(const char *dir)
{
    char path[1024], line[8192], kind[8], a[4096], b[80];
    int n[3] = {0}, ok[3] = {0};
    uint8_t in[2048], want[32], got[32], enc[SC_PAYLOAD_ENVELOPE_ENCODED_LEN];
    snprintf(path, sizeof path, "%s/gloas_go.txt", dir);
    FILE *f = fopen(path, "r");
    CHECK(f != NULL);
    if (!f)
        return;
    while (fgets(line, sizeof line, f)) {
        size_t len;
        int k = -1, good = 0;
        if (line[0] == '#' || sscanf(line, "%7s %4095s %79s", kind, a, b) != 3)
            continue;
        len = strlen(a) / 2;
        if (len > sizeof in || parse_hex(a, in, len) || parse_hex(b, want, 32))
            continue;
        if (!strcmp(kind, "ptc")) {
            sc_payload_attestation_data d;
            k = 0;
            if (sc_ssz_decode_payload_attestation_data(in, len, &d) == SC_OK) {
                sc_ssz_encode_payload_attestation_data(&d, enc);
                sc_htr_payload_attestation_data(&d, got);
                good = !memcmp(enc, in, len) && !memcmp(got, want, 32);
            }
        } else if (!strcmp(kind, "pref")) {
            sc_proposer_preferences p;
            k = 1;
            if (sc_ssz_decode_proposer_preferences(in, len, &p) == SC_OK) {
                sc_ssz_encode_proposer_preferences(&p, enc);
                sc_htr_proposer_preferences(&p, got);
                good = !memcmp(enc, in, len) && !memcmp(got, want, 32);
            }
        } else if (!strcmp(kind, "env")) {
            sc_payload_envelope e;
            k = 2;
            if (sc_decode_payload_envelope(in, len, &e) == SC_OK) {
                sc_encode_payload_envelope(&e, enc);
                sc_htr_payload_envelope(&e, got);
                good = !memcmp(enc, in, len) && !memcmp(got, want, 32);
            }
        }
        if (k >= 0) {
            n[k]++;
            ok[k] += good;
        }
    }
    fclose(f);
    printf("gloas_go vectors: PayloadAttestationData %d/%d, ProposerPreferences %d/%d, "
           "ExecutionPayloadEnvelope %d/%d match\n",
           ok[0], n[0], ok[1], n[1], ok[2], n[2]);
    CHECK(n[0] > 0 && n[1] > 0 && n[2] > 0);
    CHECK(ok[0] == n[0] && ok[1] == n[1] && ok[2] == n[2]);
}

/* hash(a || b): SigningData merkleization is exactly that. */
static void sha_pair(const uint8_t a[32], const uint8_t b[32], uint8_t out[32])
{
    uint8_t x[32], y[32];
    memcpy(x, a, 32);
    memcpy(y, b, 32);
    sc_compute_signing_root(x, y, out);
}

static void test_gloas_ssz(void)
{
    uint8_t c[86][32], r[32], w[32], h1[32], h2[32], buf[64] = {0};
    sc_payload_attestation_data d;
    memset(c, 0, sizeof c);
    /* Progressive merkleization by hand (EIP-7916 shape). */
    CHECK_RC(sc_merkleize_progressive(c, 0, r), SC_OK);
    CHECK(memcmp(r, w, 0) == 0 && r[0] == 0 && r[31] == 0);
    for (int i = 0; i < 6; i++)
        memset(c[i], i + 1, 32);
    CHECK_RC(sc_merkleize_progressive(c, 1, r), SC_OK); /* hash(c0, zero) */
    sha_pair(c[0], buf, w);
    CHECK(memcmp(r, w, 32) == 0);
    /* 6 chunks: hash(c0, hash(merkle4(c1..c4), hash(merkle16(c5, 0...), zero))) */
    CHECK_RC(sc_merkleize_progressive(c, 6, r), SC_OK);
    {
        uint8_t l4a[32], l4b[32], l4[32], l16[32], z[32] = {0}, t[32], right[32];
        sha_pair(c[1], c[2], l4a);
        sha_pair(c[3], c[4], l4b);
        sha_pair(l4a, l4b, l4);
        /* 16-leaf tree holding c5 then zeros */
        memcpy(t, c[5], 32);
        for (int lvl = 0; lvl < 4; lvl++) {
            uint8_t zl[32];
            memcpy(zl, z, 32);
            sha_pair(t, zl, t);
            sha_pair(z, z, z);
        }
        memcpy(l16, t, 32);
        memset(z, 0, 32);
        sha_pair(l16, z, h1);
        sha_pair(l4, h1, right);
        sha_pair(c[0], right, w);
    }
    CHECK(memcmp(r, w, 32) == 0);
    CHECK_RC(sc_merkleize_progressive(c, 85, r), SC_OK);
    CHECK_RC(sc_merkleize_progressive(c, 86, r), SC_ERR_ARG);
    CHECK_RC(sc_merkleize_progressive(NULL, 1, r), SC_ERR_ARG);

    /* Booleans must be 0 or 1. */
    memset(buf, 0, sizeof buf);
    CHECK_RC(sc_ssz_decode_payload_attestation_data(buf, 42, &d), SC_OK);
    buf[40] = 2;
    CHECK_RC(sc_ssz_decode_payload_attestation_data(buf, 42, &d), SC_ERR_DECODE);
    buf[40] = 1;
    buf[41] = 0xff;
    CHECK_RC(sc_ssz_decode_payload_attestation_data(buf, 42, &d), SC_ERR_DECODE);
    buf[41] = 1;
    CHECK_RC(sc_ssz_decode_payload_attestation_data(buf, 41, &d), SC_ERR_DECODE);
    CHECK_RC(sc_ssz_decode_proposer_preferences(buf, 75, NULL), SC_ERR_DECODE);
    CHECK_RC(sc_decode_payload_envelope(buf, 64, NULL), SC_ERR_DECODE);

    /* payload_present changes the root. */
    sc_ssz_decode_payload_attestation_data(buf, 42, &d);
    sc_htr_payload_attestation_data(&d, h1);
    d.payload_present = 0;
    sc_htr_payload_attestation_data(&d, h2);
    CHECK(memcmp(h1, h2, 32) != 0);

    CHECK(memcmp(SC_DOMAIN_BEACON_BUILDER, "\x0b\0\0\0", 4) == 0);
    CHECK(memcmp(SC_DOMAIN_PTC_ATTESTER, "\x0c\0\0\0", 4) == 0);
    CHECK(memcmp(SC_DOMAIN_PROPOSER_PREFERENCES, "\x0d\0\0\0", 4) == 0);
}

static void test_gloas_config(void)
{
    host_t h = {0};
    sc_config cfg;
    sc_host_ops ops = host_ops(&h);
    sc_signer *s = NULL;
    size_t sz = sc_signer_mem_size(4, 0);
    void *mem = malloc(sz);
    make_gloas_config(&cfg);
    CHECK_RC(sc_signer_init(mem, sz, 4, 0, &cfg, &ops, &s), SC_OK);
    cfg.gloas_fork_epoch = G + 1; /* not a fork of the schedule */
    CHECK_RC(sc_signer_init(mem, sz, 4, 0, &cfg, &ops, &s), SC_ERR_ARG);
    cfg.gloas_fork_epoch = G;
    cfg.gloas_scheduled = 2;
    CHECK_RC(sc_signer_init(mem, sz, 4, 0, &cfg, &ops, &s), SC_ERR_ARG);
    cfg.gloas_scheduled = 0;
    cfg.gloas_fork_epoch = 12345; /* ignored while not scheduled */
    CHECK_RC(sc_signer_init(mem, sz, 4, 0, &cfg, &ops, &s), SC_OK);
    free(mem);
    CHECK(strcmp(sc_status_name(SC_ERR_EQUIVOCATION), "SC_ERR_EQUIVOCATION") == 0);
    CHECK(strcmp(sc_status_name(SC_ERR_POLICY_FORK), "SC_ERR_POLICY_FORK") == 0);
    CHECK(SC_ERR_POLICY_DOMAIN == 20 && SC_ERR_POLICY_FORK == 21); /* old codes unchanged */
}

static sc_payload_attestation_data ptc(uint64_t slot, uint8_t present)
{
    sc_payload_attestation_data d;
    memset(&d, 0, sizeof d);
    memset(d.beacon_block_root, 0x5a, 32);
    d.slot = slot;
    d.payload_present = present;
    d.blob_data_available = 1;
    return d;
}

static void test_gloas_ptc(void)
{
    host_t h = {0};
    sc_config cfg;
    uint8_t sig[96], sig2[96], root[32], obj[32];
    make_gloas_config(&cfg);
    set_epoch(&h, G);
    sc_signer *s = new_signer(&h, &cfg, 8, 4);
    vkeys k = add_validator(s, 40, 1000);
    sc_payload_attestation_data d;

    d = ptc((G - 1) * 32 + 31, 1); /* last slot before the fork */
    CHECK_RC(sc_sign_payload_attestation(s, k.pk, &d, sig), SC_ERR_POLICY_FORK);
    d = ptc(G * 32 + 4, 1);
    CHECK_RC(sc_sign_payload_attestation(s, k.pk, &d, sig), SC_OK);
    sc_htr_payload_attestation_data(&d, obj);
    root_with(SC_DOMAIN_PTC_ATTESTER, V_GLOAS, cfg.genesis_validators_root, obj, root);
    CHECK_RC(sc_bls_verify(k.share_pk, root, 32, sig), SC_OK);
    /* Exact repeat signs the same; the other vote for the slot is refused. */
    CHECK_RC(sc_sign_payload_attestation(s, k.pk, &d, sig2), SC_OK);
    CHECK(memcmp(sig, sig2, 96) == 0);
    d = ptc(G * 32 + 4, 0);
    CHECK_RC(sc_sign_payload_attestation(s, k.pk, &d, sig), SC_ERR_EQUIVOCATION);
    d = ptc(G * 32 + 3, 1);
    CHECK_RC(sc_sign_payload_attestation(s, k.pk, &d, sig), SC_ERR_EQUIVOCATION);
    d = ptc(G * 32 + 5, 0);
    CHECK_RC(sc_sign_payload_attestation(s, k.pk, &d, sig), SC_OK);
    d = ptc((G + 3) * 32, 0); /* clock epoch G, horizon 2 */
    CHECK_RC(sc_sign_payload_attestation(s, k.pk, &d, sig), SC_ERR_POLICY_FUTURE);
    d = ptc(G * 32 + 6, 2);
    CHECK_RC(sc_sign_payload_attestation(s, k.pk, &d, sig), SC_ERR_ARG);

    /* Gloas not scheduled: refused at any epoch. */
    host_t h2 = {0};
    make_config(&cfg);
    set_epoch(&h2, G);
    sc_signer *s2 = new_signer(&h2, &cfg, 8, 4);
    vkeys k2 = add_validator(s2, 41, 1000);
    d = ptc(G * 32 + 4, 1);
    CHECK_RC(sc_sign_payload_attestation(s2, k2.pk, &d, sig), SC_ERR_POLICY_FORK);
}

/* VSGLOAS-01: an imported block bound raises the Gloas slot bounds, per
 * validator and per device: no PTC vote at or below it signs. */
static void test_gloas_import(void)
{
    for (int device = 0; device < 2; device++) {
        host_t h = {0};
        sc_config cfg;
        uint8_t sig[96];
        make_gloas_config(&cfg);
        if (device)
            cfg.mark_scope = SC_MARKS_PER_DEVICE;
        set_epoch(&h, G);
        sc_signer *s = new_signer(&h, &cfg, 8, 4);
        vkeys k = add_validator(s, 42, 1000);
        sc_watermark imp = {0};
        imp.flags = SC_WM_HAS_BLOCK;
        imp.block_slot = G * 32 + 10;
        CHECK_RC(sc_signer_import(s, k.pk, cfg.genesis_validators_root, &imp), SC_OK);
        sc_payload_attestation_data d = ptc(G * 32 + 5, 1);
        CHECK_RC(sc_sign_payload_attestation(s, k.pk, &d, sig), SC_ERR_EQUIVOCATION);
        d = ptc(G * 32 + 10, 1);
        CHECK_RC(sc_sign_payload_attestation(s, k.pk, &d, sig), SC_ERR_EQUIVOCATION);
        d = ptc(G * 32 + 11, 1);
        CHECK_RC(sc_sign_payload_attestation(s, k.pk, &d, sig), SC_OK);
    }
}

/* sc_sign_root with the Gloas domain types (the cloud runner's unverified
 * path for stock clients): signed under the Gloas fork version from the fork
 * epoch on, within the clock horizon, with no slot rule and no mark write;
 * before the fork refused before the clock is read. */
static void test_gloas_sign_root(void)
{
    static const uint8_t *const types[3] = {SC_DOMAIN_BEACON_BUILDER, SC_DOMAIN_PTC_ATTESTER,
                                            SC_DOMAIN_PROPOSER_PREFERENCES};
    host_t h = {0};
    sc_config cfg;
    uint8_t sig[96], sig2[96], keep[96], obj[32], root[32];
    make_gloas_config(&cfg);
    set_epoch(&h, G);
    sc_signer *s = new_signer(&h, &cfg, 8, 4);
    vkeys k = add_validator(s, 42, 1000);
    int writes = h.writes;

    memset(keep, 0xee, 96);
    for (int i = 0; i < 3; i++) {
        memset(obj, 0x60 + i, 32);
        CHECK_RC(sc_sign_root(s, k.pk, types[i], G, obj, sig), SC_OK);
        root_with(types[i], V_GLOAS, cfg.genesis_validators_root, obj, root);
        CHECK_RC(sc_bls_verify(k.share_pk, root, 32, sig), SC_OK);
        /* A second, different root at the same epoch signs too: a bare root
         * carries no slot, so the typed calls' one-per-slot rule cannot apply. */
        memset(obj, 0x70 + i, 32);
        CHECK_RC(sc_sign_root(s, k.pk, types[i], G, obj, sig2), SC_OK);
        CHECK(memcmp(sig, sig2, 96) != 0);
        /* Clock horizon: clock epoch G, max_epochs_ahead 2. */
        CHECK_RC(sc_sign_root(s, k.pk, types[i], G + 2, obj, sig), SC_OK);
        CHECK_RC(sc_sign_root(s, k.pk, types[i], G + 3, obj, sig), SC_ERR_POLICY_FUTURE);
        /* Before the fork: refused, signature buffer untouched. */
        memcpy(sig, keep, 96);
        CHECK_RC(sc_sign_root(s, k.pk, types[i], G - 1, obj, sig), SC_ERR_POLICY_FORK);
        CHECK(memcmp(sig, keep, 96) == 0);
    }
    /* The fork check comes before the clock read. */
    h.fail_clock = 1;
    CHECK_RC(sc_sign_root(s, k.pk, SC_DOMAIN_PTC_ATTESTER, G - 1, obj, sig), SC_ERR_POLICY_FORK);
    CHECK_RC(sc_sign_root(s, k.pk, SC_DOMAIN_PTC_ATTESTER, G, obj, sig), SC_ERR_CLOCK);
    h.fail_clock = 0;
    /* DOMAIN_BUILDER_DEPOSIT (0x0E, a builder's proof of possession) and the
     * other Gloas-era bytes stay refused. */
    static const uint8_t builder_deposit[4] = {0x0e, 0, 0, 0}, ptc_other[4] = {0x0c, 0, 0, 1};
    CHECK_RC(sc_sign_root(s, k.pk, builder_deposit, G, obj, sig), SC_ERR_POLICY_DOMAIN);
    CHECK_RC(sc_sign_root(s, k.pk, ptc_other, G, obj, sig), SC_ERR_POLICY_DOMAIN);
    /* No slashing state: no mark writes. */
    CHECK(h.writes == writes);
}

static sc_beacon_block_header gblock(uint64_t slot, uint8_t tag)
{
    sc_beacon_block_header b;
    memset(&b, 0, sizeof b);
    b.slot = slot;
    b.proposer_index = 1000;
    memset(b.parent_root, 0x10 ^ tag, 32);
    memset(b.state_root, 0x20 ^ tag, 32);
    memset(b.body_root, 0x30 ^ tag, 32);
    return b;
}

static sc_payload_envelope envelope_for(const sc_beacon_block_header *b, const sc_config *cfg,
                                        uint8_t tag)
{
    sc_payload_envelope e;
    memset(&e, 0, sizeof e);
    memset(e.payload.parent_hash, 0x41, 32);
    memcpy(e.payload.fee_recipient, cfg->fee_recipients[0], 20);
    memset(e.payload.transactions_root, tag, 32);
    e.payload.gas_limit = 45000000;
    e.payload.slot_number = b->slot;
    e.builder_index = SC_BUILDER_INDEX_SELF_BUILD;
    sc_htr_beacon_block_header(b, e.beacon_block_root);
    memcpy(e.parent_beacon_block_root, b->parent_root, 32);
    return e;
}

static void test_gloas_envelope(void)
{
    host_t h = {0};
    sc_config cfg;
    uint8_t sig[96], sig2[96], root[32], obj[32];
    make_gloas_config(&cfg);
    set_epoch(&h, G);
    sc_signer *s = new_signer(&h, &cfg, 8, 4);
    vkeys k = add_validator(s, 42, 1000);
    sc_beacon_block_header b = gblock(G * 32 + 2, 1);
    sc_payload_envelope e = envelope_for(&b, &cfg, 7);

    /* No block signed yet. */
    CHECK_RC(sc_sign_payload_envelope(s, k.pk, &e, sig), SC_ERR_POLICY_ENVELOPE);
    CHECK_RC(sc_sign_block(s, k.pk, &b, sig), SC_OK);
    CHECK_RC(sc_sign_payload_envelope(s, k.pk, &e, sig), SC_OK);
    sc_htr_payload_envelope(&e, obj);
    root_with(SC_DOMAIN_BEACON_BUILDER, V_GLOAS, cfg.genesis_validators_root, obj, root);
    CHECK_RC(sc_bls_verify(k.share_pk, root, 32, sig), SC_OK);
    CHECK_RC(sc_sign_payload_envelope(s, k.pk, &e, sig2), SC_OK); /* exact repeat */
    CHECK(memcmp(sig, sig2, 96) == 0);
    sc_payload_envelope e2 = envelope_for(&b, &cfg, 8); /* another payload, same block */
    CHECK_RC(sc_sign_payload_envelope(s, k.pk, &e2, sig), SC_ERR_EQUIVOCATION);

    /* Next block: each policy refusal, then the good one. */
    sc_beacon_block_header b2 = gblock(G * 32 + 9, 2);
    e2 = envelope_for(&b2, &cfg, 9);
    CHECK_RC(sc_sign_payload_envelope(s, k.pk, &e2, sig), SC_ERR_POLICY_ENVELOPE);
    CHECK_RC(sc_sign_block(s, k.pk, &b2, sig), SC_OK);
    e2.builder_index = 5;
    CHECK_RC(sc_sign_payload_envelope(s, k.pk, &e2, sig), SC_ERR_POLICY_BUILDER);
    e2 = envelope_for(&b2, &cfg, 9);
    memset(e2.payload.fee_recipient, 0x99, 20);
    CHECK_RC(sc_sign_payload_envelope(s, k.pk, &e2, sig), SC_ERR_POLICY_FEE_RECIPIENT);
    e2 = envelope_for(&b2, &cfg, 9);
    e2.beacon_block_root[0] ^= 1;
    CHECK_RC(sc_sign_payload_envelope(s, k.pk, &e2, sig), SC_ERR_POLICY_ENVELOPE);
    e2 = envelope_for(&b2, &cfg, 9);
    e2.parent_beacon_block_root[0] ^= 1;
    CHECK_RC(sc_sign_payload_envelope(s, k.pk, &e2, sig), SC_ERR_POLICY_ENVELOPE);
    e2 = envelope_for(&b2, &cfg, 9);
    e2.payload.slot_number++;
    CHECK_RC(sc_sign_payload_envelope(s, k.pk, &e2, sig), SC_ERR_POLICY_ENVELOPE);
    e2 = envelope_for(&b2, &cfg, 9);
    CHECK_RC(sc_sign_payload_envelope(s, k.pk, &e2, sig), SC_OK);
    /* The old block's envelope no longer qualifies. */
    CHECK_RC(sc_sign_payload_envelope(s, k.pk, &e, sig), SC_ERR_POLICY_ENVELOPE);

    /* Before the fork: refused even for a block signed then. */
    host_t h2 = {0};
    set_epoch(&h2, G - 1);
    sc_signer *s2 = new_signer(&h2, &cfg, 8, 4);
    vkeys k2 = add_validator(s2, 43, 1000);
    sc_beacon_block_header b3 = gblock((G - 1) * 32 + 2, 3);
    sc_payload_envelope e3 = envelope_for(&b3, &cfg, 1);
    CHECK_RC(sc_sign_block(s2, k2.pk, &b3, sig), SC_OK);
    CHECK_RC(sc_sign_payload_envelope(s2, k2.pk, &e3, sig), SC_ERR_POLICY_FORK);
}

static sc_proposer_preferences prefs(uint64_t slot, uint64_t index, const sc_config *cfg)
{
    sc_proposer_preferences p;
    memset(&p, 0, sizeof p);
    memset(p.dependent_root, 0x77, 32);
    p.proposal_slot = slot;
    p.validator_index = index;
    memcpy(p.fee_recipient, cfg->fee_recipients[1], 20);
    p.target_gas_limit = 45000000;
    return p;
}

static void test_gloas_preferences(void)
{
    host_t h = {0};
    sc_config cfg;
    uint8_t sig[96], root[32], obj[32];
    make_gloas_config(&cfg);
    set_epoch(&h, G - 1); /* the epoch before the fork */
    sc_signer *s = new_signer(&h, &cfg, 8, 4);
    vkeys k = add_validator(s, 44, 1000);
    int writes = h.writes;

    /* validator.md: preferences for the first Gloas epoch, signed before
     * the fork, use the Gloas fork version of the proposal epoch. */
    sc_proposer_preferences p = prefs(G * 32 + 1, 1000, &cfg);
    CHECK_RC(sc_sign_proposer_preferences(s, k.pk, &p, sig), SC_OK);
    sc_htr_proposer_preferences(&p, obj);
    root_with(SC_DOMAIN_PROPOSER_PREFERENCES, V_GLOAS, cfg.genesis_validators_root, obj, root);
    CHECK_RC(sc_bls_verify(k.share_pk, root, 32, sig), SC_OK);
    p = prefs((G - 1) * 32 + 30, 1000, &cfg); /* a pre-Gloas proposal slot */
    CHECK_RC(sc_sign_proposer_preferences(s, k.pk, &p, sig), SC_ERR_POLICY_FORK);
    p = prefs(G * 32 + 1, 999, &cfg);
    CHECK_RC(sc_sign_proposer_preferences(s, k.pk, &p, sig), SC_ERR_POLICY_INDEX);
    p = prefs(G * 32 + 1, 1000, &cfg);
    memset(p.fee_recipient, 0x99, 20);
    CHECK_RC(sc_sign_proposer_preferences(s, k.pk, &p, sig), SC_ERR_POLICY_FEE_RECIPIENT);
    p = prefs(G * 32 + 1, 1000, &cfg);
    p.target_gas_limit = cfg.gas_limit_max + 1;
    CHECK_RC(sc_sign_proposer_preferences(s, k.pk, &p, sig), SC_ERR_POLICY_GAS_LIMIT);
    p = prefs((G + 2) * 32, 1000, &cfg); /* clock epoch G-1, horizon 2 */
    CHECK_RC(sc_sign_proposer_preferences(s, k.pk, &p, sig), SC_ERR_POLICY_FUTURE);
    CHECK(h.writes == writes); /* no slashing state */
}

/* Restart: PTC votes and envelopes start from the stored block bound, with
 * per-validator and per-device marks, and cost no write while a vote of the
 * epoch has raised the device mark. */
static void test_gloas_restart(void)
{
    for (int scope = 0; scope < 2; scope++) {
        host_t h = {0};
        sc_config cfg;
        uint8_t sig[96];
        make_gloas_config(&cfg);
        cfg.mark_scope = scope ? SC_MARKS_PER_DEVICE : SC_MARKS_PER_VALIDATOR;
        cfg.commit_ahead.block_slots = 4;
        set_epoch(&h, G);
        sc_signer *s = new_signer(&h, &cfg, 8, 0);
        vkeys k = add_validator(s, 45, 1000);
        sc_payload_attestation_data d = ptc(G * 32 + 4, 1);

        if (scope) {
            sc_attestation_data a = att(G - 1, G, 1);
            CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig), SC_OK);
        }
        int w0 = h.writes;
        CHECK_RC(sc_sign_payload_attestation(s, k.pk, &d, sig), SC_OK);
        /* Per validator: one write, the block bound to slot + 4. Per device:
         * the vote of this epoch covers it already. */
        CHECK(h.writes == w0 + (scope ? 0 : 1));
        sc_slashing_state st;
        CHECK_RC(sc_signer_get_state(s, k.pk, &st), SC_OK);
        CHECK(st.committed.block_slot >= d.slot);
        CHECK(!(st.ram.flags & SC_WM_HAS_BLOCK) || st.ram.block_slot < d.slot);
        int w1 = h.writes;
        d = ptc(G * 32 + 6, 1); /* within the bound: no write */
        CHECK_RC(sc_sign_payload_attestation(s, k.pk, &d, sig), SC_OK);
        CHECK(h.writes == w1);
        /* A block after a PTC vote of an earlier slot still signs. */
        sc_beacon_block_header b = gblock(G * 32 + 7, 4);
        CHECK_RC(sc_sign_block(s, k.pk, &b, sig), SC_OK);

        /* Restart: the same vote, a repeat in the last run, is refused, and
         * so is any slot up to the stored bound. */
        sc_signer *r = new_signer(&h, &cfg, 8, 0);
        vkeys k2 = add_validator(r, 45, 1000);
        CHECK_RC(sc_signer_get_state(r, k2.pk, &st), SC_OK);
        uint64_t bound = st.committed.block_slot;
        CHECK(bound >= G * 32 + 7);
        CHECK_RC(sc_sign_payload_attestation(r, k2.pk, &d, sig), SC_ERR_EQUIVOCATION);
        d = ptc(bound, 0);
        CHECK_RC(sc_sign_payload_attestation(r, k2.pk, &d, sig), SC_ERR_EQUIVOCATION);
        /* The envelope of the block signed before the restart: refused. */
        sc_payload_envelope e = envelope_for(&b, &cfg, 3);
        CHECK_RC(sc_sign_payload_envelope(r, k2.pk, &e, sig), SC_ERR_POLICY_ENVELOPE);
        /* Above the bound: signs. */
        d = ptc(bound + 1, 0);
        if (bound + 1 < (G + 3) * 32)
            CHECK_RC(sc_sign_payload_attestation(r, k2.pk, &d, sig), SC_OK);
        printf("gloas restart (%s marks): PTC and envelope refused up to block bound %llu, "
               "slot %llu signs\n",
               scope ? "device" : "validator", (unsigned long long)bound,
               (unsigned long long)(bound + 1));
    }
}

/* ---- aggregates and sync committee messages ------------------------------ */

static const uint8_t D_SEL[4] = {0x05, 0, 0, 0};
static const uint8_t D_AGG[4] = {0x06, 0, 0, 0};
static const uint8_t D_SYNC[4] = {0x07, 0, 0, 0};
static const uint8_t D_SYNC_SEL[4] = {0x08, 0, 0, 0};
static const uint8_t D_CONTRIB[4] = {0x09, 0, 0, 0};

static void put64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

/* The validator (account) key's signature over obj, as a selection proof is. */
static void account_sign(uint32_t i, const uint8_t dtype[4], const uint8_t version[4],
                         const uint8_t gvr[32], const uint8_t obj[32], uint8_t sig[96])
{
    uint8_t sk[32], root[32];
    secret_for(i, sk);
    root_with(dtype, version, gvr, obj, root);
    CHECK_RC(sc_bls_sign(sk, root, 32, sig), SC_OK);
}

/* An Electra (or Gloas, same bytes) AggregateAndProof under the mainnet
 * preset with a one-bit aggregation_bits list. Returns its length. */
static size_t aggregate_ssz(uint8_t *out, uint64_t aggregator, uint64_t slot,
                            const uint8_t proof[96])
{
    sc_attestation_data d = att(slot / 32 - 1, slot / 32, 7);
    size_t n = 0;
    d.slot = slot;
    put64(out, aggregator);
    out[8] = 108; out[9] = out[10] = out[11] = 0; /* offset of aggregate */
    memcpy(out + 12, proof, 96);
    n = 108;
    out[n] = 236; out[n + 1] = out[n + 2] = out[n + 3] = 0; /* offset of aggregation_bits */
    sc_ssz_encode_attestation_data(&d, out + n + 4);
    memset(out + n + 4 + 128, 0x77, 96);                     /* aggregate signature */
    memset(out + n + 4 + 128 + 96, 0, 8);                    /* committee_bits */
    out[n + 4 + 128 + 96] = 0x01;
    out[n + 236] = 0x03;                                     /* one bit set, delimiter */
    return n + 237;
}

static size_t contribution_ssz(uint8_t *out, uint64_t aggregator, uint64_t slot, uint64_t sub,
                               const uint8_t proof[96])
{
    put64(out, aggregator);
    put64(out + 8, slot);
    memset(out + 16, 0x3c, 32);
    put64(out + 48, sub);
    memset(out + 56, 0, 16);
    out[56] = 0x05;            /* aggregation_bits, 128 bits */
    memset(out + 72, 0x66, 96); /* contribution signature */
    memcpy(out + 168, proof, 96);
    return 264;
}

static void test_typed(void)
{
    host_t h = {0};
    sc_config cfg;
    uint8_t sig[96], sr[32], root[32], obj[32], proof[96], bad[96], ssz[512], keep[96];
    uint8_t scratch[SC_TYPED_SCRATCH_LEN], unknown[48] = {0xc0};
    const sc_preset *p = &SC_PRESET_MAINNET;
    const uint64_t slot = E * 32 + 9;
    sc_aggregate_info ai;
    sc_contribution_info ci;
    size_t n;

    make_gloas_config(&cfg);
    set_epoch(&h, E);
    sc_signer *s = new_signer(&h, &cfg, 8, 4);
    vkeys k = add_validator(s, 3, 777);
    const uint8_t *gvr = cfg.genesis_validators_root;

    /* Selection proof: the slot's root under DOMAIN_SELECTION_PROOF. */
    CHECK_RC(sc_sign_selection_proof(s, k.pk, slot, sig, sr), SC_OK);
    sc_htr_uint64(slot, obj);
    root_with(D_SEL, V_FULU, gvr, obj, root);
    CHECK(memcmp(root, sr, 32) == 0);
    CHECK_RC(sc_bls_verify(k.share_pk, root, 32, sig), SC_OK);
    CHECK_RC(sc_sign_selection_proof(s, k.pk, (E + 3) * 32, sig, NULL), SC_ERR_POLICY_FUTURE);
    CHECK_RC(sc_sign_selection_proof(s, unknown, slot, sig, NULL), SC_ERR_UNKNOWN_VALIDATOR);

    /* Aggregate and proof (Electra form at a Fulu epoch). */
    account_sign(3, D_SEL, V_FULU, gvr, obj, proof);
    n = aggregate_ssz(ssz, 777, slot, proof);
    CHECK_RC(sc_decode_aggregate_and_proof(ssz, n, SC_AGGREGATE_ELECTRA, p, scratch, &ai), SC_OK);
    CHECK(ai.aggregator_index == 777 && ai.data.slot == slot);
    CHECK_RC(sc_sign_aggregate_and_proof(s, k.pk, ssz, n, SC_AGGREGATE_ELECTRA, p, scratch, sig, sr),
             SC_OK);
    root_with(D_AGG, V_FULU, gvr, ai.object_root, root);
    CHECK(memcmp(root, sr, 32) == 0);
    CHECK_RC(sc_bls_verify(k.share_pk, root, 32, sig), SC_OK);
    memcpy(keep, sig, 96);
    /* The Gloas form before the Gloas fork. */
    CHECK_RC(sc_sign_aggregate_and_proof(s, k.pk, ssz, n, SC_AGGREGATE_GLOAS, p, scratch, sig, NULL),
             SC_ERR_POLICY_FORK);
    /* Another aggregator index than the bound one. */
    n = aggregate_ssz(ssz, 778, slot, proof);
    CHECK_RC(sc_sign_aggregate_and_proof(s, k.pk, ssz, n, SC_AGGREGATE_ELECTRA, p, scratch, sig, NULL),
             SC_ERR_POLICY_INDEX);
    /* A selection proof of another slot, one by the share key, and garbage. */
    sc_htr_uint64(slot + 1, obj);
    account_sign(3, D_SEL, V_FULU, gvr, obj, bad);
    n = aggregate_ssz(ssz, 777, slot, bad);
    CHECK_RC(sc_sign_aggregate_and_proof(s, k.pk, ssz, n, SC_AGGREGATE_ELECTRA, p, scratch, sig, NULL),
             SC_ERR_SELECTION_PROOF);
    sc_htr_uint64(slot, obj);
    account_sign(10003, D_SEL, V_FULU, gvr, obj, bad);
    n = aggregate_ssz(ssz, 777, slot, bad);
    CHECK_RC(sc_sign_aggregate_and_proof(s, k.pk, ssz, n, SC_AGGREGATE_ELECTRA, p, scratch, sig, NULL),
             SC_ERR_SELECTION_PROOF);
    memset(bad, 0xab, 96);
    n = aggregate_ssz(ssz, 777, slot, bad);
    CHECK_RC(sc_sign_aggregate_and_proof(s, k.pk, ssz, n, SC_AGGREGATE_ELECTRA, p, scratch, sig, NULL),
             SC_ERR_SELECTION_PROOF);
    /* Past the clock horizon; truncated; an unknown form. */
    sc_htr_uint64((E + 3) * 32, obj);
    account_sign(3, D_SEL, V_FULU, gvr, obj, bad);
    n = aggregate_ssz(ssz, 777, (E + 3) * 32, bad);
    CHECK_RC(sc_sign_aggregate_and_proof(s, k.pk, ssz, n, SC_AGGREGATE_ELECTRA, p, scratch, sig, NULL),
             SC_ERR_POLICY_FUTURE);
    n = aggregate_ssz(ssz, 777, slot, proof);
    CHECK_RC(sc_sign_aggregate_and_proof(s, k.pk, ssz, n - 1, SC_AGGREGATE_ELECTRA, p, scratch, sig, NULL),
             SC_ERR_DECODE);
    CHECK_RC(sc_sign_aggregate_and_proof(s, k.pk, ssz, n, 3, p, scratch, sig, NULL), SC_ERR_ARG);
    CHECK(memcmp(sig, keep, 96) == 0); /* refusals leave the signature alone */

    /* At the Gloas fork the Gloas form signs (its own root) and Electra's is refused. */
    set_epoch(&h, G);
    {
        const uint64_t gslot = G * 32 + 1;
        sc_htr_uint64(gslot, obj);
        account_sign(3, D_SEL, V_GLOAS, gvr, obj, proof);
        n = aggregate_ssz(ssz, 777, gslot, proof);
        CHECK_RC(sc_sign_aggregate_and_proof(s, k.pk, ssz, n, SC_AGGREGATE_ELECTRA, p, scratch, sig, NULL),
                 SC_ERR_POLICY_FORK);
        CHECK_RC(sc_sign_aggregate_and_proof(s, k.pk, ssz, n, SC_AGGREGATE_GLOAS, p, scratch, sig, sr),
                 SC_OK);
        CHECK_RC(sc_decode_aggregate_and_proof(ssz, n, SC_AGGREGATE_GLOAS, p, scratch, &ai), SC_OK);
        root_with(D_AGG, V_GLOAS, gvr, ai.object_root, root);
        CHECK(memcmp(root, sr, 32) == 0);
        CHECK_RC(sc_bls_verify(k.share_pk, root, 32, sig), SC_OK);
        memcpy(obj, ai.object_root, 32);
        CHECK_RC(sc_decode_aggregate_and_proof(ssz, n, SC_AGGREGATE_ELECTRA, p, scratch, &ai), SC_OK);
        CHECK(memcmp(obj, ai.object_root, 32) != 0); /* same bytes, other root */
    }
    set_epoch(&h, E);

    /* Sync committee message: the block root is the object root. */
    memset(obj, 0x4d, 32);
    CHECK_RC(sc_sign_sync_committee_message(s, k.pk, slot, obj, sig, sr), SC_OK);
    root_with(D_SYNC, V_FULU, gvr, obj, root);
    CHECK(memcmp(root, sr, 32) == 0);
    CHECK_RC(sc_bls_verify(k.share_pk, root, 32, sig), SC_OK);
    CHECK_RC(sc_sign_sync_committee_message(s, k.pk, (E + 3) * 32, obj, sig, NULL),
             SC_ERR_POLICY_FUTURE);

    /* Sync selection proof. */
    CHECK_RC(sc_sign_sync_selection_proof(s, k.pk, slot, 2, p, sig, sr), SC_OK);
    sc_htr_sync_aggregator_selection_data(slot, 2, obj);
    root_with(D_SYNC_SEL, V_FULU, gvr, obj, root);
    CHECK(memcmp(root, sr, 32) == 0);
    CHECK_RC(sc_bls_verify(k.share_pk, root, 32, sig), SC_OK);
    CHECK_RC(sc_sign_sync_selection_proof(s, k.pk, slot, 4, p, sig, NULL), SC_ERR_ARG);

    /* Contribution and proof. */
    account_sign(3, D_SYNC_SEL, V_FULU, gvr, obj, proof);
    CHECK(sc_contribution_and_proof_len(p) == 264);
    n = contribution_ssz(ssz, 777, slot, 2, proof);
    CHECK_RC(sc_decode_contribution_and_proof(ssz, n, p, &ci), SC_OK);
    CHECK(ci.slot == slot && ci.subcommittee_index == 2 && ci.aggregator_index == 777);
    CHECK_RC(sc_sign_contribution_and_proof(s, k.pk, ssz, n, p, sig, sr), SC_OK);
    root_with(D_CONTRIB, V_FULU, gvr, ci.object_root, root);
    CHECK(memcmp(root, sr, 32) == 0);
    CHECK_RC(sc_bls_verify(k.share_pk, root, 32, sig), SC_OK);
    n = contribution_ssz(ssz, 1, slot, 2, proof);
    CHECK_RC(sc_sign_contribution_and_proof(s, k.pk, ssz, n, p, sig, NULL), SC_ERR_POLICY_INDEX);
    n = contribution_ssz(ssz, 777, slot, 3, proof); /* proof is for subcommittee 2 */
    CHECK_RC(sc_sign_contribution_and_proof(s, k.pk, ssz, n, p, sig, NULL), SC_ERR_SELECTION_PROOF);
    n = contribution_ssz(ssz, 777, slot, 4, proof);
    CHECK_RC(sc_sign_contribution_and_proof(s, k.pk, ssz, n, p, sig, NULL), SC_ERR_ARG);
    n = contribution_ssz(ssz, 777, slot, 2, proof);
    CHECK_RC(sc_sign_contribution_and_proof(s, k.pk, ssz, n + 1, p, sig, NULL), SC_ERR_DECODE);
    CHECK_RC(sc_sign_contribution_and_proof(s, k.pk, ssz, n, &SC_PRESET_MINIMAL, sig, NULL),
             SC_ERR_DECODE);

    /* An unbound key (index unknown) skips only the index check. */
    vkeys u = add_validator(s, 4, SC_INDEX_UNKNOWN);
    sc_htr_uint64(slot, obj);
    account_sign(4, D_SEL, V_FULU, gvr, obj, proof);
    n = aggregate_ssz(ssz, 31337, slot, proof);
    CHECK_RC(sc_sign_aggregate_and_proof(s, u.pk, ssz, n, SC_AGGREGATE_ELECTRA, p, scratch, sig, NULL),
             SC_OK);

    CHECK(SC_ERR_SELECTION_PROOF == 25);
    CHECK(strcmp(sc_status_name(SC_ERR_SELECTION_PROOF), "SC_ERR_SELECTION_PROOF") == 0);
}

/* ---- fork schedule updates ---------------------------------------------- */

static const uint8_t V_NEXT[4] = {9, 0, 0, 0};

static sc_schedule schedule_of(const sc_config *c)
{
    sc_schedule n;
    memset(&n, 0, sizeof n);
    memcpy(n.forks, c->forks, sizeof n.forks);
    n.fork_count = c->fork_count;
    n.gloas_scheduled = c->gloas_scheduled;
    n.gloas_fork_epoch = c->gloas_fork_epoch;
    return n;
}

/* Appends a fork; the caller keeps the epochs ascending. */
static void add_fork(sc_schedule *n, uint64_t epoch, const uint8_t v[4])
{
    n->forks[n->fork_count].epoch = epoch;
    memcpy(n->forks[n->fork_count].version, v, 4);
    n->fork_count++;
}

/* Non-zero if s signs an attestation of epoch under fork version v. */
static int signs_with(const sc_signer *s, const sc_config *cfg, uint64_t epoch, const uint8_t v[4])
{
    uint8_t obj[32], got[32], want[32];
    memset(obj, 0x3c, 32);
    sc_signer_signing_root(s, SC_DOMAIN_BEACON_ATTESTER, epoch, obj, got);
    root_with(SC_DOMAIN_BEACON_ATTESTER, v, cfg->genesis_validators_root, obj, want);
    return memcmp(got, want, 32) == 0;
}

/*
 * sc_signer_set_schedule leaves every epoch up to
 * epoch(max(activate_at, now)) + max_epochs_ahead + 1 as it is. make_config
 * has max_epochs_ahead 2, so with the clock in epoch E the first epoch an
 * update may touch is E + 4.
 */
static void test_set_schedule(void)
{
    host_t h = {0};
    sc_config cfg;
    sc_schedule base, cur, n;
    uint8_t sig[96];
    make_config(&cfg);
    base = schedule_of(&cfg);
    set_epoch(&h, E);

    /* At the clock: E + 3 is too soon, also with activate_at in the past;
     * E + 4 passes. The check alone changes nothing. */
    sc_signer *s = new_signer(&h, &cfg, 4, 0);
    vkeys k = add_validator(s, 11, 1000);
    sc_attestation_data a = att(E - 1, E, 1), dbl = att(E - 1, E, 2);
    CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig), SC_OK);
    int writes = h.writes;
    n = base;
    add_fork(&n, E + 3, V_NEXT);
    CHECK_RC(sc_signer_set_schedule(s, &n, 0), SC_ERR_SCHEDULE);
    CHECK_RC(sc_signer_set_schedule(s, &n, h.now - 100 * EPOCH_SECONDS), SC_ERR_SCHEDULE);
    CHECK_RC(sc_signer_check_schedule(s, &n, 0), SC_ERR_SCHEDULE);
    CHECK(signs_with(s, &cfg, E + 3, V_FULU));
    n = base;
    add_fork(&n, E + 4, V_NEXT);
    CHECK_RC(sc_signer_check_schedule(s, &n, 0), SC_OK);
    CHECK(signs_with(s, &cfg, E + 4, V_FULU));
    CHECK_RC(sc_signer_set_schedule(s, &n, 0), SC_OK);
    CHECK(signs_with(s, &cfg, E + 3, V_FULU) && signs_with(s, &cfg, E + 4, V_NEXT));
    cur = n;
    /* A future fork moves later, goes away and comes back. */
    n = cur;
    n.forks[n.fork_count - 1].epoch = E + 6;
    CHECK_RC(sc_signer_set_schedule(s, &n, 0), SC_OK);
    CHECK(signs_with(s, &cfg, E + 5, V_FULU) && signs_with(s, &cfg, E + 6, V_NEXT));
    CHECK_RC(sc_signer_set_schedule(s, &base, 0), SC_OK);
    CHECK(signs_with(s, &cfg, E + 6, V_FULU));
    CHECK_RC(sc_signer_set_schedule(s, &cur, 0), SC_OK);
    /* One epoch later the fork at E + 4 is within reach: it stays. */
    set_epoch(&h, E + 1);
    n = cur;
    n.forks[n.fork_count - 1].epoch = E + 6;
    CHECK_RC(sc_signer_set_schedule(s, &n, 0), SC_ERR_SCHEDULE);
    CHECK_RC(sc_signer_set_schedule(s, &base, 0), SC_ERR_SCHEDULE);
    CHECK(signs_with(s, &cfg, E + 4, V_NEXT));
    /* The rule compares versions, not entries: a second entry that changes
     * no epoch's version passes. */
    n = cur;
    add_fork(&n, E + 4, V_NEXT);
    CHECK_RC(sc_signer_set_schedule(s, &n, 0), SC_OK);
    /* Validators, slashing state and the repeat root stayed; no write. */
    CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig), SC_OK);
    CHECK_RC(sc_sign_attestation(s, k.pk, &dbl, sig), SC_ERR_SLASH_TARGET);
    CHECK(h.writes == writes);

    /* activate_at in epoch E + 10 moves the first allowed epoch to E + 14,
     * and the new schedule may apply at once: until then both agree. */
    set_epoch(&h, E);
    s = new_signer(&h, &cfg, 1, 0);
    uint64_t at = GENESIS_TIME + (E + 10) * EPOCH_SECONDS + 5;
    n = base;
    add_fork(&n, E + 13, V_NEXT);
    CHECK_RC(sc_signer_set_schedule(s, &n, at), SC_ERR_SCHEDULE);
    n = base;
    add_fork(&n, E + 14, V_NEXT);
    CHECK_RC(sc_signer_set_schedule(s, &n, at), SC_OK);
    CHECK(signs_with(s, &cfg, E + 13, V_FULU) && signs_with(s, &cfg, E + 14, V_NEXT));

    /* Forks that started and the chain identity never change. */
    s = new_signer(&h, &cfg, 1, 0);
    n = base;
    n.forks[n.fork_count - 1].version[1] = 1; /* Fulu (epoch 411392) gets another version */
    CHECK_RC(sc_signer_set_schedule(s, &n, 0), SC_ERR_SCHEDULE);
    n = base;
    n.forks[n.fork_count - 1].epoch = E + 10; /* Fulu later */
    CHECK_RC(sc_signer_set_schedule(s, &n, 0), SC_ERR_SCHEDULE);
    n = base;
    n.fork_count--; /* Fulu gone */
    CHECK_RC(sc_signer_set_schedule(s, &n, 0), SC_ERR_SCHEDULE);
    memset(&n, 0, sizeof n);
    add_fork(&n, 0, V_NEXT); /* another version from genesis on */
    for (uint32_t i = 0; i < base.fork_count; i++)
        add_fork(&n, base.forks[i].epoch, base.forks[i].version);
    CHECK_RC(sc_signer_set_schedule(s, &n, 0), SC_ERR_SCHEDULE);
    CHECK(signs_with(s, &cfg, 0, V_GENESIS) && signs_with(s, &cfg, E, V_FULU));
    n = base;
    n.gloas_scheduled = 1; /* Gloas at the Fulu epoch, which started */
    n.gloas_fork_epoch = 411392;
    CHECK_RC(sc_signer_set_schedule(s, &n, 0), SC_ERR_SCHEDULE);

    /* Gloas scheduled ahead, then its state alone decides. */
    vkeys g = add_validator(s, 12, 1001);
    n = base;
    add_fork(&n, E + 6, V_NEXT);
    n.gloas_scheduled = 1;
    n.gloas_fork_epoch = E + 6;
    CHECK_RC(sc_signer_set_schedule(s, &n, 0), SC_OK);
    cur = n;
    set_epoch(&h, E + 3); /* E + 6 is now within reach */
    n.gloas_scheduled = 0;
    CHECK_RC(sc_signer_set_schedule(s, &n, 0), SC_ERR_SCHEDULE);
    set_epoch(&h, E + 6);
    sc_payload_attestation_data d = ptc((E + 6) * 32 + 1, 1);
    CHECK_RC(sc_sign_payload_attestation(s, g.pk, &d, sig), SC_OK);
    d = ptc((E + 5) * 32 + 31, 1);
    CHECK_RC(sc_sign_payload_attestation(s, g.pk, &d, sig), SC_ERR_POLICY_FORK);

    /* Bad input and a failing clock change nothing. */
    set_epoch(&h, E);
    s = new_signer(&h, &cfg, 1, 0);
    n = base;
    add_fork(&n, E + 4, V_NEXT);
    CHECK_RC(sc_signer_set_schedule(NULL, &n, 0), SC_ERR_ARG);
    CHECK_RC(sc_signer_set_schedule(s, NULL, 0), SC_ERR_ARG);
    CHECK_RC(sc_signer_check_schedule(NULL, &n, 0), SC_ERR_ARG);
    h.fail_clock = 1;
    CHECK_RC(sc_signer_set_schedule(s, &n, 0), SC_ERR_CLOCK);
    h.fail_clock = 0;
    CHECK(signs_with(s, &cfg, E + 4, V_FULU));
    n.fork_count = SC_MAX_FORKS + 1;
    CHECK_RC(sc_signer_set_schedule(s, &n, 0), SC_ERR_ARG);
    n = base;
    add_fork(&n, E + 4, V_NEXT);
    n.forks[0].epoch = E + 5; /* not ascending */
    CHECK_RC(sc_signer_set_schedule(s, &n, 0), SC_ERR_ARG);
    n = base;
    add_fork(&n, E + 8, V_NEXT);
    n.gloas_scheduled = 1;
    n.gloas_fork_epoch = E + 9; /* not a fork epoch */
    CHECK_RC(sc_signer_set_schedule(s, &n, 0), SC_ERR_ARG);
    n.gloas_scheduled = 2;
    n.gloas_fork_epoch = E + 8;
    CHECK_RC(sc_signer_set_schedule(s, &n, 0), SC_ERR_ARG);
    CHECK(signs_with(s, &cfg, E + 8, V_FULU));

    /* A far activate_at refuses near changes. With max_epochs_ahead at the
     * top the sums saturate; a wrapping sum would let this update through. */
    n = base;
    add_fork(&n, E + 5, V_NEXT);
    CHECK_RC(sc_signer_set_schedule(s, &n, UINT64_MAX), SC_ERR_SCHEDULE);
    sc_config wide = cfg;
    wide.max_epochs_ahead = UINT64_MAX;
    s = new_signer(&h, &wide, 1, 0);
    CHECK_RC(sc_signer_set_schedule(s, &n, 0), SC_ERR_SCHEDULE);
    CHECK_RC(sc_signer_set_schedule(s, &base, UINT64_MAX), SC_OK); /* no change */

    CHECK(SC_ERR_SCHEDULE == 26);
    CHECK(strcmp(sc_status_name(SC_ERR_SCHEDULE), "SC_ERR_SCHEDULE") == 0);
}

/*
 * Marks count slots and epochs, never the domain, so a fork change cannot
 * lead to a slashing. A host that restarts the signer with another version
 * for an epoch it signed (which sc_signer_set_schedule refuses) gets the
 * same attestation and block refused: their signing roots differ, so they
 * are not exact repeats, and the marks cover their target and slot.
 */
static void test_fork_change_marks(void)
{
    for (int scope = 0; scope < 2; scope++) {
        host_t h = {0};
        sc_config cfg, moved;
        sc_schedule n;
        uint8_t sig[96];
        make_config(&cfg);
        cfg.mark_scope = scope ? SC_MARKS_PER_DEVICE : SC_MARKS_PER_VALIDATOR;
        set_epoch(&h, E);
        sc_signer *s = new_signer(&h, &cfg, 1, 0);
        vkeys k = add_validator(s, 13, 1000);
        sc_attestation_data a = att(E - 1, E, 1);
        sc_beacon_block_header b = blk(E * 32 + 2, 1);
        b.proposer_index = 1000;
        CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig), SC_OK);
        CHECK_RC(sc_sign_block(s, k.pk, &b, sig), SC_OK);
        n = schedule_of(&cfg);
        add_fork(&n, E, V_NEXT);
        CHECK_RC(sc_signer_set_schedule(s, &n, 0), SC_ERR_SCHEDULE);

        moved = cfg;
        moved.forks[moved.fork_count].epoch = E;
        memcpy(moved.forks[moved.fork_count].version, V_NEXT, 4);
        moved.fork_count++;
        sc_signer *s2 = new_signer(&h, &moved, 1, 0);
        add_validator(s2, 13, 1000);
        CHECK(signs_with(s, &cfg, E, V_FULU) && signs_with(s2, &moved, E, V_NEXT));
        /* Per validator the stored source window refuses it first. */
        CHECK_RC(sc_sign_attestation(s2, k.pk, &a, sig),
                 scope ? SC_ERR_SLASH_TARGET : SC_ERR_SLASH_SOURCE);
        CHECK_RC(sc_sign_block(s2, k.pk, &b, sig), SC_ERR_SLASH_BLOCK);
    }
}

/* ---- slot time changes -------------------------------------------------- */

static sc_slot_times slot_times2(uint64_t e1, uint64_t s1, uint64_t e2, uint64_t s2)
{
    sc_slot_times t;
    memset(&t, 0, sizeof t);
    t.changes[0].epoch = e1;
    t.changes[0].seconds_per_slot = s1;
    t.changes[1].epoch = e2;
    t.changes[1].seconds_per_slot = s2;
    t.count = e2 ? 2 : (e1 ? 1 : 0);
    return t;
}

/*
 * Time maps to slots piece by piece (12 s slots in make_config, then 6 s
 * from epoch 10 and 4 s from epoch 20), the clock horizon follows the
 * changes, and sc_signer_set_slot_times leaves every epoch up to
 * epoch(max(activate_at, now)) + max_epochs_ahead + 1 as it is.
 */
static void test_slot_times(void)
{
    host_t h = {0};
    sc_config cfg;
    sc_slot_times t, bad, got;
    uint8_t sig[96];
    make_config(&cfg);
    const uint64_t g = cfg.genesis_time, s10 = g + 320 * 12, s20 = s10 + 320 * 6;

    t = slot_times2(10, 6, 20, 4);
    CHECK_RC(sc_slot_times_check(&cfg, &t), SC_OK);
    CHECK_RC(sc_slot_times_check(&cfg, NULL), SC_OK);
    CHECK(sc_slot_at(&cfg, &t, g - 5) == 0 && sc_slot_at(&cfg, &t, g + 11) == 0 && sc_slot_at(&cfg, &t, g + 12) == 1);
    CHECK(sc_slot_at(&cfg, &t, s10 - 1) == 319 && sc_slot_at(&cfg, &t, s10) == 320 && sc_slot_at(&cfg, &t, s10 + 5) == 320 &&
          sc_slot_at(&cfg, &t, s10 + 6) == 321);
    CHECK(sc_slot_at(&cfg, &t, s20 - 1) == 639 && sc_slot_at(&cfg, &t, s20) == 640 && sc_slot_at(&cfg, &t, s20 + 4) == 641);
    CHECK(sc_epoch_at(&cfg, &t, s20 + 4 * 32) == 21 && sc_epoch_at(&cfg, NULL, s20) == (s20 - g) / EPOCH_SECONDS);
    /* The value rules. */
    bad = slot_times2(0, 6, 0, 0);
    bad.count = 1;
    CHECK_RC(sc_slot_times_check(&cfg, &bad), SC_ERR_ARG); /* epoch 0 */
    bad = slot_times2(10, 6, 10, 4);
    CHECK_RC(sc_slot_times_check(&cfg, &bad), SC_ERR_ARG); /* not ascending */
    bad = slot_times2(10, 6, 20, 6);
    CHECK_RC(sc_slot_times_check(&cfg, &bad), SC_ERR_ARG); /* keeps the slot time */
    bad = slot_times2(10, 12, 0, 0);
    CHECK_RC(sc_slot_times_check(&cfg, &bad), SC_ERR_ARG); /* the genesis slot time */
    bad = slot_times2(10, 0, 0, 0);
    CHECK_RC(sc_slot_times_check(&cfg, &bad), SC_ERR_ARG);
    bad = t;
    bad.count = SC_MAX_SLOT_TIMES + 1;
    CHECK_RC(sc_slot_times_check(&cfg, &bad), SC_ERR_ARG);
    bad = slot_times2(10, 6, UINT64_MAX / 16, 4);
    CHECK_RC(sc_slot_times_check(&cfg, &bad), SC_ERR_ARG); /* the start does not fit */
    bad = slot_times2(10, UINT64_MAX / 16, 0, 0);
    CHECK_RC(sc_slot_times_check(&cfg, &bad), SC_ERR_ARG); /* an epoch's length does not fit */

    /* A signer made with the changes: in epoch 30 under them it signs up to
     * epoch 32; a signer without them is in epoch 18 then. */
    size_t sz = sc_signer_mem_size(4, 0);
    void *mem = malloc(sz);
    sc_host_ops ops = host_ops(&h);
    sc_signer *s = NULL;
    CHECK(mem != NULL);
    if (g_nmem < 64)
        g_mem[g_nmem++] = mem;
    bad = slot_times2(10, 12, 0, 0);
    CHECK_RC(sc_signer_init_ext(mem, sz, 4, 0, &cfg, &bad, &ops, &s), SC_ERR_ARG);
    CHECK_RC(sc_signer_init_ext(mem, sz, 4, 0, &cfg, &t, &ops, &s), SC_OK);
    sc_signer_get_slot_times(s, &got);
    CHECK(got.count == 2 && got.changes[1].epoch == 20 && got.changes[1].seconds_per_slot == 4);
    h.now = s20 + 10 * 4 * 32 + 5;
    vkeys k = add_validator(s, 21, 2000);
    sc_attestation_data a = att(29, 32, 1), far = att(29, 33, 1);
    CHECK_RC(sc_sign_attestation(s, k.pk, &far, sig), SC_ERR_POLICY_FUTURE);
    CHECK_RC(sc_sign_attestation(s, k.pk, &a, sig), SC_OK);
    sc_signer *plain = new_signer(&h, &cfg, 4, 0);
    sc_signer_get_slot_times(plain, &got);
    CHECK(got.count == 0);
    vkeys kp = add_validator(plain, 22, 2001);
    CHECK_RC(sc_sign_attestation(plain, kp.pk, &a, sig), SC_ERR_POLICY_FUTURE);

    /* The rule, with the clock in epoch E (no changes yet): a change at
     * E + 3 is too soon, E + 4 passes; in force from epoch E + 10, E + 14
     * passes and E + 13 does not. */
    set_epoch(&h, E);
    sc_signer *r = new_signer(&h, &cfg, 4, 0);
    t = slot_times2(E + 3, 6, 0, 0);
    CHECK_RC(sc_signer_set_slot_times(r, &t, 0), SC_ERR_SCHEDULE);
    CHECK_RC(sc_signer_check_slot_times(r, &t, h.now - 100 * EPOCH_SECONDS), SC_ERR_SCHEDULE);
    t = slot_times2(E + 4, 6, 0, 0);
    CHECK_RC(sc_signer_check_slot_times(r, &t, 0), SC_OK);
    sc_signer_get_slot_times(r, &got);
    CHECK(got.count == 0); /* the check changes nothing */
    uint64_t later = g + (E + 10) * EPOCH_SECONDS;
    t = slot_times2(E + 13, 6, 0, 0);
    CHECK_RC(sc_signer_check_slot_times(r, &t, later), SC_ERR_SCHEDULE);
    t = slot_times2(E + 14, 6, 0, 0);
    CHECK_RC(sc_signer_check_slot_times(r, &t, later), SC_OK);
    bad = slot_times2(E + 14, 12, 0, 0);
    CHECK_RC(sc_signer_set_slot_times(r, &bad, later), SC_ERR_ARG);
    t = slot_times2(E + 4, 6, 0, 0);
    CHECK_RC(sc_signer_set_slot_times(r, &t, 0), SC_OK);
    sc_signer_get_slot_times(r, &got);
    CHECK(got.count == 1 && got.changes[0].epoch == E + 4);
    /* A later change on top passes; a change that has come within reach
     * stays: one epoch later the change at E + 4 can no longer go. */
    bad = slot_times2(E + 4, 6, E + 8, 4);
    CHECK_RC(sc_signer_check_slot_times(r, &bad, 0), SC_OK);
    set_epoch(&h, E + 1);
    bad = slot_times2(0, 0, 0, 0);
    CHECK_RC(sc_signer_set_slot_times(r, &bad, 0), SC_ERR_SCHEDULE);
    bad = slot_times2(E + 4, 4, 0, 0);
    CHECK_RC(sc_signer_set_slot_times(r, &bad, 0), SC_ERR_SCHEDULE);
    h.fail_clock = 1;
    CHECK_RC(sc_signer_check_slot_times(r, &t, 0), SC_ERR_CLOCK);
    h.fail_clock = 0;
}

/*
 * The fork rule counts epochs under pending slot time changes too. With the
 * clock in epoch E (12 s slots) a fork update in force at the start of epoch
 * E + 20 may touch epoch E + 24 under the plain clock. With 4 s slots
 * pending from E + 4 the clock reaches E + 52 by then, so the first epoch it
 * may touch is E + 56. The other order: with that fork in the signer, a
 * slot time change that brings E + 56 within reach before the fork's
 * effective time fails the same rule, checked as a return to the schedule
 * before the fork.
 */
static void test_schedule_pending_slot_times(void)
{
    host_t h = {0};
    sc_config cfg;
    sc_schedule base, n;
    sc_slot_times pend = slot_times2(E + 4, 4, 0, 0), faster = slot_times2(E + 4, 3, 0, 0);
    sc_slot_times bad = slot_times2(E + 4, 12, 0, 0);
    make_config(&cfg);
    base = schedule_of(&cfg);
    set_epoch(&h, E);
    sc_signer *s = new_signer(&h, &cfg, 4, 0);
    const uint64_t t = cfg.genesis_time + (E + 20) * EPOCH_SECONDS;
    CHECK(sc_epoch_at(&cfg, &pend, t) == E + 52 && sc_epoch_at(&cfg, &faster, t) == E + 68);

    n = base;
    add_fork(&n, E + 30, V_NEXT);
    CHECK_RC(sc_signer_check_schedule(s, &n, t), SC_OK);
    CHECK_RC(sc_signer_check_schedule_under(s, &n, t, &pend, 1), SC_ERR_SCHEDULE);
    CHECK_RC(sc_signer_set_schedule_under(s, &n, t, &pend, 1), SC_ERR_SCHEDULE);
    CHECK(signs_with(s, &cfg, E + 30, V_FULU));
    n = base;
    add_fork(&n, E + 55, V_NEXT);
    CHECK_RC(sc_signer_check_schedule_under(s, &n, t, &pend, 1), SC_ERR_SCHEDULE);
    n = base;
    add_fork(&n, E + 56, V_NEXT);
    CHECK_RC(sc_signer_check_schedule_under(s, &n, t, &bad, 1), SC_ERR_ARG);
    CHECK_RC(sc_signer_check_schedule_under(s, &n, t, NULL, 1), SC_ERR_ARG);
    CHECK_RC(sc_signer_check_schedule_under(s, &n, t, &pend, 1), SC_OK);
    CHECK_RC(sc_signer_set_schedule_under(s, &n, t, &pend, 1), SC_OK);
    CHECK(signs_with(s, &cfg, E + 56, V_NEXT));

    /* The fork at E + 56 is in the signer, in force at t. 4 s slots from
     * E + 4 keep it clear; 3 s slots reach E + 68 by t, so not. */
    CHECK_RC(sc_signer_check_schedule_under(s, &base, t, &pend, 1), SC_OK);
    CHECK_RC(sc_signer_check_schedule_under(s, &base, t, &faster, 1), SC_ERR_SCHEDULE);
    CHECK(signs_with(s, &cfg, E + 56, V_NEXT));
}

/* BuilderRequestAuth: vectors from tools/xcheck-gloas -bra (go-eth2-client
 * v0.30.3): SSZ, hash_tree_root of the data and of the container. */
static void test_builder_auth_go(const char *dir)
{
    static char line[16384], a[8300];
    char kind[8], b[80], c[80];
    static uint8_t in[SC_SSZ_BUILDER_REQUEST_AUTH_MAX_LEN];
    uint8_t want_data[32], want[32], got[32];
    int n = 0, ok = 0;
    char path[1024];
    snprintf(path, sizeof path, "%s/builder_auth_go.txt", dir);
    FILE *f = fopen(path, "r");
    CHECK(f != NULL);
    if (!f)
        return;
    while (fgets(line, sizeof line, f)) {
        sc_builder_request_auth r;
        long len;
        int good = 0;
        if (line[0] == '#' || sscanf(line, "%7s %8299s %79s %79s", kind, a, b, c) != 4 || strcmp(kind, "bra"))
            continue;
        len = parse_hex_any(a, in, sizeof in);
        if (len < 0 || parse_hex(b, want_data, 32) || parse_hex(c, want, 32))
            continue;
        n++;
        if (sc_ssz_decode_builder_request_auth(in, (size_t)len, &r) == SC_OK) {
            good = sc_htr_builder_auth_data(r.data, r.data_len, got) == SC_OK && !memcmp(got, want_data, 32);
            good = good && sc_htr_builder_request_auth(&r, got) == SC_OK && !memcmp(got, want, 32);
        }
        ok += good;
    }
    fclose(f);
    printf("builder_auth_go vectors: BuilderRequestAuth %d/%d match\n", ok, n);
    CHECK(n >= 16);
    CHECK(ok == n);
}

static void test_builder_auth(void)
{
    host_t h = {0};
    sc_config cfg, pol;
    sc_builder_request_auth r;
    uint8_t sig[96], root[32], obj[32], d[32], zero[32] = {0}, ssz[SC_SSZ_BUILDER_REQUEST_AUTH_MAX_LEN];
    static const uint8_t host[] = "builder.example.org"; /* the Web3Signer 26.9.0 example */
    static const uint8_t other[] = "other.example.org";
    static uint8_t big[SC_BUILDER_AUTH_MAX_DATA + 1];

    make_gloas_config(&cfg);
    CHECK_RC(sc_htr_builder_auth_data(host, sizeof host - 1, cfg.builder_auth_roots[0]), SC_OK);
    cfg.builder_auth_root_count = 1;
    set_epoch(&h, G);
    sc_signer *s = new_signer(&h, &cfg, 8, 4);
    vkeys k = add_validator(s, 45, 1001);
    int writes = h.writes;

    /* Signed under DOMAIN_BUILDER_REQUEST_AUTH, genesis fork version, zero root. */
    r.data = host, r.data_len = sizeof host - 1, r.slot = G * 32 + 3;
    CHECK_RC(sc_sign_builder_request_auth(s, k.pk, &r, sig), SC_OK);
    CHECK_RC(sc_htr_builder_request_auth(&r, obj), SC_OK);
    root_with(SC_DOMAIN_BUILDER_REQUEST_AUTH, cfg.genesis_fork_version, zero, obj, root);
    CHECK_RC(sc_bls_verify(k.share_pk, root, 32, sig), SC_OK);
    CHECK_RC(sc_signer_signing_root(s, SC_DOMAIN_BUILDER_REQUEST_AUTH, 12345, obj, d), SC_OK);
    CHECK(!memcmp(d, root, 32)); /* no fork version, no epoch in the domain */
    /* The container root, by hand: a plain Container of two fields,
     * hash(root(data), slot chunk). */
    {
        uint8_t slot[32] = {0}, a[32];
        sc_htr_builder_auth_data(host, sizeof host - 1, d);
        for (int i = 0; i < 8; i++)
            slot[i] = (uint8_t)(r.slot >> (8 * i));
        sha_pair(d, slot, a);
        CHECK(!memcmp(a, obj, 32));
    }

    /* Data not on the list; an empty list refuses everything. */
    r.data = other, r.data_len = sizeof other - 1;
    CHECK_RC(sc_sign_builder_request_auth(s, k.pk, &r, sig), SC_ERR_POLICY_BUILDER_AUTH);
    r.data = host, r.data_len = sizeof host - 2; /* a prefix of the allowed data */
    CHECK_RC(sc_sign_builder_request_auth(s, k.pk, &r, sig), SC_ERR_POLICY_BUILDER_AUTH);
    r.data = host, r.data_len = sizeof host - 1;
    pol = cfg;
    pol.builder_auth_root_count = 0;
    CHECK_RC(sc_signer_set_policy(s, &pol), SC_OK);
    CHECK_RC(sc_sign_builder_request_auth(s, k.pk, &r, sig), SC_ERR_POLICY_BUILDER_AUTH);
    /* A policy update adds both. */
    pol.builder_auth_root_count = 2;
    memcpy(pol.builder_auth_roots[0], cfg.builder_auth_roots[0], 32);
    sc_htr_builder_auth_data(other, sizeof other - 1, pol.builder_auth_roots[1]);
    CHECK_RC(sc_signer_set_policy(s, &pol), SC_OK);
    CHECK_RC(sc_sign_builder_request_auth(s, k.pk, &r, sig), SC_OK);
    r.data = other, r.data_len = sizeof other - 1;
    CHECK_RC(sc_sign_builder_request_auth(s, k.pk, &r, sig), SC_OK);
    pol.builder_auth_root_count = SC_MAX_BUILDER_AUTH_ROOTS + 1;
    CHECK_RC(sc_signer_set_policy(s, &pol), SC_ERR_ARG);
    CHECK_RC(sc_sign_builder_request_auth(s, k.pk, &r, sig), SC_OK); /* unchanged */

    /* Fork gate, clock horizon, unknown key, size. */
    r.data = host, r.data_len = sizeof host - 1;
    r.slot = (G - 1) * 32 + 31;
    CHECK_RC(sc_sign_builder_request_auth(s, k.pk, &r, sig), SC_ERR_POLICY_FORK);
    r.slot = (G + 3) * 32; /* clock epoch G, horizon 2 */
    CHECK_RC(sc_sign_builder_request_auth(s, k.pk, &r, sig), SC_ERR_POLICY_FUTURE);
    r.slot = G * 32;
    {
        uint8_t nopk[48] = {0};
        CHECK_RC(sc_sign_builder_request_auth(s, nopk, &r, sig), SC_ERR_UNKNOWN_VALIDATOR);
    }
    r.data = big, r.data_len = sizeof big;
    CHECK_RC(sc_sign_builder_request_auth(s, k.pk, &r, sig), SC_ERR_DECODE);
    CHECK_RC(sc_htr_builder_auth_data(big, sizeof big, d), SC_ERR_ARG);
    CHECK(h.writes == writes); /* not slashable: no slashing state */

    /* Strict SSZ. */
    memset(ssz, 0, sizeof ssz);
    ssz[0] = 12;
    CHECK_RC(sc_ssz_decode_builder_request_auth(ssz, 12, &r), SC_OK);
    CHECK(r.data_len == 0);
    CHECK_RC(sc_ssz_decode_builder_request_auth(ssz, sizeof ssz, &r), SC_OK);
    CHECK(r.data_len == SC_BUILDER_AUTH_MAX_DATA);
    CHECK_RC(sc_ssz_decode_builder_request_auth(ssz, 11, &r), SC_ERR_DECODE);
    CHECK_RC(sc_ssz_decode_builder_request_auth(big, sizeof big + 0, &r), SC_ERR_DECODE);
    ssz[0] = 13;
    CHECK_RC(sc_ssz_decode_builder_request_auth(ssz, 20, &r), SC_ERR_DECODE);
    ssz[0] = 12, ssz[1] = 1;
    CHECK_RC(sc_ssz_decode_builder_request_auth(ssz, 20, &r), SC_ERR_DECODE);

    /* Empty data: the zero subtree of depth 7 mixed with length 0. */
    {
        uint8_t z[32] = {0}, n0[32] = {0};
        for (int i = 0; i < 7; i++)
            sha_pair(z, z, z);
        sha_pair(z, n0, z);
        CHECK_RC(sc_htr_builder_auth_data(NULL, 0, d), SC_OK);
        CHECK(!memcmp(d, z, 32));
    }
    CHECK(!strcmp(sc_status_name(SC_ERR_POLICY_BUILDER_AUTH), "SC_ERR_POLICY_BUILDER_AUTH"));
    CHECK(SC_ERR_POLICY_BUILDER_AUTH == 27);
}

int main(int argc, char **argv)
{
    const char *data_dir = argc > 1 ? argv[1] : "tests/data";
    printf("memory: sc_signer_mem_size(1000 validators, 64 cache) = %zu bytes, "
           "(10000, 64) = %zu bytes\n",
           sc_signer_mem_size(1000, 64), sc_signer_mem_size(10000, 64));
    test_domains();
    test_registration_go(data_dir);
    test_attestations();
    test_attestation_slot();
    test_sign_root();
    test_blocks();
    test_exits();
    test_registrations();
    test_set_policy();
    test_commit_ahead_writes();
    test_restart();
    test_store_failure();
    test_import();
    test_hash_cache();
    test_table_and_errors();
    test_fork_versions();
    test_repeats_in_run();
    test_repeat_restart();
    test_device_marks();
    test_cover_epoch();
    test_nonfinality_restart(0);
    test_nonfinality_restart(2);
    test_write_counts();
    test_restart_property();
    test_device_restart_property();
    test_gloas_go(data_dir);
    test_gloas_ssz();
    test_gloas_config();
    test_gloas_ptc();
    test_gloas_import();
    test_gloas_sign_root();
    test_gloas_envelope();
    test_gloas_preferences();
    test_builder_auth();
    test_builder_auth_go(data_dir);
    test_gloas_restart();
    test_typed();
    test_set_schedule();
    test_fork_change_marks();
    test_slot_times();
    test_schedule_pending_slot_times();
    bench_cache();
    for (int i = 0; i < g_nmem; i++)
        free(g_mem[i]);
    printf("UNIT ");
    return test_summary("unit");
}
