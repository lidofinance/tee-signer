/* Simulator entry points shared by sim.c (driver) and covfuzz.c (fuzzer). */
#ifndef SIM_H
#define SIM_H

#include <stddef.h>
#include <stdint.h>

/* Refusal and miss reasons for honest duties. */
enum {
    L_DOWN,        /* signer not running or the validator not loaded */
    L_NOTSENT,     /* the host did not route the request to this signer */
    L_CLOCK,       /* trusted clock: failed, or target past clock epoch + max_epochs_ahead */
    L_STORAGE,     /* store or record write failed, record lost to a clone */
    L_RESTART_FIN, /* restart mark or floor, chain finalizing */
    L_RESTART_NF,  /* restart mark or floor, chain not finalizing */
    L_SRC_BACK,    /* source below one this signer signed in this run (reorg) */
    L_TGT_DUP,     /* target or slot at or below one signed in this run */
    L_CRASH,       /* the signer crashed during the call */
    L_OTHER,
    L_N
};

typedef struct {
    uint64_t slots, events, requests, sign_calls, signed_ok, crashes, restarts, rollbacks,
        clones, store_calls;
    uint64_t honest_att, honest_att_signed[4]; /* by number of signers that signed */
    uint64_t val_att_ok, val_att_miss, val_blk_ok, val_blk_miss;
    uint64_t refuse[L_N];   /* honest attestation refusals per signer */
    uint64_t val_miss[L_N]; /* validator-level misses (fewer than 2 of 3) by first cause */
    uint64_t cost[L_N];     /* refused where the EIP-3076 minimal reference signs */
    uint64_t ref_allowed;   /* requests the reference would sign */
    uint64_t excess;        /* signed where the reference refuses */
    uint64_t viol_single, viol_combined, viol_clock;
    uint64_t viol_sched; /* an epoch signed under two fork versions by one signer, or a
                            schedule update the rule should have taken or refused */
    uint64_t sched_set, sched_refused; /* fork schedule updates taken and refused */
    uint64_t writes_hist[6]; /* device-epochs with 0,1,2,3,4-15,16+ storage writes */
    uint64_t writes_max, writes_total, record_writes;
    uint64_t lost_sum, lost_n, lost_max, lost_never; /* epochs refused after a restart */
    /* the mark log (cloud-ext profiles) */
    uint64_t xlog_writes, xlog_start_refused, xlog_lost, xlog_down_slots;
    uint64_t store_rb_refused, store_rb_done, store_replays;
    uint64_t state_wipes; /* restarts with the local store lost (cloud-ext) */
    uint64_t handovers, handover_failed; /* handovers done, refused for a store down */
    int64_t max_ahead_real; /* highest signed epoch minus real epoch */
    uint64_t ta_clock_ahead_max; /* seconds a TA clock ran ahead of real time */
    char first_violation[512];
} sim_metrics;

/* Runs one fuzz input. Returns the number of safety violations (0 = none). */
int sim_run_bytes(const uint8_t *data, size_t len, sim_metrics *out);

/* Cluster size n and signing threshold m (default 3 and 2), for every run
 * after the call. Returns 0, or -1 for n outside 1..7 or m outside 1..n. */
int sim_set_cluster(int n, int m);

/* Coverage feature hook: covfuzz.c defines it, sim.c has a weak no-op. */
void sim_feature(uint32_t f);

#endif
