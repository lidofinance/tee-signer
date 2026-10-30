/* Input format of fuzz/target_signer.c, shared with fuzz/mkseeds.c. */
#ifndef SC_FUZZ_SIGNER_OPS_H
#define SC_FUZZ_SIGNER_OPS_H

/* Header byte 0. */
#define F_DEVICE 0x01     /* SC_MARKS_PER_DEVICE */
#define F_NO_GLOAS 0x04   /* gloas_scheduled = 0 */
#define F_VERIFY 0x08     /* verify attestation and block signatures */
#define F_SLOT_TIMES 0x10 /* slot time changes follow the patches */

/* Header block (HEADER_LEN bytes): flags, patch count (% 6), max validators,
 * hash cache entries, clock offset, patches, [slot times]. Then each
 * operation: opcode, validator, an ARGS_LEN argument block, and any bulk
 * data it reads after the block. */
enum {
    OP_TIME,
    OP_ADD,
    OP_RESTART,
    OP_FAIL,
    OP_PRELOAD_MARK,
    OP_PRELOAD_DEVICE,
    OP_ATTESTATION,    /* kind 1 */
    OP_BLOCK,          /* kind 2 */
    OP_EXIT,           /* kind 3 */
    OP_REGISTRATION,   /* kind 4 */
    OP_ROOT,           /* kind 5 */
    OP_PTC,            /* Gloas kinds */
    OP_ENVELOPE,
    OP_PREFERENCES,
    OP_AGGREGATE,      /* kind 9 */
    OP_CONTRIBUTION,   /* kind 10 */
    OP_SELECTION_PROOF, /* kind 11 */
    OP_SYNC_MESSAGE,   /* kind 12 */
    OP_SYNC_SELECTION, /* kind 13 */
    OP_BUILDER_AUTH,   /* kind 14 */
    OP_RANDAO,
    OP_IMPORT,
    OP_COVER,
    OP_POLICY,
    OP_SCHEDULE,
    OP_SLOT_TIMES,
    OP_QUERY,
    OP_COUNT
};

/* Bytes of the header block and of each operation's argument block. */
#define HEADER_LEN 64
#define ARGS_LEN 48

/* Largest AggregateAndProof the signer target builds or copies. */
#define MAX_AGG_SSZ 17000

#endif
