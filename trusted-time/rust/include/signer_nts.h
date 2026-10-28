/* signer_nts.h: the C ABI of libsigner_nts.a (the Rust crate in nts/).
 *
 * Written by hand. nts/src/lib.rs has the matching exports, and a unit test
 * there (nts/src/tests.rs) checks that this file declares them with the
 * same numbers and struct sizes.
 *
 * The library opens no socket, reads no clock and draws no random numbers.
 * The caller runs TLS (NTS-KE) and UDP (NTP), passes in its monotonic clock
 * readings in nanoseconds, and fills the random octets from a CSPRNG.
 *
 * Rules for every function:
 *   - Input buffers are (pointer, length). A null pointer is allowed only
 *     with length 0.
 *   - Output buffers are (pointer, capacity, *out_len). *out_len gets the
 *     length written, or the length needed with SNTS_E_BUFFER.
 *   - `reason` pointers may be null. When a function returns SNTS_E_KE,
 *     SNTS_E_NTP, SNTS_E_SAMPLE or SNTS_E_QUORUM it writes the reason there:
 *     kind << 16 | value. snts_reason_text() gives the text.
 *   - Handles (snts_assoc, snts_request) are freed with their _free
 *     function, once. A handle is not safe to use from two threads at once;
 *     different handles are.
 *   - No panic crosses into the caller: the library is built with
 *     panic = "abort", so a bug aborts the process. */
#ifndef SIGNER_NTS_H
#define SIGNER_NTS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return codes. */
#define SNTS_OK (0)
#define SNTS_KISS (1)         /* snts_ntp_verify: a Kiss-o'-Death, no time */
#define SNTS_MORE (2)         /* snts_ke_response_length: read more octets */
#define SNTS_E_NULL (-1)      /* a required pointer is null */
#define SNTS_E_BUFFER (-2)    /* output buffer too small; *out_len = needed */
#define SNTS_E_ARG (-3)       /* key length, random length or direction wrong */
#define SNTS_E_KE (-4)        /* NTS-KE response refused; see reason */
#define SNTS_E_NO_COOKIE (-5) /* no cookie left: run NTS-KE again */
#define SNTS_E_NTP (-6)       /* NTP response refused; see reason */
#define SNTS_E_SAMPLE (-7)    /* authentic, but fails an RFC 5905 check; see reason */
#define SNTS_E_QUORUM (-8)    /* no quorum; see reason */

/* Sizes and limits. */
#define SNTS_KEY_LEN 32                /* each exported key, AEAD_AES_SIV_CMAC_256 (RFC 5297 6.1) */
#define SNTS_REQUEST_RANDOM_LEN 56     /* transmit timestamp 8, Unique Identifier 32, nonce 16 */
#define SNTS_KE_MAX_RESPONSE_LEN 65536 /* RFC 8915 section 4 */
#define SNTS_NTP_MAX_REQUEST_LEN 1280
#define SNTS_NTP_MAX_RESPONSE_LEN 2048
#define SNTS_MAX_OPERATOR_LEN 32
#define SNTS_MAX_SERVERS 16
#define SNTS_RHO_PPM 500             /* local clock drift allowed, RFC 5905 MAXFREQ */
#define SNTS_MAX_BOUND_NS 1000000000 /* RFC 5905 MAXDIST, 1 s */
#define SNTS_SAMPLE_SIZE 72
#define SNTS_INTERVAL_SIZE 64
#define SNTS_QUORUM_RESULT_SIZE 32

typedef struct snts_assoc snts_assoc;     /* keys and cookies of one NTS-KE session */
typedef struct snts_request snts_request; /* one NTP request waiting for its answer */

/* One measurement. Times are nanoseconds. "local" means the caller's
 * monotonic clock; offset_ns is real Unix time minus that clock. */
typedef struct {
  int64_t offset_ns;   /* ((T2 - T1) + (T3 - T4)) / 2 */
  int64_t delay_ns;    /* (T4 - T1) - (T3 - T2) */
  int64_t bound_ns;    /* delay/2 + rootdelay/2 + rootdisp + 2^precision + rho (T4 - T1) */
  int64_t t4_local_ns; /* when the bound holds */
  int64_t root_delay_ns;
  int64_t root_dispersion_ns;
  uint32_t cookies_received; /* new cookies in this response */
  uint32_t cookies_held;     /* cookies in the association now */
  int32_t precision;         /* log2 seconds */
  uint8_t stratum;
  uint8_t leap;    /* 0, 1 or 2 */
  uint8_t kiss[4]; /* SNTS_KISS: the kiss code, e.g. "RATE" */
} snts_sample;

/* One server's interval for the quorum. The label is inline, so an array
 * of these holds no pointers. */
typedef struct {
  uint8_t operator_label[SNTS_MAX_OPERATOR_LEN]; /* who runs the server */
  uint32_t operator_len;                         /* 1 to 32 */
  int64_t offset_ns;
  int64_t bound_ns;
  int64_t t4_local_ns;
} snts_interval;

typedef struct {
  int64_t offset_ns; /* midpoint of [lo, hi] */
  int64_t bound_ns;  /* half of hi - lo, rounded up */
  int64_t lo_ns;
  int64_t hi_ns;
} snts_quorum_result;

/* The name and version of the library, for example "signer-nts 0.0.3".
 * NUL-terminated, valid for the life of the program. Do not free it. */
const char *snts_version(void);

/* Runs the AES-SIV-CMAC-256 test vector of RFC 5297 appendix A.1: encrypt,
 * decrypt, and a tampered ciphertext that must be refused.
 * Returns 0 if all of it matches, else the step that failed:
 *   1 encrypt failed
 *   2 the ciphertext differs from the RFC
 *   3 decrypt failed
 *   4 the plaintext differs from the RFC
 *   5 a tampered ciphertext was accepted */
int snts_aes_siv_selftest(void);

/* A static text for a return code and its reason. Never null. */
const char *snts_reason_text(int code, uint32_t reason);

/* NTS-KE (RFC 8915 section 4). The TLS 1.3 session is the caller's. */

/* "ntske/1", the ALPN protocol ID. Static. */
const char *snts_ke_alpn(void);
/* "EXPORTER-network-time-security", the TLS exporter label (5.1). Static. */
const char *snts_ke_exporter_label(void);
/* The 5-octet exporter context (5.1): direction 0 for the C2S key, 1 for
 * the S2C key. Export SNTS_KEY_LEN octets with it. */
int snts_ke_exporter_context(int direction, uint8_t *out, size_t cap, size_t *out_len);
/* The 16-octet request: NTPv4, AEAD_AES_SIV_CMAC_256, End of Message. */
int snts_ke_request(uint8_t *out, size_t cap, size_t *out_len);
/* SNTS_OK and *out_len once buf holds a whole response (up to End of
 * Message), SNTS_MORE if more octets are needed, SNTS_E_KE if the framing
 * or a cap is broken. */
int snts_ke_response_length(const uint8_t *buf, size_t len, size_t *out_len, uint32_t *reason);

/* Checks a whole NTS-KE response and makes an association from it and the
 * two exported keys (each SNTS_KEY_LEN). The caller wipes its copies of the
 * keys. SNTS_E_ARG for a wrong key length, SNTS_E_KE for a refused response. */
int snts_assoc_new(const uint8_t *response, size_t response_len, const uint8_t *c2s, size_t c2s_len,
                   const uint8_t *s2c, size_t s2c_len, snts_assoc **out, uint32_t *reason);
/* Frees the association and wipes its keys and cookies. Null is fine. */
void snts_assoc_free(snts_assoc *a);
/* Cookies held (at most 8). 0 for null. */
size_t snts_assoc_cookies(const snts_assoc *a);
/* The NTP port: the negotiated one, else 123. 0 for null. */
uint16_t snts_assoc_port(const snts_assoc *a);
/* The NTP server the KE server named (4.1.7), no NUL; *out_len 0 if none:
 * then use the KE server's address. */
int snts_assoc_server(const snts_assoc *a, uint8_t *out, size_t cap, size_t *out_len);

/* NTP with NTS (RFC 8915 section 5). */

/* Builds a request with the oldest cookie, which leaves the association
 * (each cookie is sent once, 5.7), and enough placeholders to hold 8
 * cookies after the answer. `random` is SNTS_REQUEST_RANDOM_LEN octets from
 * a CSPRNG. SNTS_E_BUFFER (cookie kept) if cap is short; at most
 * SNTS_NTP_MAX_REQUEST_LEN is needed. SNTS_E_NO_COOKIE when none is left.
 * On SNTS_OK, *req is a new handle for the answer. */
int snts_ntp_request(snts_assoc *a, const uint8_t *random, size_t random_len, uint8_t *out, size_t cap,
                     size_t *out_len, snts_request **req);
/* Frees a request. Null is fine. */
void snts_request_free(snts_request *r);
/* Checks a response to r with the association's S2C key, keeps the new
 * cookies, and measures it (t1/t4: the caller's monotonic clock just before
 * sending and just after receiving; pivot: any Unix time within 68 years,
 * it picks the NTP era). SNTS_OK: *out is a sample. SNTS_KISS: *out.kiss
 * has the code. SNTS_E_NTP: refused, r stays open for the real answer.
 * SNTS_E_SAMPLE: authentic but refused by an RFC 5905 check (the cookies
 * are kept). After SNTS_OK or SNTS_KISS, r refuses further responses. */
int snts_ntp_verify(snts_assoc *a, snts_request *r, const uint8_t *packet, size_t packet_len,
                    int64_t t1_local_ns, int64_t t4_local_ns, int64_t pivot_unix_ns, snts_sample *out,
                    uint32_t *reason);

/* Combines 3 to 16 intervals from distinct operators, one of which may be
 * wrong, at the caller's monotonic time now_local_ns. Each bound first grows
 * by SNTS_RHO_PPM of its age. [lo, hi] spans the points that at least n - 1
 * intervals cover (RFC 5905 11.2.1, Marzullo); SNTS_E_QUORUM if no point
 * does. */
int snts_quorum(const snts_interval *intervals, size_t n, int64_t now_local_ns, snts_quorum_result *out,
                uint32_t *reason);

#ifdef __cplusplus
}
#endif

#endif /* SIGNER_NTS_H */
