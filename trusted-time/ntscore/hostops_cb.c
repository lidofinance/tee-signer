/* C side of the cgo binding: the host operations route to Go through
 * these trampolines. ctx carries a cgo.Handle, an integer, never a Go
 * pointer; a UDP socket is a cgo.Handle too. */
#include <stdint.h>
#include <string.h>

#include "nts_core.h"
#include "_cgo_export.h"

static int random_cb(void *ctx, uint8_t *buf, size_t n) { return ntsgoRandom((uintptr_t)ctx, buf, n); }

static int64_t monotonic_cb(void *ctx) { return ntsgoMonotonic((uintptr_t)ctx); }

static int key_exchange_cb(void *ctx, size_t peer, const nts_server *srv, int64_t validity_unix_ns, int64_t timeout_ns, const uint8_t *req,
			   size_t reqlen, uint8_t *resp, size_t respcap, size_t *resplen, uint8_t c2s[NTS_KEY_LEN], uint8_t s2c[NTS_KEY_LEN],
			   int64_t *elapsed_ns)
{
	return ntsgoKeyExchange((uintptr_t)ctx, peer, (nts_server *)srv, validity_unix_ns, timeout_ns, (uint8_t *)req, reqlen, resp, respcap, resplen,
				c2s, s2c, elapsed_ns);
}

static int udp_open_cb(void *ctx, size_t peer, const char *addr, size_t addrlen, int64_t timeout_ns, void **sock)
{
	uintptr_t h = 0;
	int rc = ntsgoUDPOpen((uintptr_t)ctx, peer, (char *)addr, addrlen, timeout_ns, &h);
	*sock = (void *)h;
	return rc;
}

static int udp_send_cb(void *ctx, void *sock, const uint8_t *p, size_t n)
{
	return ntsgoUDPSend((uintptr_t)ctx, (uintptr_t)sock, (uint8_t *)p, n);
}

static int udp_recv_cb(void *ctx, void *sock, uint8_t *buf, size_t cap, size_t *n, int64_t wait_ns)
{
	return ntsgoUDPRecv((uintptr_t)ctx, (uintptr_t)sock, buf, cap, n, wait_ns);
}

static void udp_close_cb(void *ctx, void *sock) { ntsgoUDPClose((uintptr_t)ctx, (uintptr_t)sock); }

void ntsgo_make_ops(nts_host_ops *ops, uintptr_t handle)
{
	memset(ops, 0, sizeof *ops);
	ops->ctx = (void *)handle;
	ops->random = random_cb;
	ops->monotonic = monotonic_cb;
	ops->key_exchange = key_exchange_cb;
	ops->udp_open = udp_open_cb;
	ops->udp_send = udp_send_cb;
	ops->udp_recv = udp_recv_cb;
	ops->udp_close = udp_close_cb;
}
