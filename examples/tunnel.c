/*
 * Copyright (c) 2025 Joris Vink <joris@sanctorum.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * A simple example of how to use libkyrka for direct tunnels without
 * cathedral and with encapsulation turned on.
 *
 * $ cd examples
 * $ dd if=/dev/urandom.c bs=32 count=1 of=secret.key
 * $ gcc -Wall -std=c99 -pedantic -Werror tunnel.c -o tunnel \
 *   -I ../include -L ../host-build/lib -lkyrka -lsodium
 * $ ./tunnel 127.0.0.1:1234 127.0.0.1:4321
 * .. on another terminal ..
 * $ ./tunnel 127.0.0.1:4321 127.0.0.1:1234
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <libkyrka/libkyrka.h>

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define DATA	"Blessed sanctum, save us"

struct tunnel {
	u_int16_t		id;
	int			fd;
	time_t			last;
	KYRKA			*ctx;
};

void		fatal(const char *, ...);

static struct tunnel	*tunnel_setup(void);

static void	tunnel_read(int, KYRKA *);
static void	tunnel_manage(struct tunnel *);
static void	tunnel_address(struct sockaddr_in *, char *);
static void	tunnel_event(KYRKA *, union kyrka_event *, void *);
static void	tunnel_plaintext(const void *, size_t, u_int64_t, void *);
static void	tunnel_ciphertext(const void *, size_t, u_int64_t, void *);

static struct sockaddr_in	peer;
static struct sockaddr_in	local;
static u_int8_t			tek[32];

int
main(int argc, char *argv[])
{
	struct timespec		ts;
	struct pollfd		pfd;
	struct tunnel		*tun;

	if (argc != 3)
		fatal("Usage: tunnel [lip:lport] [rip:rport]");

	memset(tek, 'T', sizeof(tek));
	memset(&peer, 0, sizeof(peer));
	memset(&local, 0, sizeof(local));

	tunnel_address(&local, argv[1]);
	tunnel_address(&peer, argv[2]);

	tun = tunnel_setup();

	pfd.fd = tun->fd;
	pfd.events = POLLIN;

	for (;;) {
		if (poll(&pfd, 1, 1000) == -1) {
			if (errno == EINTR)
				break;
			fatal("poll: %s", strerror(errno));
		}

		(void)clock_gettime(CLOCK_MONOTONIC, &ts);

		if ((ts.tv_sec - tun->last) >= 1) {
			tun->last = ts.tv_sec;
			tunnel_manage(tun);
		}

		if (pfd.revents & POLLIN)
			tunnel_read(pfd.fd, tun->ctx);
	}

	return (0);
}

void
fatal(const char *fmt, ...)
{
	va_list		args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	fprintf(stderr, "\n");

	exit(1);
}

static void
tunnel_read(int fd, KYRKA *ctx)
{
	ssize_t		ret;
	u_int8_t	pkt[1500];

	if ((ret = recv(fd, pkt, sizeof(pkt), MSG_DONTWAIT)) == -1) {
		if (errno == EWOULDBLOCK || errno == EAGAIN)
			return;
		fatal("recv: %s", strerror(errno));
	}

	if (kyrka_purgatory_input(ctx, pkt, ret) == -1 &&
	    kyrka_last_error(ctx) != KYRKA_ERROR_NO_RX_KEY)
		fatal("kyrka_purgatory_input: %d", kyrka_last_error(ctx));
}

static void
tunnel_address(struct sockaddr_in *sin, char *addr)
{
	long		port;
	char		*p, *ep;

	if ((p = strrchr(addr, ':')) == NULL)
		fatal("expected address format is ip:port");

	*(p)++ = '\0';

	if (inet_pton(AF_INET, addr, &sin->sin_addr) == -1)
		fatal("invalid ip %s", addr);

	port = strtol(p, &ep, 10);
	if (port == 0 || *ep != '\0' || p == ep || port > USHRT_MAX)
		fatal("invalid port: %s", p);

	sin->sin_family = AF_INET;
	sin->sin_port = htons(port);
}

static struct tunnel *
tunnel_setup(void)
{
	struct tunnel			*tun;

	if ((tun = calloc(1, sizeof(*tun))) == NULL)
		fatal("calloc");

	if ((tun->fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("socket: %s", strerror(errno));

	if (bind(tun->fd, (const struct sockaddr *)&local, sizeof(local)) == -1)
		fatal("bind: %s", strerror(errno));

	if ((tun->ctx = kyrka_ctx_alloc(tunnel_event, tun)) == NULL)
		fatal("kyrka_ctx_alloc: failed");

	if (kyrka_heaven_ifc(tun->ctx, tunnel_plaintext, tun) == -1)
		fatal("kyrka_heaven_ifc: %d", kyrka_last_error(tun->ctx));

	if (kyrka_purgatory_ifc(tun->ctx, tunnel_ciphertext, tun) == -1)
		fatal("kyrka_purgatory_ifc: %d", kyrka_last_error(tun->ctx));

	if (kyrka_secret_load(tun->ctx, "secret.key") == -1)
		fatal("kyrka_secret_load: %d", kyrka_last_error(tun->ctx));

	if (kyrka_encap_key_load(tun->ctx, tek, sizeof(tek)) == -1)
		fatal("kyrka_encap_key_load: %d", kyrka_last_error(tun->ctx));

	return (tun);
}

static void
tunnel_manage(struct tunnel *tun)
{
	if (kyrka_key_manage(tun->ctx) == -1 &&
	    kyrka_last_error(tun->ctx) != KYRKA_ERROR_NO_SECRET)
		fatal("kyrka_key_manage: %d", kyrka_last_error(tun->ctx));

	if (kyrka_heaven_input(tun->ctx, DATA, sizeof(DATA) - 1) == -1 &&
	    kyrka_last_error(tun->ctx) != KYRKA_ERROR_NO_TX_KEY)
		fatal("kyrka_heaven_input: %d", kyrka_last_error(tun->ctx));
}

static void
tunnel_event(KYRKA *ctx, union kyrka_event *evt, void *udata)
{
	switch (evt->type) {
	case KYRKA_EVENT_KEYS_INFO:
		printf("tx=%08x rx=%08x\n", evt->keys.tx_spi, evt->keys.rx_spi);
		break;
	case KYRKA_EVENT_EXCHANGE_INFO:
		printf("%s\n", evt->exchange.reason);
		break;
	case KYRKA_EVENT_ENCAP_INFO:
		printf("encapsulation spi=%08x\n", evt->encap.spi);
		break;
	default:
		printf("ignoring 0x%02x\n", evt->type);
		break;
	}
}

static void
tunnel_plaintext(const void *data, size_t len, u_int64_t seq, void *udata)
{
	printf("<< %.*s\n", (int)len, (const char *)data);
}

static void
tunnel_ciphertext(const void *data, size_t len, u_int64_t seq, void *udata)
{
	struct tunnel		*tun;

	tun = udata;

	if (sendto(tun->fd, data, len, 0,
	    (const struct sockaddr *)&peer, sizeof(peer)) == -1)
		fatal("sendto: %s", strerror(errno));
}
