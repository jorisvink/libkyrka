/*
 * Copyright (c) 2026 Joris Vink <joris@sanctorum.se>
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

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "framework.h"
#include "libkyrka-int.h"

#define MSG		"hello"

struct bridge {
	struct kyrka	*self;
	struct kyrka	*peer;

	size_t		last_len;
	u_int8_t	last[KYRKA_PACKET_DATA_LEN];
};

static struct bridge	bridge_a;
static struct bridge	bridge_b;

static void
key_noop_send(struct kyrka_packet *pkt, u_int64_t seq, void *udata)
{
}

static void
key_manage_requires_secret_test(void)
{
	int		ret;
	struct kyrka	*ctx;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	ret = kyrka_key_manage(NULL);
	VERIFY(ret == -1);

	ret = kyrka_key_manage(ctx);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_NO_SECRET);
}

static void
key_manage_requires_callback_test(void)
{
	int		ret;
	struct kyrka	*ctx;
	u_int8_t	secret[KYRKA_KEY_LENGTH];

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	memset(secret, 0xaa, sizeof(secret));
	VERIFY(kyrka_secret_load(ctx, secret, sizeof(secret)) == 0);

	ret = kyrka_key_manage(ctx);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_NO_CALLBACK);
}

static void
key_manage_creates_offer_test(void)
{
	int			ret;
	union kyrka_event	evt;
	struct kyrka		*ctx;
	u_int8_t		secret[KYRKA_KEY_LENGTH];

	memset(&evt, 0, sizeof(evt));

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	memset(secret, 0xbb, sizeof(secret));
	VERIFY(kyrka_secret_load(ctx, secret, sizeof(secret)) == 0);
	VERIFY(kyrka_purgatory_ifc(ctx, key_noop_send, NULL) == 0);

	VERIFY(ctx->offer.local.spi == 0);

	ret = kyrka_key_manage(ctx);
	VERIFY(ret == 0);

	VERIFY(ctx->offer.local.spi != 0);
	VERIFY(ctx->offer.flags & KYRKA_OFFER_INCLUDE_KEM_PK);
}

static void
bridge_send(struct kyrka_packet *pkt, u_int64_t seq, void *udata)
{
	struct bridge	*br = udata;

	VERIFY(kyrka_purgatory_input(br->peer, pkt) != -1 ||
	    kyrka_last_error(br->peer) == KYRKA_ERROR_NO_RX_KEY);
}

static void
bridge_plaintext(struct kyrka_packet *pkt, u_int64_t seq, void *udata)
{
	struct bridge	*br = udata;

	VERIFY(pkt->length <= sizeof(br->last));

	memcpy(br->last, kyrka_packet_data(pkt), pkt->length);
	br->last_len = pkt->length;
}

static void
key_exchange_full_handshake_test(void)
{
	int			ret;
	size_t			len;
	struct kyrka_packet	pkt;
	void			*ptr;
	struct kyrka		*a, *b;
	u_int8_t		secret[KYRKA_KEY_LENGTH];

	memset(&bridge_a, 0, sizeof(bridge_a));
	memset(&bridge_b, 0, sizeof(bridge_b));

	a = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(a != NULL);
	b = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(b != NULL);

	bridge_a.self = a;
	bridge_a.peer = b;
	bridge_b.self = b;
	bridge_b.peer = a;

	memset(secret, 0xcc, sizeof(secret));
	VERIFY(kyrka_secret_load(a, secret, sizeof(secret)) == 0);
	VERIFY(kyrka_secret_load(b, secret, sizeof(secret)) == 0);

	VERIFY(kyrka_purgatory_ifc(a, bridge_send, &bridge_a) == 0);
	VERIFY(kyrka_purgatory_ifc(b, bridge_send, &bridge_b) == 0);
	VERIFY(kyrka_heaven_ifc(a, bridge_plaintext, &bridge_a) == 0);
	VERIFY(kyrka_heaven_ifc(b, bridge_plaintext, &bridge_b) == 0);

	VERIFY(kyrka_key_manage(a) == 0);
	VERIFY(a->offer.local.spi != 0);
	VERIFY(a->tx.cipher == NULL);

	VERIFY(kyrka_key_manage(a) == 0);
	VERIFY(b->offer.local.spi != 0);
	VERIFY(b->rx.cipher != NULL);

	VERIFY(kyrka_key_manage(b) == 0);
	VERIFY(a->rx.cipher != NULL);
	VERIFY(a->tx.cipher != NULL);

	VERIFY(b->tx.cipher == NULL);

	VERIFY(kyrka_key_manage(a) == 0);
	VERIFY(b->tx.cipher != NULL);

	VERIFY(a->tx.spi == b->rx.spi);
	VERIFY(a->rx.spi == b->tx.spi);

	ptr = kyrka_packet_databuf(a, &pkt, &len);
	VERIFY(ptr != NULL);
	VERIFY(sizeof(MSG) - 1 <= len);
	memcpy(ptr, MSG, sizeof(MSG) - 1);
	pkt.length = sizeof(MSG) - 1;

	ret = kyrka_heaven_input(a, &pkt);
	VERIFY(ret == 0);

	VERIFY(bridge_b.last_len == sizeof(MSG) - 1);
	VERIFY(memcmp(bridge_b.last, MSG, sizeof(MSG) - 1) == 0);


	ptr = kyrka_packet_databuf(b, &pkt, &len);
	VERIFY(ptr != NULL);
	memcpy(ptr, MSG, sizeof(MSG) - 1);
	pkt.length = sizeof(MSG) - 1;

	ret = kyrka_heaven_input(b, &pkt);
	VERIFY(ret == 0);

	VERIFY(bridge_a.last_len == sizeof(MSG) - 1);
	VERIFY(memcmp(bridge_a.last, MSG, sizeof(MSG) - 1) == 0);
}

void
test_entry(void)
{
	test_framework_register("key_manage_requires_secret_test",
	    key_manage_requires_secret_test);
	test_framework_register("key_manage_requires_callback_test",
	    key_manage_requires_callback_test);
	test_framework_register("key_manage_creates_offer_test",
	    key_manage_creates_offer_test);
	test_framework_register("key_exchange_full_handshake_test",
	    key_exchange_full_handshake_test);

	test_framework_run();
}
