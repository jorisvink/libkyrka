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
#include <time.h>

#include "framework.h"
#include "libkyrka-int.h"

#define MSG		"hello"

struct captured {
	int		hits;
	u_int64_t	seq;
};

static void
heaven_purgatory_capture(struct kyrka_packet *pkt, u_int64_t seq, void *udata)
{
	struct captured	*cap = udata;

	cap->hits++;
	cap->seq = seq;
}

static void
heaven_install_tx(struct kyrka *ctx, u_int32_t spi)
{
	struct timespec		ts;
	u_int8_t		key[KYRKA_KEY_LENGTH];

	memset(key, 0xcd, sizeof(key));
	(void)clock_gettime(CLOCK_MONOTONIC, &ts);

	ctx->tx.cipher = kyrka_cipher_setup(key, sizeof(key));
	VERIFY(ctx->tx.cipher != NULL);

	ctx->tx.spi = spi;
	ctx->tx.salt = 0x01020304;
	ctx->tx.seqnr = 1;
	ctx->tx.pkt = 0;
	ctx->tx.age = ts.tv_sec;
}

static void
heaven_input_success_test(void)
{
	int			ret;
	struct captured		cap;
	struct kyrka_packet	pkt;
	struct kyrka		*ctx;
	void			*ptr;

	memset(&cap, 0, sizeof(cap));

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);
	VERIFY(kyrka_purgatory_ifc(ctx, heaven_purgatory_capture, &cap) == 0);

	heaven_install_tx(ctx, 0x42);

	ptr = kyrka_packet_data(&pkt);
	memcpy(ptr, MSG, sizeof(MSG) - 1);
	pkt.length = sizeof(MSG) - 1;

	ret = kyrka_heaven_input(ctx, &pkt);
	VERIFY(ret == 0);

	VERIFY(cap.hits == 1);
	VERIFY(cap.seq == 1);
	VERIFY(ctx->tx.seqnr == 2);
}

static void
heaven_input_shroud_requires_key_test(void)
{
	int			ret;
	struct kyrka_packet	pkt;
	void			*ptr;
	struct kyrka		*ctx;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);
	VERIFY(kyrka_purgatory_ifc(ctx, heaven_purgatory_capture, NULL) == 0);
	VERIFY(kyrka_shroud_enable(ctx) == 0);

	heaven_install_tx(ctx, 0x42);

	ptr = kyrka_packet_data(&pkt);
	memcpy(ptr, MSG, sizeof(MSG) - 1);
	pkt.length = sizeof(MSG) - 1;

	ret = kyrka_heaven_input(ctx, &pkt);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_SHROUD_NO_KEYS);
}

static void
heaven_input_mtu_size_test(void)
{
	int			ret;
	struct kyrka_packet	pkt;
	struct kyrka		*ctx;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);
	VERIFY(kyrka_purgatory_ifc(ctx, heaven_purgatory_capture, NULL) == 0);

	heaven_install_tx(ctx, 0x42);

	pkt.length = KYRKA_PACKET_DATA_LEN;

	ret = kyrka_heaven_input(ctx, &pkt);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_MTU_SIZE);
}

static void
heaven_input_sa_packet_hard_expiry_test(void)
{
	int			ret;
	struct kyrka_packet	pkt;
	void			*ptr;
	struct kyrka		*ctx;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);
	VERIFY(kyrka_purgatory_ifc(ctx, heaven_purgatory_capture, NULL) == 0);

	heaven_install_tx(ctx, 0x42);
	ctx->tx.seqnr = KYRKA_SA_PACKET_HARD;

	ptr = kyrka_packet_data(&pkt);
	memcpy(ptr, MSG, sizeof(MSG) - 1);
	pkt.length = sizeof(MSG) - 1;

	ret = kyrka_heaven_input(ctx, &pkt);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_NO_TX_KEY);
	VERIFY(ctx->tx.cipher == NULL);
}

static void
heaven_input_sa_age_hard_expiry_test(void)
{
	int			ret;
	struct kyrka_packet	pkt;
	void			*ptr;
	struct kyrka		*ctx;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);
	VERIFY(kyrka_purgatory_ifc(ctx, heaven_purgatory_capture, NULL) == 0);

	heaven_install_tx(ctx, 0x42);
	ctx->tx.age -= (KYRKA_SA_LIFETIME_HARD + 1);

	ptr = kyrka_packet_data(&pkt);
	memcpy(ptr, MSG, sizeof(MSG) - 1);
	pkt.length = sizeof(MSG) - 1;

	ret = kyrka_heaven_input(ctx, &pkt);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_NO_TX_KEY);
	VERIFY(ctx->tx.cipher == NULL);
}

void
test_entry(void)
{
	test_framework_register("heaven_input_success_test",
	    heaven_input_success_test);
	test_framework_register("heaven_input_shroud_requires_key_test",
	    heaven_input_shroud_requires_key_test);
	test_framework_register("heaven_input_mtu_size_test",
	    heaven_input_mtu_size_test);
	test_framework_register("heaven_input_sa_packet_hard_expiry_test",
	    heaven_input_sa_packet_hard_expiry_test);
	test_framework_register("heaven_input_sa_age_hard_expiry_test",
	    heaven_input_sa_age_hard_expiry_test);

	test_framework_run();
}
