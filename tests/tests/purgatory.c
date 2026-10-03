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

static u_int8_t		test_key[KYRKA_KEY_LENGTH];

struct captured {
	u_int64_t	pn;
	size_t		len;
	int		hits;
	u_int8_t	data[KYRKA_PACKET_DATA_LEN];
};

static void
purgatory_install_rx(struct kyrka *ctx, u_int32_t spi, u_int32_t salt)
{
	struct timespec	ts;

	memset(test_key, 0xab, sizeof(test_key));

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);

	ctx->rx.cipher = kyrka_cipher_setup(test_key, sizeof(test_key));
	VERIFY(ctx->rx.cipher != NULL);

	ctx->rx.spi = spi;
	ctx->rx.salt = salt;
	ctx->rx.seqnr = 1;
	ctx->rx.bitmap = 0;
	ctx->rx.pkt = 0;
	ctx->rx.age = ts.tv_sec;
}

static void
purgatory_build_packet(struct kyrka_packet *pkt, u_int32_t spi,
    u_int32_t salt, u_int64_t pn, const void *payload, size_t len,
    u_int8_t reserved, u_int8_t next)
{
	struct kyrka_cipher		c;
	u_int8_t			*ptr;
	struct kyrka_proto_hdr		*hdr;
	struct kyrka_proto_tail		*tail;
	void				*cipher;
	u_int8_t			nonce[KYRKA_NONCE_LENGTH];

	cipher = kyrka_cipher_setup(test_key, sizeof(test_key));
	VERIFY(cipher != NULL);

	hdr = kyrka_packet_head(pkt);
	memset(hdr, 0, sizeof(*hdr));
	hdr->esp.spi = htobe32(spi);
	hdr->esp.seq = htobe32(pn & 0xffffffff);
	hdr->pn = htobe64(pn);

	ptr = kyrka_packet_data(pkt);
	memcpy(ptr, payload, len);

	pkt->length = len;
	tail = kyrka_packet_tail(pkt);
	tail->reserved = reserved;
	tail->next = next;
	pkt->length += sizeof(*tail);

	memcpy(nonce, &salt, sizeof(salt));
	memcpy(&nonce[sizeof(salt)], &hdr->pn, sizeof(hdr->pn));

	c.ctx = cipher;
	c.aad = hdr;
	c.aad_len = sizeof(*hdr);

	c.nonce = nonce;
	c.nonce_len = sizeof(nonce);

	c.pt = ptr;
	c.ct = ptr;

	c.data_len = pkt->length;
	c.tag = ptr + pkt->length;

	VERIFY(kyrka_cipher_encrypt(&c) == 0);
	pkt->length += sizeof(*hdr) + KYRKA_TAG_LENGTH;

	kyrka_cipher_cleanup(cipher);
}

static void
purgatory_heaven_capture(struct kyrka_packet *pkt, u_int64_t pn, void *udata)
{
	struct captured	*cap = udata;

	cap->hits++;
	cap->pn = pn;
	cap->len = pkt->length;
	memcpy(cap->data, kyrka_packet_data(pkt), pkt->length);
}

static void
purgatory_input_param_test(void)
{
	int			ret;
	struct kyrka_packet	pkt;
	struct kyrka		*ctx;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	ret = kyrka_purgatory_input(NULL, NULL);
	VERIFY(ret == -1);

	ret = kyrka_purgatory_input(ctx, NULL);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);

	pkt.length = 0;
	ret = kyrka_purgatory_input(ctx, &pkt);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);

	pkt.length = KYRKA_PACKET_DATA_LEN + 1;
	ret = kyrka_purgatory_input(ctx, &pkt);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);
}

static void
purgatory_input_too_short_test(void)
{
	int			ret;
	struct kyrka_packet	pkt;
	struct kyrka		*ctx;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	pkt.length = sizeof(struct kyrka_proto_hdr) +
	    sizeof(struct kyrka_proto_tail) + KYRKA_TAG_LENGTH - 1;

	ret = kyrka_purgatory_input(ctx, &pkt);
	VERIFY(ret == 0);
}

static void
purgatory_input_zero_spi_test(void)
{
	int				ret;
	struct kyrka_packet		pkt;
	struct kyrka_proto_hdr		*hdr;
	struct kyrka			*ctx;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	pkt.length = sizeof(struct kyrka_proto_hdr) +
	    sizeof(struct kyrka_proto_tail) + KYRKA_TAG_LENGTH;

	hdr = kyrka_packet_head(&pkt);
	memset(hdr, 0, sizeof(*hdr));

	ret = kyrka_purgatory_input(ctx, &pkt);
	VERIFY(ret == 0);
}

static void
purgatory_input_no_callback_test(void)
{
	int				ret;
	struct kyrka_packet		pkt;
	struct kyrka_proto_hdr		*hdr;
	struct kyrka			*ctx;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	pkt.length = sizeof(struct kyrka_proto_hdr) +
	    sizeof(struct kyrka_proto_tail) + KYRKA_TAG_LENGTH;

	hdr = kyrka_packet_head(&pkt);
	memset(hdr, 0, sizeof(*hdr));
	hdr->esp.spi = htobe32(0x1234);
	hdr->esp.seq = htobe32(0x5678);

	ret = kyrka_purgatory_input(ctx, &pkt);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_NO_CALLBACK);
}

static void
purgatory_input_no_rx_key_test(void)
{
	int				ret;
	struct captured			cap;
	struct kyrka_packet		pkt;
	struct kyrka_proto_hdr		*hdr;
	struct kyrka			*ctx;

	memset(&cap, 0, sizeof(cap));

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);
	VERIFY(kyrka_heaven_ifc(ctx, purgatory_heaven_capture, &cap) == 0);

	pkt.length = sizeof(struct kyrka_proto_hdr) +
	    sizeof(struct kyrka_proto_tail) + KYRKA_TAG_LENGTH;

	hdr = kyrka_packet_head(&pkt);
	memset(hdr, 0, sizeof(*hdr));
	hdr->esp.spi = htobe32(0x1234);
	hdr->esp.seq = htobe32(0x5678);

	ret = kyrka_purgatory_input(ctx, &pkt);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_NO_RX_KEY);
	VERIFY(cap.hits == 0);
}

static void
purgatory_input_flock_mismatch_test(void)
{
	int				ret;
	struct captured			cap;
	struct kyrka_packet		pkt;
	struct kyrka			*ctx;

	memset(&cap, 0, sizeof(cap));

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);
	VERIFY(kyrka_heaven_ifc(ctx, purgatory_heaven_capture, &cap) == 0);

	ctx->cathedral.flock_src = 10;
	ctx->cathedral.flock_dst = 20;

	purgatory_install_rx(ctx, 0xaa, 0x11);
	purgatory_build_packet(&pkt, 0xaa, 0x11, 1, MSG, sizeof(MSG) - 1, 0, 0);

	ret = kyrka_purgatory_input(ctx, &pkt);
	VERIFY(ret == 0);
	VERIFY(cap.hits == 0);
}

static void
purgatory_input_spi_mismatch_test(void)
{
	int				ret;
	struct captured			cap;
	struct kyrka_packet		pkt;
	struct kyrka			*ctx;

	memset(&cap, 0, sizeof(cap));

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);
	VERIFY(kyrka_heaven_ifc(ctx, purgatory_heaven_capture, &cap) == 0);

	purgatory_install_rx(ctx, 0xaa, 0x11);
	purgatory_build_packet(&pkt, 0xbb, 0x11, 1, MSG, sizeof(MSG) - 1, 0, 0);

	ret = kyrka_purgatory_input(ctx, &pkt);
	VERIFY(ret == 0);
	VERIFY(cap.hits == 0);
}

static void
purgatory_input_success_test(void)
{
	int				ret;
	struct captured			cap;
	struct kyrka_packet		pkt;
	struct kyrka			*ctx;

	memset(&cap, 0, sizeof(cap));

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);
	VERIFY(kyrka_heaven_ifc(ctx, purgatory_heaven_capture, &cap) == 0);

	purgatory_install_rx(ctx, 0xaa, 0x11);
	purgatory_build_packet(&pkt, 0xaa, 0x11, 1, MSG, sizeof(MSG) - 1, 0, 0);

	ret = kyrka_purgatory_input(ctx, &pkt);
	VERIFY(ret == 0);

	VERIFY(cap.hits == 1);
	VERIFY(cap.pn == 1);
	VERIFY(cap.len == sizeof(MSG) - 1);
	VERIFY(memcmp(cap.data, MSG, sizeof(MSG) - 1) == 0);
	VERIFY(ctx->rx.pkt == 1);
}

static void
purgatory_input_bad_tail_test(void)
{
	int				ret;
	struct captured			cap;
	struct kyrka_packet		pkt;
	struct kyrka			*ctx;

	memset(&cap, 0, sizeof(cap));

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);
	VERIFY(kyrka_heaven_ifc(ctx, purgatory_heaven_capture, &cap) == 0);

	purgatory_install_rx(ctx, 0xaa, 0x11);
	purgatory_build_packet(&pkt, 0xaa, 0x11, 1, MSG, sizeof(MSG) - 1, 1, 0);

	ret = kyrka_purgatory_input(ctx, &pkt);
	VERIFY(ret == 0);
	VERIFY(cap.hits == 0);

	memset(&cap, 0, sizeof(cap));
	purgatory_install_rx(ctx, 0xaa, 0x11);
	purgatory_build_packet(&pkt, 0xaa, 0x11, 1, MSG, sizeof(MSG) - 1, 0, 1);

	ret = kyrka_purgatory_input(ctx, &pkt);
	VERIFY(ret == 0);
	VERIFY(cap.hits == 0);
}

static void
purgatory_input_replay_test(void)
{
	int				ret;
	struct captured			cap;
	struct kyrka_packet		pkt;
	struct kyrka			*ctx;

	memset(&cap, 0, sizeof(cap));

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);
	VERIFY(kyrka_heaven_ifc(ctx, purgatory_heaven_capture, &cap) == 0);

	purgatory_install_rx(ctx, 0xaa, 0x11);
	purgatory_build_packet(&pkt, 0xaa, 0x11, 1, MSG, sizeof(MSG) - 1, 0, 0);

	ret = kyrka_purgatory_input(ctx, &pkt);
	VERIFY(ret == 0);
	VERIFY(cap.hits == 1);

	purgatory_build_packet(&pkt, 0xaa, 0x11, 1, MSG, sizeof(MSG) - 1, 0, 0);
	ret = kyrka_purgatory_input(ctx, &pkt);
	VERIFY(ret == 0);
	VERIFY(cap.hits == 1);
}

static void
purgatory_input_too_old_test(void)
{
	int				ret;
	struct captured			cap;
	struct kyrka_packet		pkt;
	struct kyrka			*ctx;

	memset(&cap, 0, sizeof(cap));

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);
	VERIFY(kyrka_heaven_ifc(ctx, purgatory_heaven_capture, &cap) == 0);

	purgatory_install_rx(ctx, 0xaa, 0x11);

	purgatory_build_packet(&pkt, 0xaa, 0x11, 0, MSG, sizeof(MSG) - 1, 0, 0);

	ret = kyrka_purgatory_input(ctx, &pkt);
	VERIFY(ret == 0);
	VERIFY(cap.hits == 0);
}

void
test_entry(void)
{
	test_framework_register("purgatory_input_param_test",
	    purgatory_input_param_test);
	test_framework_register("purgatory_input_too_short_test",
	    purgatory_input_too_short_test);
	test_framework_register("purgatory_input_zero_spi_test",
	    purgatory_input_zero_spi_test);
	test_framework_register("purgatory_input_no_callback_test",
	    purgatory_input_no_callback_test);
	test_framework_register("purgatory_input_no_rx_key_test",
	    purgatory_input_no_rx_key_test);
	test_framework_register("purgatory_input_flock_mismatch_test",
	    purgatory_input_flock_mismatch_test);
	test_framework_register("purgatory_input_spi_mismatch_test",
	    purgatory_input_spi_mismatch_test);
	test_framework_register("purgatory_input_success_test",
	    purgatory_input_success_test);
	test_framework_register("purgatory_input_bad_tail_test",
	    purgatory_input_bad_tail_test);
	test_framework_register("purgatory_input_replay_test",
	    purgatory_input_replay_test);
	test_framework_register("purgatory_input_too_old_test",
	    purgatory_input_too_old_test);

	test_framework_run();
}
