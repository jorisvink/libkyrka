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

#include "framework.h"
#include "libkyrka-int.h"

static void
packet_offsets_test(void)
{
	struct kyrka_packet	pkt;

	pkt.length = 128;

	VERIFY(kyrka_packet_start(&pkt) == (void *)&pkt.data[0]);
	VERIFY(kyrka_packet_head(&pkt) ==
	    (void *)&pkt.data[KYRKA_PACKET_HEAD_OFFSET]);
	VERIFY(kyrka_packet_data(&pkt) ==
	    (void *)&pkt.data[KYRKA_PACKET_DATA_OFFSET]);
	VERIFY(kyrka_packet_tail(&pkt) ==
	    (void *)&pkt.data[KYRKA_PACKET_DATA_OFFSET + pkt.length]);
}

static void
packet_databuf_test(void)
{
	void			*ptr;
	size_t			len;
	struct kyrka		*ctx;
	struct kyrka_packet	pkt;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	ptr = kyrka_packet_databuf(NULL, &pkt, &len);
	VERIFY(ptr == NULL);

	ptr = kyrka_packet_databuf(ctx, NULL, &len);
	VERIFY(ptr == NULL);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);

	ptr = kyrka_packet_databuf(ctx, &pkt, &len);
	VERIFY(ptr != NULL);
	VERIFY(ptr == kyrka_packet_data(&pkt));
	VERIFY(len == KYRKA_PACKET_DATA_LEN);
}

static void
packet_recvbuf_test(void)
{
	void			*ptr;
	size_t			len;
	struct kyrka		*ctx;
	struct kyrka_packet	pkt;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	ptr = kyrka_packet_recvbuf(NULL, &pkt, &len);
	VERIFY(ptr == NULL);

	ptr = kyrka_packet_recvbuf(ctx, NULL, &len);
	VERIFY(ptr == NULL);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);

	ptr = kyrka_packet_recvbuf(ctx, &pkt, &len);
	VERIFY(ptr != NULL);
	VERIFY(ptr == kyrka_packet_head(&pkt));
	VERIFY(len == KYRKA_PACKET_DATA_LEN);

	VERIFY(kyrka_shroud_enable(ctx) == 0);

	ptr = kyrka_packet_recvbuf(ctx, &pkt, &len);
	VERIFY(ptr != NULL);
	VERIFY(ptr == kyrka_packet_start(&pkt));
	VERIFY(len == KYRKA_PACKET_DATA_LEN);
}

static void
packet_sendbuf_test(void)
{
	void			*ptr;
	size_t			len;
	struct kyrka		*ctx;
	struct kyrka_packet	pkt;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	ptr = kyrka_packet_sendbuf(NULL, &pkt, &len);
	VERIFY(ptr == NULL);

	ptr = kyrka_packet_sendbuf(ctx, NULL, &len);
	VERIFY(ptr == NULL);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);

	pkt.length = 42;
	ptr = kyrka_packet_sendbuf(ctx, &pkt, &len);
	VERIFY(ptr != NULL);
	VERIFY(ptr == kyrka_packet_head(&pkt));
	VERIFY(len == pkt.length);

	VERIFY(kyrka_shroud_enable(ctx) == 0);

	pkt.length = 84;
	ptr = kyrka_packet_sendbuf(ctx, &pkt, &len);
	VERIFY(ptr != NULL);
	VERIFY(ptr == kyrka_packet_start(&pkt));
	VERIFY(len == pkt.length);
}

static void
packet_crypto_checklen_test(void)
{
	size_t			min;
	struct kyrka		*ctx;
	struct kyrka_packet	pkt;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	min = sizeof(struct kyrka_proto_hdr) +
	    sizeof(struct kyrka_proto_tail) + KYRKA_TAG_LENGTH;

	pkt.length = min - 1;
	VERIFY(kyrka_packet_crypto_checklen(ctx, &pkt) == -1);

	pkt.length = min;
	VERIFY(kyrka_packet_crypto_checklen(ctx, &pkt) == 0);

	VERIFY(kyrka_shroud_enable(ctx) == 0);
	min += sizeof(struct kyrka_shroud_hdr) + 1;

	pkt.length = min - 1;
	VERIFY(kyrka_packet_crypto_checklen(ctx, &pkt) == -1);

	pkt.length = min;
	VERIFY(kyrka_packet_crypto_checklen(ctx, &pkt) == 0);
}

void
test_entry(void)
{
	test_framework_register("packet_offsets_test", packet_offsets_test);
	test_framework_register("packet_databuf_test", packet_databuf_test);
	test_framework_register("packet_recvbuf_test", packet_recvbuf_test);
	test_framework_register("packet_sendbuf_test", packet_sendbuf_test);
	test_framework_register("packet_crypto_checklen_test",
	    packet_crypto_checklen_test);

	test_framework_run();
}
