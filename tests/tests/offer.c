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
offer_nonce_test(void)
{
	u_int8_t	nonce[KYRKA_NONCE_LENGTH];

	memset(nonce, 0xff, sizeof(nonce));
	kyrka_offer_nonce(nonce, sizeof(nonce));

	VERIFY(nonce[KYRKA_NONCE_LENGTH - 1] == 0x01);
}

static void
offer_init_test(void)
{
	struct kyrka_packet	pkt;
	struct kyrka_offer	*op;

	kyrka_random_init();

	op = kyrka_offer_init(&pkt, 0x1234, KYRKA_KEY_OFFER_MAGIC,
	    KYRKA_OFFER_TYPE_KEY);

	VERIFY(op == kyrka_packet_head(&pkt));
	VERIFY(pkt.length == sizeof(*op));
	VERIFY(op->data.type == KYRKA_OFFER_TYPE_KEY);
	VERIFY(be32toh(op->hdr.spi) == 0x1234);
	VERIFY(be64toh(op->hdr.magic) == KYRKA_KEY_OFFER_MAGIC);
}

static void
offer_encrypt_decrypt_roundtrip_test(void)
{
	int			ret;
	struct kyrka_key	key;
	struct kyrka_packet	pkt;
	struct kyrka_offer	*op;

	kyrka_random_init();
	memset(&key, 0x11, sizeof(key));

	op = kyrka_offer_init(&pkt, 0xaabb, KYRKA_KEY_OFFER_MAGIC,
	    KYRKA_OFFER_TYPE_KEY);
	op->data.offer.key.salt = 0xdeadbeef;

	ret = kyrka_offer_encrypt(&key, op);
	VERIFY(ret == 0);

	ret = kyrka_offer_decrypt(&key, op, 10);
	VERIFY(ret == 0);
	VERIFY(op->data.offer.key.salt == 0xdeadbeef);
}

static void
offer_decrypt_bad_key_test(void)
{
	int			ret;
	struct kyrka_offer	*op;
	struct kyrka_packet	pkt;
	struct kyrka_key	key, other;

	kyrka_random_init();
	memset(&key, 0x11, sizeof(key));
	memset(&other, 0x22, sizeof(other));

	op = kyrka_offer_init(&pkt, 0xaabb, KYRKA_KEY_OFFER_MAGIC,
	    KYRKA_OFFER_TYPE_KEY);

	ret = kyrka_offer_encrypt(&key, op);
	VERIFY(ret == 0);

	ret = kyrka_offer_decrypt(&other, op, 10);
	VERIFY(ret == -1);
}

static void
offer_decrypt_tampered_aad_test(void)
{
	int			ret;
	struct kyrka_key	key;
	struct kyrka_packet	pkt;
	struct kyrka_offer	*op;

	kyrka_random_init();
	memset(&key, 0x33, sizeof(key));

	op = kyrka_offer_init(&pkt, 0xaabb, KYRKA_KEY_OFFER_MAGIC,
	    KYRKA_OFFER_TYPE_KEY);

	ret = kyrka_offer_encrypt(&key, op);
	VERIFY(ret == 0);

	op->hdr.spi = htobe32(be32toh(op->hdr.spi) + 1);

	ret = kyrka_offer_decrypt(&key, op, 10);
	VERIFY(ret == -1);
}

static void
offer_decrypt_expired_test(void)
{
	int			ret;
	struct kyrka_key	key;
	struct kyrka_packet	pkt;
	struct kyrka_offer	*op;

	kyrka_random_init();
	memset(&key, 0x44, sizeof(key));

	op = kyrka_offer_init(&pkt, 0xaabb, KYRKA_KEY_OFFER_MAGIC,
	    KYRKA_OFFER_TYPE_KEY);
	op->data.timestamp = htobe64((u_int64_t)0);

	ret = kyrka_offer_encrypt(&key, op);
	VERIFY(ret == 0);

	ret = kyrka_offer_decrypt(&key, op, 10);
	VERIFY(ret == -1);
}

static void
offer_sign_test(void)
{
	int			ret;
	struct kyrka_packet	pkt;
	struct kyrka_offer	*op;
	struct kyrka		*ctx;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	op = kyrka_offer_init(&pkt, 0x01, KYRKA_CATHEDRAL_MAGIC,
	    KYRKA_OFFER_TYPE_INFO);

	ret = kyrka_offer_sign(ctx, op);
	VERIFY(ret == 0);
}

void
test_entry(void)
{
	test_framework_register("offer_nonce_test", offer_nonce_test);
	test_framework_register("offer_init_test", offer_init_test);
	test_framework_register("offer_encrypt_decrypt_roundtrip_test",
	    offer_encrypt_decrypt_roundtrip_test);
	test_framework_register("offer_decrypt_bad_key_test",
	    offer_decrypt_bad_key_test);
	test_framework_register("offer_decrypt_tampered_aad_test",
	    offer_decrypt_tampered_aad_test);
	test_framework_register("offer_decrypt_expired_test",
	    offer_decrypt_expired_test);
	test_framework_register("offer_sign_test", offer_sign_test);

	test_framework_run();
}
