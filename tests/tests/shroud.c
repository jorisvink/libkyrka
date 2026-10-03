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

static struct kyrka *
shroud_ctx_setup(void)
{
	struct kyrka	*ctx;
	u_int8_t	secret[KYRKA_KEY_LENGTH];

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	VERIFY(kyrka_shroud_enable(ctx) == 0);

	memset(secret, 0x55, sizeof(secret));
	VERIFY(kyrka_secret_load(ctx, secret, sizeof(secret)) == 0);

	VERIFY(kyrka_mtu_size(ctx, KYRKA_PACKET_DATA_LEN) == 0);

	return (ctx);
}

static void
shroud_has_key_test(void)
{
	struct kyrka	*ctx;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	VERIFY(kyrka_shroud_has_key(ctx, KYRKA_SHROUD_PEER_KEY) == 0);

	VERIFY(kyrka_shroud_enable(ctx) == 0);

	VERIFY(kyrka_shroud_has_key(ctx, KYRKA_SHROUD_PEER_KEY) == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_SHROUD_NO_KEYS);

	ctx->shroud.flags |= KYRKA_SHROUD_PEER_KEY;
	VERIFY(kyrka_shroud_has_key(ctx, KYRKA_SHROUD_PEER_KEY) == 0);

	VERIFY(kyrka_shroud_has_key(ctx, KYRKA_SHROUD_CATHEDRAL_KEY) == -1);
	ctx->shroud.flags |= KYRKA_SHROUD_CATHEDRAL_KEY;
	VERIFY(kyrka_shroud_has_key(ctx, KYRKA_SHROUD_CATHEDRAL_KEY) == 0);
}

static void
shroud_kdf_test(void)
{
	struct kyrka	*ctx;
	u_int8_t	peer[KYRKA_KEY_LENGTH];
	u_int8_t	cathedral[KYRKA_KEY_LENGTH];

	ctx = shroud_ctx_setup();

	kyrka_shroud_kdf(ctx, KYRKA_KDF_PURPOSE_SHROUD_PEER);
	memcpy(peer, ctx->shroud.peer, sizeof(peer));

	kyrka_shroud_kdf(ctx, KYRKA_KDF_PURPOSE_SHROUD_CATHEDRAL);
	memcpy(cathedral, ctx->shroud.cathedral, sizeof(cathedral));

	VERIFY(memcmp(peer, cathedral, sizeof(peer)) != 0);
}

static void
shroud_identity_test(void)
{
	struct kyrka	*ctx;
	u_int8_t	id_a[KYRKA_SHROUD_ID_LENGTH];
	u_int8_t	id_b[KYRKA_SHROUD_ID_LENGTH];

	ctx = shroud_ctx_setup();

	kyrka_shroud_base_identity(ctx);
	kyrka_shroud_identity(ctx);
	memcpy(id_a, ctx->shroud.id, sizeof(id_a));

	kyrka_shroud_identity(ctx);
	memcpy(id_b, ctx->shroud.id, sizeof(id_b));

	VERIFY(memcmp(id_a, id_b, sizeof(id_a)) != 0);
}

static void
shroud_base_identity_deterministic_test(void)
{
	struct kyrka	*a, *b;
	u_int8_t	base_a[KYRKA_SHROUD_ID_LENGTH];
	u_int8_t	base_b[KYRKA_SHROUD_ID_LENGTH];

	a = shroud_ctx_setup();
	b = shroud_ctx_setup();

	a->cathedral.flock_src = 10;
	a->cathedral.flock_dst = 20;
	a->cathedral.identity = 0x42;

	b->cathedral.flock_src = 20;
	b->cathedral.flock_dst = 10;
	b->cathedral.identity = 0x42;

	kyrka_shroud_base_identity(a);
	kyrka_shroud_base_identity(b);

	kyrka_mask(a, a->shroud.base, sizeof(a->shroud.base));
	kyrka_mask(b, b->shroud.base, sizeof(b->shroud.base));

	memcpy(base_a, a->shroud.base, sizeof(base_a));
	memcpy(base_b, b->shroud.base, sizeof(base_b));

	VERIFY(memcmp(base_a, base_b, sizeof(base_a)) == 0);
}

static void
shroud_packet_no_mtu_test(void)
{
	struct kyrka		*ctx;
	struct kyrka_packet	pkt;
	u_int8_t		secret[KYRKA_KEY_LENGTH];

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	VERIFY(kyrka_shroud_enable(ctx) == 0);

	memset(secret, 0x66, sizeof(secret));
	VERIFY(kyrka_secret_load(ctx, secret, sizeof(secret)) == 0);

	kyrka_shroud_kdf(ctx, KYRKA_KDF_PURPOSE_SHROUD_PEER);
	ctx->shroud.flags |= KYRKA_SHROUD_PEER_KEY;

	pkt.length = 32;
	pkt.shroud = KYRKA_PACKET_SHROUD_PEER;

	VERIFY(kyrka_shroud_packet(ctx, &pkt) == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_MTU_SIZE);
}

static void
shroud_packet_no_key_test(void)
{
	struct kyrka_packet	pkt;
	struct kyrka		*ctx;

	ctx = shroud_ctx_setup();

	pkt.length = 32;
	pkt.shroud = KYRKA_PACKET_SHROUD_PEER;

	VERIFY(kyrka_shroud_packet(ctx, &pkt) == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_SHROUD_NO_KEYS);
}

static void
shroud_packet_roundtrip_test(void)
{
	struct kyrka_packet	pkt;
	struct kyrka		*ctx;
	u_int8_t		*data;
	u_int8_t		original[64];

	ctx = shroud_ctx_setup();

	kyrka_shroud_kdf(ctx, KYRKA_KDF_PURPOSE_SHROUD_PEER);
	ctx->shroud.flags |= KYRKA_SHROUD_PEER_KEY;

	memset(original, 0x77, sizeof(original));

	data = kyrka_packet_head(&pkt);
	memcpy(data, original, sizeof(original));

	pkt.length = sizeof(original);
	pkt.shroud = KYRKA_PACKET_SHROUD_PEER;

	VERIFY(kyrka_shroud_packet(ctx, &pkt) == 0);
	VERIFY(pkt.length != sizeof(original));

	data = kyrka_packet_head(&pkt);
	VERIFY(memcmp(data, original, sizeof(original)) != 0);

	VERIFY(kyrka_shroud_xor(ctx, &pkt, 1) == 0);
	VERIFY(pkt.length == sizeof(original));

	data = kyrka_packet_head(&pkt);
	VERIFY(memcmp(data, original, sizeof(original)) == 0);
}

static void
shroud_xor_bad_type_test(void)
{
	struct kyrka_packet	pkt;
	struct kyrka		*ctx;

	ctx = shroud_ctx_setup();

	pkt.length = 32;
	pkt.shroud = 0;

	VERIFY(kyrka_shroud_xor(ctx, &pkt, 0) == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_INTERNAL);
}

void
test_entry(void)
{
	test_framework_register("shroud_has_key_test", shroud_has_key_test);
	test_framework_register("shroud_kdf_test", shroud_kdf_test);
	test_framework_register("shroud_identity_test", shroud_identity_test);
	test_framework_register("shroud_base_identity_deterministic_test",
	    shroud_base_identity_deterministic_test);
	test_framework_register("shroud_packet_no_mtu_test",
	    shroud_packet_no_mtu_test);
	test_framework_register("shroud_packet_no_key_test",
	    shroud_packet_no_key_test);
	test_framework_register("shroud_packet_roundtrip_test",
	    shroud_packet_roundtrip_test);
	test_framework_register("shroud_xor_bad_type_test",
	    shroud_xor_bad_type_test);

	test_framework_run();
}
