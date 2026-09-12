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

#include <sys/types.h>

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "framework.h"
#include "libkyrka-int.h"

static u_int8_t load_key_expected[32] = {
	0xc1, 0x4f, 0xa8, 0x03, 0x23, 0x52, 0xa4, 0xba, 0x98, 0xe4,
	0xfe, 0x07, 0xc0, 0x68, 0x22, 0xf1, 0xc7, 0x29, 0x7f, 0x33,
	0x55, 0x3e, 0x5e, 0xa8, 0xc0, 0x9c, 0x4b, 0xfe, 0xbb, 0x7e,
	0xd5, 0x02
};

static void
event_callback(struct kyrka *ctx, union kyrka_event *evt, void *udata)
{
}

static void
api_populate_secret_key(struct kyrka *ctx, void *ptr, size_t len)
{
	int		ret;

	ret = kyrka_key_load_from_path(ctx, "test-data/secret.key", ptr, len);
	VERIFY(ret == 0);
}

static void
api_generic_callback(struct kyrka_packet *pkt, u_int64_t seq, void *udata)
{
}

static void
internal_key_load(void)
{
	int			ret;
	struct kyrka		*ctx;
	u_int8_t		loaded[32];

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	api_populate_secret_key(ctx, loaded, sizeof(loaded));
	kyrka_mask(ctx, loaded, sizeof(loaded));
	ret = memcmp(load_key_expected, loaded, sizeof(loaded));
	VERIFY(ret == 0);
}

static void
api_kyrka_ctx_alloc(void)
{
	struct kyrka		*ctx;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);
	kyrka_ctx_free(ctx);

	ctx = kyrka_ctx_alloc(event_callback, NULL);
	VERIFY(ctx != NULL);
	kyrka_ctx_free(ctx);
}

static void
api_kyrka_secret_load_path(void)
{
	int			ret;
	struct kyrka		*ctx;
	u_int8_t		expected[32];

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	ret = kyrka_secret_load_path(NULL, NULL);
	VERIFY(ret == -1);
	VERIFY(!(ctx->flags & KYRKA_FLAG_SECRET_SET));

	ret = kyrka_secret_load_path(ctx, NULL);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);
	VERIFY(!(ctx->flags & KYRKA_FLAG_SECRET_SET));

	ret = kyrka_secret_load_path(ctx, "does_not_exist");
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_SYSTEM);
	VERIFY(errno == ENOENT);
	VERIFY(!(ctx->flags & KYRKA_FLAG_SECRET_SET));

	ret = kyrka_secret_load_path(ctx, "test-data/secret.key");
	VERIFY(ret == 0);
	VERIFY(ctx->flags & KYRKA_FLAG_SECRET_SET);

	api_populate_secret_key(ctx, expected, sizeof(expected));
	kyrka_mask(ctx, expected, sizeof(expected));
	kyrka_mask(ctx, ctx->cfg.secret, sizeof(ctx->cfg.secret));
	ret = memcmp(ctx->cfg.secret, expected, sizeof(expected));
	VERIFY(ret == 0);
}

static void
api_kyrka_secret_load(void)
{
	int			ret;
	struct kyrka		*ctx;
	u_int8_t		expected[32];

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	ret = kyrka_secret_load(NULL, NULL, 0);
	VERIFY(ret == -1);
	VERIFY(!(ctx->flags & KYRKA_FLAG_SECRET_SET));

	ret = kyrka_secret_load(ctx, NULL, 0);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);
	VERIFY(!(ctx->flags & KYRKA_FLAG_SECRET_SET));

	api_populate_secret_key(ctx, expected, sizeof(expected));

	ret = kyrka_secret_load(ctx, expected, 0);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);
	VERIFY(!(ctx->flags & KYRKA_FLAG_SECRET_SET));

	ret = kyrka_secret_load(ctx, expected, sizeof(expected));
	VERIFY(ret == 0);
	VERIFY(ctx->flags & KYRKA_FLAG_SECRET_SET);

	kyrka_mask(ctx, ctx->cfg.secret, sizeof(ctx->cfg.secret));
	ret = memcmp(ctx->cfg.secret, expected, sizeof(expected));
	VERIFY(ret == 0);
}

static void
api_kyrka_cathedral_secret_load(void)
{
	int			ret;
	struct kyrka		*ctx;
	u_int8_t		expected[32];

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	ret = kyrka_cathedral_secret_load(NULL, NULL, 0);
	VERIFY(ret == -1);
	VERIFY(!(ctx->flags & KYRKA_FLAG_CATHEDRAL_SECRET));

	ret = kyrka_cathedral_secret_load(ctx, NULL, 0);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);
	VERIFY(!(ctx->flags & KYRKA_FLAG_CATHEDRAL_SECRET));

	api_populate_secret_key(ctx, expected, sizeof(expected));

	ret = kyrka_cathedral_secret_load(ctx, expected, 0);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);
	VERIFY(!(ctx->flags & KYRKA_FLAG_CATHEDRAL_SECRET));

	ret = kyrka_cathedral_secret_load(ctx, expected, sizeof(expected));
	VERIFY(ret == 0);
	VERIFY(ctx->flags & KYRKA_FLAG_CATHEDRAL_SECRET);

	kyrka_mask(ctx, ctx->cathedral.secret, sizeof(ctx->cathedral.secret));
	ret = memcmp(ctx->cathedral.secret, expected, sizeof(expected));
	VERIFY(ret == 0);
}

static void
api_kyrka_device_kek_load(void)
{
	int			ret;
	struct kyrka		*ctx;
	u_int8_t		expected[32];

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	ret = kyrka_device_kek_load(NULL, NULL, 0);
	VERIFY(ret == -1);
	VERIFY(!(ctx->flags & KYRKA_FLAG_DEVICE_KEK));

	ret = kyrka_device_kek_load(ctx, NULL, 0);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);
	VERIFY(!(ctx->flags & KYRKA_FLAG_DEVICE_KEK));

	api_populate_secret_key(ctx, expected, sizeof(expected));

	ret = kyrka_device_kek_load(ctx, expected, 0);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);
	VERIFY(!(ctx->flags & KYRKA_FLAG_DEVICE_KEK));

	ret = kyrka_device_kek_load(ctx, expected, sizeof(expected));
	VERIFY(ret == 0);
	VERIFY(ctx->flags & KYRKA_FLAG_DEVICE_KEK);

	kyrka_mask(ctx, ctx->cfg.kek, sizeof(ctx->cfg.kek));
	ret = memcmp(ctx->cfg.kek, expected, sizeof(expected));
	VERIFY(ret == 0);
}

static void
api_kyrka_cathedral_cosk_load(void)
{
	int		ret;
	struct kyrka	*ctx;
	u_int8_t	expected[KYRKA_ED25519_SIGN_SECRET_LENGTH];

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	ret = kyrka_cathedral_cosk_load(NULL, NULL, 0);
	VERIFY(ret == -1);
	VERIFY(!(ctx->flags & KYRKA_FLAG_CATHEDRAL_SIGNING_KEY));

	ret = kyrka_cathedral_cosk_load(ctx, NULL, 0);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);
	VERIFY(!(ctx->flags & KYRKA_FLAG_CATHEDRAL_SIGNING_KEY));

	memset(expected, 0x5a, sizeof(expected));

	ret = kyrka_cathedral_cosk_load(ctx, expected, 0);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);
	VERIFY(!(ctx->flags & KYRKA_FLAG_CATHEDRAL_SIGNING_KEY));

	ret = kyrka_cathedral_cosk_load(ctx, expected, sizeof(expected));
	VERIFY(ret == 0);
	VERIFY(ctx->flags & KYRKA_FLAG_CATHEDRAL_SIGNING_KEY);

	kyrka_mask(ctx, ctx->cathedral.sk, sizeof(ctx->cathedral.sk));
	ret = memcmp(ctx->cathedral.sk, expected, sizeof(expected));
	VERIFY(ret == 0);
}

static void
api_kyrka_version(void)
{
	const char	*version;

	version = kyrka_version();
	VERIFY(version != NULL);
	VERIFY(strlen(version) > 0);
}

static void
api_kyrka_last_error_no_context(void)
{
	VERIFY(kyrka_last_error(NULL) == KYRKA_ERROR_NO_CONTEXT);
}

static void
api_kyrka_mtu_size(void)
{
	int		ret;
	struct kyrka	*ctx;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	ret = kyrka_mtu_size(NULL, 1500);
	VERIFY(ret == -1);

	ret = kyrka_mtu_size(ctx, sizeof(struct kyrka_offer) - 1);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);
	VERIFY(ctx->cfg.mtu == 0);

	ret = kyrka_mtu_size(ctx, KYRKA_PACKET_DATA_LEN + 1);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);
	VERIFY(ctx->cfg.mtu == 0);

	ret = kyrka_mtu_size(ctx, sizeof(struct kyrka_offer));
	VERIFY(ret == 0);
	VERIFY(ctx->cfg.mtu == sizeof(struct kyrka_offer));

	ret = kyrka_mtu_size(ctx, KYRKA_PACKET_DATA_LEN);
	VERIFY(ret == 0);
	VERIFY(ctx->cfg.mtu == KYRKA_PACKET_DATA_LEN);
}

static void
api_kyrka_p2p_active(void)
{
	int		ret;
	struct kyrka	*ctx;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	VERIFY(ctx->flags & KYRKA_FLAG_P2P_ACTIVE);

	ret = kyrka_p2p_active(NULL, 1);
	VERIFY(ret == -1);

	ret = kyrka_p2p_active(ctx, 2);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);

	ret = kyrka_p2p_active(ctx, 0);
	VERIFY(ret == 0);
	VERIFY(!(ctx->flags & KYRKA_FLAG_P2P_ACTIVE));

	ret = kyrka_p2p_active(ctx, 1);
	VERIFY(ret == 0);
	VERIFY(ctx->flags & KYRKA_FLAG_P2P_ACTIVE);
}

static void
api_kyrka_shroud_enable(void)
{
	int		ret;
	struct kyrka	*ctx;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	VERIFY(!(ctx->flags & KYRKA_FLAG_USE_SHROUD));

	ret = kyrka_shroud_enable(NULL);
	VERIFY(ret == -1);

	ret = kyrka_shroud_enable(ctx);
	VERIFY(ret == 0);
	VERIFY(ctx->flags & KYRKA_FLAG_USE_SHROUD);
}

static void
api_kyrka_peer_timeout(void)
{
	int		ret;
	struct kyrka	*ctx;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	ret = kyrka_peer_timeout(NULL);
	VERIFY(ret == -1);

	ctx->tx.cipher = kyrka_cipher_setup(ctx->mask, sizeof(ctx->mask));
	VERIFY(ctx->tx.cipher != NULL);
	ctx->rx.cipher = kyrka_cipher_setup(ctx->mask, sizeof(ctx->mask));
	VERIFY(ctx->rx.cipher != NULL);
	ctx->tx.spi = 0x1234;
	ctx->rx.spi = 0x5678;

	ret = kyrka_peer_timeout(ctx);
	VERIFY(ret == 0);

	VERIFY(ctx->tx.cipher == NULL);
	VERIFY(ctx->rx.cipher == NULL);
	VERIFY(ctx->tx.spi == 0);
	VERIFY(ctx->rx.spi == 0);
}

static void
api_kyrka_key_material_copy(void)
{
	int		ret;
	struct kyrka	*src, *dst;
	u_int8_t	kek[KYRKA_KEY_LENGTH];
	u_int8_t	secret[KYRKA_KEY_LENGTH];
	u_int8_t	expected[KYRKA_KEY_LENGTH];
	u_int8_t	cathedral_secret[KYRKA_KEY_LENGTH];

	src = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(src != NULL);
	dst = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(dst != NULL);

	ret = kyrka_key_material_copy(NULL, NULL);
	VERIFY(ret == -1);

	ret = kyrka_key_material_copy(dst, NULL);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(dst) == KYRKA_ERROR_PARAMETER);

	ret = kyrka_key_material_copy(dst, src);
	VERIFY(ret == 0);
	VERIFY(!(dst->flags & KYRKA_FLAG_SECRET_SET));
	VERIFY(!(dst->flags & KYRKA_FLAG_DEVICE_KEK));
	VERIFY(!(dst->flags & KYRKA_FLAG_CATHEDRAL_SECRET));

	memset(secret, 0x11, sizeof(secret));
	memset(kek, 0x22, sizeof(kek));
	memset(cathedral_secret, 0x33, sizeof(cathedral_secret));

	VERIFY(kyrka_secret_load(src, secret, sizeof(secret)) == 0);
	VERIFY(kyrka_device_kek_load(src, kek, sizeof(kek)) == 0);
	VERIFY(kyrka_cathedral_secret_load(src, cathedral_secret,
	    sizeof(cathedral_secret)) == 0);

	ret = kyrka_key_material_copy(dst, src);
	VERIFY(ret == 0);

	VERIFY(dst->flags & KYRKA_FLAG_SECRET_SET);
	VERIFY(dst->flags & KYRKA_FLAG_DEVICE_KEK);
	VERIFY(dst->flags & KYRKA_FLAG_CATHEDRAL_SECRET);

	memcpy(expected, secret, sizeof(expected));
	kyrka_mask(dst, dst->cfg.secret, sizeof(dst->cfg.secret));
	VERIFY(memcmp(dst->cfg.secret, expected, sizeof(expected)) == 0);

	memcpy(expected, kek, sizeof(expected));
	kyrka_mask(dst, dst->cfg.kek, sizeof(dst->cfg.kek));
	VERIFY(memcmp(dst->cfg.kek, expected, sizeof(expected)) == 0);

	memcpy(expected, cathedral_secret, sizeof(expected));
	kyrka_mask(dst, dst->cathedral.secret, sizeof(dst->cathedral.secret));
	VERIFY(memcmp(dst->cathedral.secret, expected, sizeof(expected)) == 0);
}

static void
api_kyrka_heaven_ifc(void)
{
	int		ret;
	u_int8_t	*ptr;
	struct kyrka	*ctx;

	ptr = NULL;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	ret = kyrka_heaven_ifc(NULL, NULL, NULL);
	VERIFY(ret == -1);
	VERIFY(ctx->heaven.send == NULL);
	VERIFY(ctx->heaven.udata == NULL);

	ret = kyrka_heaven_ifc(ctx, NULL, NULL);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);
	VERIFY(ctx->heaven.send == NULL);
	VERIFY(ctx->heaven.udata == NULL);

	ret = kyrka_heaven_ifc(ctx, api_generic_callback, NULL);
	VERIFY(ret == 0);
	VERIFY(ctx->heaven.send == api_generic_callback);
	VERIFY(ctx->heaven.udata == NULL);

	ret = kyrka_heaven_ifc(ctx, api_generic_callback, ptr);
	VERIFY(ret == 0);
	VERIFY(ctx->heaven.send == api_generic_callback);
	VERIFY(ctx->heaven.udata == ptr);
}

static void
api_kyrka_purgatory_ifc(void)
{
	int		ret;
	u_int8_t	*ptr;
	struct kyrka	*ctx;

	ptr = NULL;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	ret = kyrka_purgatory_ifc(NULL, NULL, NULL);
	VERIFY(ret == -1);
	VERIFY(ctx->purgatory.send == NULL);
	VERIFY(ctx->purgatory.udata == NULL);

	ret = kyrka_purgatory_ifc(ctx, NULL, NULL);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);
	VERIFY(ctx->purgatory.send == NULL);
	VERIFY(ctx->purgatory.udata == NULL);

	ret = kyrka_purgatory_ifc(ctx, api_generic_callback, NULL);
	VERIFY(ret == 0);
	VERIFY(ctx->purgatory.send == api_generic_callback);
	VERIFY(ctx->purgatory.udata == NULL);

	ret = kyrka_purgatory_ifc(ctx, api_generic_callback, ptr);
	VERIFY(ret == 0);
	VERIFY(ctx->purgatory.send == api_generic_callback);
	VERIFY(ctx->purgatory.udata == ptr);
}

static void
api_kyrka_heaven_input(void)
{
	int			ret;
	struct kyrka		*ctx;
	struct kyrka_packet	pkt;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	ret = kyrka_heaven_input(NULL, NULL);
	VERIFY(ret == -1);

	ret = kyrka_heaven_input(ctx, NULL);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);

	pkt.length = 0;
	ret = kyrka_heaven_input(ctx, &pkt);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);

	pkt.length = KYRKA_PACKET_DATA_LEN + 1;
	ret = kyrka_heaven_input(ctx, &pkt);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);

	pkt.length = 256;
	ret = kyrka_heaven_input(ctx, &pkt);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_NO_CALLBACK);

	/* This is correct, we need purgatory cb for heaven input to work. */
	ret = kyrka_purgatory_ifc(ctx, api_generic_callback, NULL);
	VERIFY(ret == 0);

	pkt.length = 256;
	ret = kyrka_heaven_input(ctx, &pkt);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_NO_TX_KEY);
}

static void
api_kyrka_purgatory_input(void)
{
	int			ret;
	struct kyrka		*ctx;
	struct kyrka_packet	pkt;

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

	/*
	 * We cannot test as much as for heaven as purgatory input
	 * immediately requires data to be in the right format and
	 * we are only testing the API here.
	 */
}

void
test_entry(void)
{
	test_framework_register("test_internal_key_load", internal_key_load);

	test_framework_register("kyrka_ctx_alloc", api_kyrka_ctx_alloc);

	test_framework_register("kyrka_secret_load", api_kyrka_secret_load);
	test_framework_register("kyrka_secret_load_path",
	    api_kyrka_secret_load_path);

	test_framework_register("kyrka_cathedral_secret_load",
	    api_kyrka_cathedral_secret_load);

	test_framework_register("kyrka_device_kek_load",
	    api_kyrka_device_kek_load);
	test_framework_register("kyrka_cathedral_cosk_load",
	    api_kyrka_cathedral_cosk_load);

	test_framework_register("kyrka_version", api_kyrka_version);
	test_framework_register("kyrka_last_error_no_context",
	    api_kyrka_last_error_no_context);

	test_framework_register("kyrka_mtu_size", api_kyrka_mtu_size);
	test_framework_register("kyrka_p2p_active", api_kyrka_p2p_active);
	test_framework_register("kyrka_shroud_enable", api_kyrka_shroud_enable);
	test_framework_register("kyrka_peer_timeout", api_kyrka_peer_timeout);
	test_framework_register("kyrka_key_material_copy",
	    api_kyrka_key_material_copy);

	test_framework_register("kyrka_heaven_ifc", api_kyrka_heaven_ifc);
	test_framework_register("kyrka_heaven_input", api_kyrka_heaven_input);

	test_framework_register("kyrka_purgatory_ifc",
	    api_kyrka_purgatory_ifc);
	test_framework_register("kyrka_purgatory_input",
	    api_kyrka_purgatory_input);

	test_framework_run();
}
