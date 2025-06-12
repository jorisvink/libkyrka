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
api_generic_callback(const void *data, size_t len, u_int64_t seq, void *udata)
{
}

static void
internal_key_load(void)
{
	int			ret;
	struct kyrka		*ctx;
	u_int8_t		loaded[32];
	u_int8_t		expected[32] = {
		0xc1, 0x4f, 0xa8, 0x03, 0x23, 0x52, 0xa4, 0xba, 0x98, 0xe4,
		0xfe, 0x07, 0xc0, 0x68, 0x22, 0xf1, 0xc7, 0x29, 0x7f, 0x33,
		0x55, 0x3e, 0x5e, 0xa8, 0xc0, 0x9c, 0x4b, 0xfe, 0xbb, 0x7e,
		0xd5, 0x02
	};


	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	api_populate_secret_key(ctx, loaded, sizeof(loaded));
	ret = memcmp(expected, loaded, sizeof(loaded));
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

	ret = memcmp(ctx->cfg.kek, expected, sizeof(expected));
	VERIFY(ret == 0);
}

static void
api_kyrka_encap_key_load(void)
{
	int			ret;
	struct kyrka		*ctx;
	u_int8_t		expected[32];

	kyrka_random_init();

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	ret = kyrka_encap_key_load(NULL, NULL, 0);
	VERIFY(ret == -1);
	VERIFY(!(ctx->flags & KYRKA_FLAG_ENCAPSULATION));

	ret = kyrka_encap_key_load(ctx, NULL, 0);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);
	VERIFY(!(ctx->flags & KYRKA_FLAG_ENCAPSULATION));

	api_populate_secret_key(ctx, expected, sizeof(expected));

	ret = kyrka_encap_key_load(ctx, expected, 0);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);
	VERIFY(!(ctx->flags & KYRKA_FLAG_ENCAPSULATION));

	ret = kyrka_encap_key_load(ctx, expected, sizeof(expected));
	VERIFY(ret == 0);
	VERIFY(ctx->flags & KYRKA_FLAG_ENCAPSULATION);

	ret = memcmp(ctx->encap.tek, expected, sizeof(expected));
	VERIFY(ret == 0);
}

static void
api_kyrka_heaven_ifc(void)
{
	int			ret;
	struct kyrka		*ctx;
	u_int8_t		*ptr;

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
	int			ret;
	struct kyrka		*ctx;
	u_int8_t		*ptr;

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
	u_int8_t		data[256];

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	ret = kyrka_heaven_input(NULL, NULL, 0);
	VERIFY(ret == -1);

	ret = kyrka_heaven_input(ctx, NULL, 0);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);

	ret = kyrka_heaven_input(ctx, data, 0);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);

	ret = kyrka_heaven_input(ctx, data, UINT_MAX);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);

	ret = kyrka_heaven_input(ctx, data, sizeof(data));
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_NO_CALLBACK);

	/* This is correct, we need purgatory cb for heaven input to work. */
	ret = kyrka_purgatory_ifc(ctx, api_generic_callback, NULL);
	VERIFY(ret == 0);

	ret = kyrka_heaven_input(ctx, data, sizeof(data));
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_NO_TX_KEY);
}

static void
api_kyrka_purgatory_input(void)
{
	int			ret;
	struct kyrka		*ctx;
	u_int8_t		data[256];

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	ret = kyrka_purgatory_input(NULL, NULL, 0);
	VERIFY(ret == -1);

	ret = kyrka_purgatory_input(ctx, NULL, 0);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);

	ret = kyrka_purgatory_input(ctx, data, 0);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);

	ret = kyrka_purgatory_input(ctx, data, UINT_MAX);
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

	test_framework_register("kyrka_encap_key_load",
	    api_kyrka_encap_key_load);

	test_framework_register("kyrka_heaven_ifc", api_kyrka_heaven_ifc);
	test_framework_register("kyrka_heaven_input", api_kyrka_heaven_input);

	test_framework_register("kyrka_purgatory_ifc",
	    api_kyrka_purgatory_ifc);
	test_framework_register("kyrka_purgatory_input",
	    api_kyrka_purgatory_input);

	test_framework_run();
}
