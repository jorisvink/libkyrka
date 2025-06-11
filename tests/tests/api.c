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
api_kyrka_ctx_alloc(void)
{
	struct kyrka		*ctx;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);
	kyrka_ctx_free(ctx);

	ctx = kyrka_ctx_alloc(event_callback, NULL);
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

void
test_entry(void)
{
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

	test_framework_run();
}
