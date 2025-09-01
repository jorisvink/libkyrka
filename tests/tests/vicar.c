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

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "framework.h"
#include "libkyrka-int.h"

static u_int8_t expected_kek[32] = {
	0xba, 0xdc, 0x0f, 0xfe, 0xba, 0xdc, 0x0f, 0xfe,
	0xba, 0xdc, 0x0f, 0xfe, 0xba, 0xdc, 0x0f, 0xfe,
	0xba, 0xdc, 0x0f, 0xfe, 0xba, 0xdc, 0x0f, 0xfe,
	0xba, 0xdc, 0x0f, 0xfe, 0xba, 0xdc, 0x0f, 0xfe
};

static u_int8_t expected_cs[32] = {
	0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
	0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
	0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
	0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe
};

static void
vicar_load_test(void)
{
	int				ret;
	struct kyrka_cathedral_cfg	cfg;
	KYRKA				*base;

	base = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(base != NULL);

	ret = kyrka_vicar_load(NULL, NULL, NULL, NULL);
	VERIFY(ret == -1);

	ret = kyrka_vicar_load(base, NULL, NULL, NULL);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(base) == KYRKA_ERROR_PARAMETER);

	ret = kyrka_vicar_load(base, "test-data/vicar.cfg", NULL, NULL);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(base) == KYRKA_ERROR_PARAMETER);

	ret = kyrka_vicar_load(base, "test-data/vicar.cfg", "lol", NULL);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(base) == KYRKA_ERROR_PARAMETER);

	ret = kyrka_vicar_load(base, "test-data/vicar.cfg", "lol", &cfg);
	VERIFY(ret == 0);
}

static void
context_copy_test(void)
{
	int				ret;
	struct kyrka_cathedral_cfg	cfg;
	KYRKA				*base, *clone;

	base = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(base != NULL);

	ret = kyrka_vicar_load(base, "test-data/vicar.cfg", "lol", &cfg);
	VERIFY(ret == 0);

	clone = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(clone != NULL);

	ret = kyrka_key_material_copy(clone, base);
	VERIFY(ret == 0);

	kyrka_mask(base, base->cfg.kek, sizeof(base->cfg.kek));
	kyrka_mask(clone, clone->cfg.kek, sizeof(clone->cfg.kek));

	kyrka_mask(base, base->cathedral.secret,
	    sizeof(base->cathedral.secret));
	kyrka_mask(clone, clone->cathedral.secret,
	    sizeof(clone->cathedral.secret));

	ret = nyfe_mem_cmp(base->cfg.kek, expected_kek, sizeof(expected_kek));
	VERIFY(ret == 0);

	ret = nyfe_mem_cmp(clone->cfg.kek, expected_kek, sizeof(expected_kek));
	VERIFY(ret == 0);

	ret = nyfe_mem_cmp(base->cathedral.secret,
	    expected_cs, sizeof(expected_cs));
	VERIFY(ret == 0);

	ret = nyfe_mem_cmp(clone->cathedral.secret,
	    expected_cs, sizeof(expected_cs));
	VERIFY(ret == 0);
}

void
test_entry(void)
{
	test_framework_register("vicar_load_test", vicar_load_test);
	test_framework_register("context_copy_test", context_copy_test);

	test_framework_run();
}
