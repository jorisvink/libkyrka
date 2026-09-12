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
cipher_init_test(void)
{
	VERIFY(kyrka_cipher_init() == 0);
}

static void
cipher_roundtrip_test(void)
{
	int			ret;
	void			*ctx;
	u_int8_t		aad[8];
	struct kyrka_cipher	cipher;
	u_int8_t		key[KYRKA_KEY_LENGTH];
	u_int8_t		tag[KYRKA_TAG_LENGTH];
	u_int8_t		pt[64], ct[64], out[64];
	u_int8_t		nonce[KYRKA_NONCE_LENGTH];

	VERIFY(kyrka_cipher_init() == 0);

	memset(pt, 0x44, sizeof(pt));
	memset(key, 0x11, sizeof(key));
	memset(aad, 0x33, sizeof(aad));
	memset(nonce, 0x22, sizeof(nonce));

	ctx = kyrka_cipher_setup(key, sizeof(key));
	VERIFY(ctx != NULL);

	cipher.ctx = ctx;
	cipher.pt = pt;
	cipher.ct = ct;
	cipher.tag = tag;

	cipher.aad = aad;
	cipher.aad_len = sizeof(aad);

	cipher.nonce = nonce;
	cipher.nonce_len = sizeof(nonce);

	cipher.data_len = sizeof(pt);

	ret = kyrka_cipher_encrypt(&cipher);
	VERIFY(ret == 0);
	VERIFY(memcmp(pt, ct, sizeof(pt)) != 0);

	cipher.ct = ct;
	cipher.pt = out;

	ret = kyrka_cipher_decrypt(&cipher);
	VERIFY(ret == 0);
	VERIFY(memcmp(pt, out, sizeof(pt)) == 0);

	kyrka_cipher_cleanup(ctx);
}

static void
cipher_decrypt_detects_tamper_test(void)
{
	int			ret;
	void			*ctx;
	u_int8_t		aad[4];
	struct kyrka_cipher	cipher;
	u_int8_t		key[KYRKA_KEY_LENGTH];
	u_int8_t		tag[KYRKA_TAG_LENGTH];
	u_int8_t		pt[32], ct[32], out[32];
	u_int8_t		nonce[KYRKA_NONCE_LENGTH];

	VERIFY(kyrka_cipher_init() == 0);

	memset(pt, 0x88, sizeof(pt));
	memset(key, 0x55, sizeof(key));
	memset(aad, 0x77, sizeof(aad));
	memset(nonce, 0x66, sizeof(nonce));

	ctx = kyrka_cipher_setup(key, sizeof(key));
	VERIFY(ctx != NULL);

	cipher.ctx = ctx;
	cipher.pt = pt;
	cipher.ct = ct;
	cipher.tag = tag;
	cipher.aad = aad;
	cipher.aad_len = sizeof(aad);
	cipher.nonce = nonce;
	cipher.nonce_len = sizeof(nonce);
	cipher.data_len = sizeof(pt);

	ret = kyrka_cipher_encrypt(&cipher);
	VERIFY(ret == 0);

	ct[0] ^= 0x01;

	cipher.ct = ct;
	cipher.pt = out;

	ret = kyrka_cipher_decrypt(&cipher);
	VERIFY(ret == -1);

	kyrka_cipher_cleanup(ctx);
}

static void
cipher_decrypt_detects_aad_tamper_test(void)
{
	int			ret;
	void			*ctx;
	u_int8_t		aad[4];
	struct kyrka_cipher	cipher;
	u_int8_t		key[KYRKA_KEY_LENGTH];
	u_int8_t		tag[KYRKA_TAG_LENGTH];
	u_int8_t		pt[32], ct[32], out[32];
	u_int8_t		nonce[KYRKA_NONCE_LENGTH];

	VERIFY(kyrka_cipher_init() == 0);

	memset(pt, 0xcc, sizeof(pt));
	memset(key, 0x99, sizeof(key));
	memset(aad, 0xbb, sizeof(aad));
	memset(nonce, 0xaa, sizeof(nonce));

	ctx = kyrka_cipher_setup(key, sizeof(key));
	VERIFY(ctx != NULL);

	cipher.ctx = ctx;
	cipher.pt = pt;
	cipher.ct = ct;
	cipher.tag = tag;

	cipher.aad = aad;
	cipher.aad_len = sizeof(aad);

	cipher.nonce = nonce;
	cipher.nonce_len = sizeof(nonce);

	cipher.data_len = sizeof(pt);

	ret = kyrka_cipher_encrypt(&cipher);
	VERIFY(ret == 0);

	aad[0] ^= 0x01;

	cipher.ct = ct;
	cipher.pt = out;

	ret = kyrka_cipher_decrypt(&cipher);
	VERIFY(ret == -1);

	kyrka_cipher_cleanup(ctx);
}

void
test_entry(void)
{
	test_framework_register("cipher_init_test", cipher_init_test);
	test_framework_register("cipher_roundtrip_test", cipher_roundtrip_test);
	test_framework_register("cipher_decrypt_detects_tamper_test",
	    cipher_decrypt_detects_tamper_test);
	test_framework_register("cipher_decrypt_detects_aad_tamper_test",
	    cipher_decrypt_detects_aad_tamper_test);

	test_framework_run();
}
