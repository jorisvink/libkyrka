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

#include <stdio.h>

#include <mbedtls/gcm.h>

#include "libkyrka-int.h"

/*
 * State structure, we only hold the mbedtls gcm context here.
 */
struct cipher_aes_gcm {
	mbedtls_gcm_context		gcm;
};

/*
 * Perform any one-time cipher initialization.
 */
int
kyrka_cipher_init(void)
{
	if (mbedtls_gcm_self_test(0) != 0)
		return (-1);

	return (0);
}

/*
 * Setup the cipher for use.
 */
void *
kyrka_cipher_setup(const u_int8_t *key, size_t len)
{
	struct cipher_aes_gcm	*cipher;

	PRECOND(key != NULL);
	PRECOND(len == KYRKA_KEY_LENGTH);

	if ((cipher = calloc(1, sizeof(*cipher))) == NULL)
		return (NULL);

	mbedtls_gcm_init(&cipher->gcm);

	if (mbedtls_gcm_setkey(&cipher->gcm,
	    MBEDTLS_CIPHER_ID_AES, key, len * 8) != 0) {
		mbedtls_gcm_free(&cipher->gcm);
		free(cipher);
		return (NULL);
	}

	nyfe_zeroize_register(cipher, sizeof(*cipher));

	return (cipher);
}

/*
 * Encrypt and authenticate some data in combination with the given nonce
 * aad, etc.
 */
int
kyrka_cipher_encrypt(struct kyrka_cipher *cipher)
{
	struct cipher_aes_gcm	*ctx;
	size_t			data_len;

	PRECOND(cipher != NULL);

	VERIFY(cipher->pt != NULL);
	VERIFY(cipher->ct != NULL);
	VERIFY(cipher->tag != NULL);
	VERIFY(cipher->aad != NULL);
	VERIFY(cipher->nonce != NULL);
	VERIFY(cipher->nonce_len == KYRKA_NONCE_LENGTH);

	ctx = cipher->ctx;

	if (mbedtls_gcm_starts(&ctx->gcm, MBEDTLS_GCM_ENCRYPT,
	    cipher->nonce, cipher->nonce_len) != 0)
		return (-1);

	if (mbedtls_gcm_update_ad(&ctx->gcm,
	    cipher->aad, cipher->aad_len) != 0)
		return (-1);

	if (mbedtls_gcm_update(&ctx->gcm, cipher->pt,
	    cipher->data_len, cipher->pt, cipher->data_len, &data_len) != 0)
		return (-1);

	VERIFY(data_len == cipher->data_len);

	if (mbedtls_gcm_finish(&ctx->gcm, NULL, 0,
	    &data_len, cipher->tag, KYRKA_TAG_LENGTH) != 0)
		return (-1);

	VERIFY(data_len == 0);

	return (0);
}

/*
 * Decrypt and authenticate some data in combination with the given nonce,
 * aad etc. Returns -1 if the data was unable to be authenticated.
 */
int
kyrka_cipher_decrypt(struct kyrka_cipher *cipher)
{
	struct cipher_aes_gcm	*ctx;
	size_t			data_len;
	u_int8_t		tag[KYRKA_TAG_LENGTH];

	PRECOND(cipher != NULL);

	VERIFY(cipher->pt != NULL);
	VERIFY(cipher->ct != NULL);
	VERIFY(cipher->tag != NULL);
	VERIFY(cipher->aad != NULL);
	VERIFY(cipher->nonce != NULL);
	VERIFY(cipher->nonce_len == KYRKA_NONCE_LENGTH);

	ctx = cipher->ctx;

	if (mbedtls_gcm_starts(&ctx->gcm, MBEDTLS_GCM_DECRYPT,
	    cipher->nonce, cipher->nonce_len) != 0)
		return (-1);

	if (mbedtls_gcm_update_ad(&ctx->gcm,
	    cipher->aad, cipher->aad_len) != 0)
		return (-1);

	if (mbedtls_gcm_update(&ctx->gcm, cipher->pt,
	    cipher->data_len, cipher->pt, cipher->data_len, &data_len) != 0)
		return (-1);

	VERIFY(data_len == cipher->data_len);

	if (mbedtls_gcm_finish(&ctx->gcm, NULL, 0,
	    &data_len, tag, sizeof(tag)) != 0)
		return (-1);

	VERIFY(data_len == 0);

	if (nyfe_mem_cmp(cipher->tag, tag, sizeof(tag)))
		return (-1);

	return (0);
}

/*
 * Cleanup and wipe the cipher state.
 */
void
kyrka_cipher_cleanup(void *arg)
{
	struct cipher_aes_gcm	*cipher;

	PRECOND(arg != NULL);

	cipher = arg;

	mbedtls_gcm_free(&cipher->gcm);
	free(cipher);
}
