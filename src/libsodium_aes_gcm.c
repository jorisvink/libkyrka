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
#include <sodium.h>

#include "libkyrka-int.h"

/*
 * The local cipher state.
 */
struct cipher_aes_gcm {
	crypto_aead_aes256gcm_state	ctx;
};

/*
 * Perform any one-time cipher initialization.
 */
int
kyrka_cipher_init(void)
{
	return (sodium_init());
}

/*
 * Setup the cipher.
 */
void *
kyrka_cipher_setup(const u_int8_t *key, size_t len)
{
	struct cipher_aes_gcm	*cipher;

	PRECOND(key != NULL);
	PRECOND(len == KYRKA_KEY_LENGTH);

	if ((cipher = calloc(1, sizeof(*cipher))) == NULL)
		return (NULL);

	if (crypto_aead_aes256gcm_beforenm(&cipher->ctx, key) == -1) {
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

	PRECOND(cipher != NULL);

	VERIFY(cipher->pt != NULL);
	VERIFY(cipher->ct != NULL);
	VERIFY(cipher->tag != NULL);
	VERIFY(cipher->aad != NULL);
	VERIFY(cipher->nonce != NULL);
	VERIFY(cipher->nonce_len == KYRKA_NONCE_LENGTH);

	ctx = cipher->ctx;

	if (crypto_aead_aes256gcm_encrypt_detached_afternm(cipher->ct,
	    cipher->tag, NULL, cipher->pt, cipher->data_len, cipher->aad,
	    cipher->aad_len, NULL, cipher->nonce, &ctx->ctx) == -1)
		return (-1);

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

	PRECOND(cipher != NULL);

	VERIFY(cipher->pt != NULL);
	VERIFY(cipher->ct != NULL);
	VERIFY(cipher->tag != NULL);
	VERIFY(cipher->aad != NULL);
	VERIFY(cipher->nonce != NULL);
	VERIFY(cipher->nonce_len == KYRKA_NONCE_LENGTH);

	ctx = cipher->ctx;

	if (crypto_aead_aes256gcm_decrypt_detached_afternm(cipher->pt,
	    NULL, cipher->ct, cipher->data_len, cipher->tag, cipher->aad,
	    cipher->aad_len, cipher->nonce, &ctx->ctx) == -1)
		return (-1);

	return (0);
}

/*
 * Cleanup the AES-GCM cipher states.
 */
void
kyrka_cipher_cleanup(void *arg)
{
	struct cipher_aes_gcm	*cipher;

	PRECOND(arg != NULL);

	cipher = arg;

	nyfe_zeroize(cipher, sizeof(*cipher));
	free(cipher);
}
