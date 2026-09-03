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

/*
 * A last resort backend for using AES-GCM via OpenSSL's its libcrypto
 * using a software implementation.
 *
 * This is absolutely not ideal but this should work anywhere OpenSSL exists.
 *
 * Why not EVP you ask? Because the EVP interfaces cause bless and confess
 * to try and want to call openat() to open things like /etc/ssl/openssl.cnf
 * even though we are only doing encryption or decryption. Incredibly broken
 * in a sandboxed and privsep'd environment.
 *
 * "But you can turn that off via OPENSSL_init_crypto()" - Yes thats true, but
 * on certain platforms it will also try /proc/sys/crypto/fips_enabled at
 * runtime and I am over it. Unless someone can show me a way to turn *that*
 * off we are stuck with not being able to use their "preferred" method.
 */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <sys/types.h>

#include <openssl/aes.h>
#include <openssl/modes.h>

#include <stdio.h>

#include "libkyrka-int.h"

#define CIPHER_AES_GCM_TAG_SIZE		16

/*
 * The local cipher state.
 */
struct cipher_aes_gcm {
	AES_KEY			key;
	GCM128_CONTEXT		*gcm;
};

/*
 * Perform any one-time cipher initialization.
 */
int
kyrka_cipher_init(void)
{
	return (0);
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

	if (AES_set_encrypt_key(key, 256, &cipher->key) != 0) {
		free(cipher);
		return (NULL);
	}

	if ((cipher->gcm = CRYPTO_gcm128_new(&cipher->key,
	    (block128_f)AES_encrypt)) == NULL) {
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
	VERIFY(cipher->aad_len > 0);
	VERIFY(cipher->nonce != NULL);
	VERIFY(cipher->nonce_len == KYRKA_NONCE_LENGTH);

	ctx = cipher->ctx;

	CRYPTO_gcm128_setiv(ctx->gcm, cipher->nonce, cipher->nonce_len);

	if (CRYPTO_gcm128_aad(ctx->gcm, cipher->aad, cipher->aad_len) != 0)
		return (-1);

	if (CRYPTO_gcm128_encrypt(ctx->gcm,
	    cipher->pt, cipher->ct, cipher->data_len) != 0)
		return (-1);

	CRYPTO_gcm128_tag(ctx->gcm, cipher->tag, CIPHER_AES_GCM_TAG_SIZE);

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
	VERIFY(cipher->aad_len > 0);
	VERIFY(cipher->nonce != NULL);
	VERIFY(cipher->nonce_len == KYRKA_NONCE_LENGTH);

	ctx = cipher->ctx;

	CRYPTO_gcm128_setiv(ctx->gcm, cipher->nonce, cipher->nonce_len);

	if (CRYPTO_gcm128_aad(ctx->gcm, cipher->aad, cipher->aad_len) != 0)
		return (-1);

	if (CRYPTO_gcm128_decrypt(ctx->gcm,
	    cipher->ct, cipher->pt, cipher->data_len) != 0)
		return (-1);

	if (CRYPTO_gcm128_finish(ctx->gcm, cipher->tag,
	    CIPHER_AES_GCM_TAG_SIZE) != 0)
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

	CRYPTO_gcm128_release(cipher->gcm);
	nyfe_zeroize(cipher, sizeof(*cipher));

	free(cipher);
}
