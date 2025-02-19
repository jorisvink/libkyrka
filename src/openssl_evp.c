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

/*
 * AES-GCM support via OpenSSL its EVP interface.
 *
 * While this lies in the hot path of the packet flow and is allocating
 * a new EVP_CIPHER_CTX per packet it round key expansion and such is
 * most likely HW accelerated, so the overhead for the allocation
 * and teardown is worth it.
 *
 * If you don't want this overhead, look into using the intel-aes-gcm backend.
 */

#include <sys/types.h>

#include <openssl/evp.h>

#include <stdio.h>

#include "libkyrka-int.h"

#define CIPHER_AES_GCM_TAG_SIZE		16

/*
 * The local cipher state.
 */
struct cipher_aes_gcm {
	u_int8_t	key[32];
};

/*
 * Setup the cipher.
 */
void *
kyrka_cipher_setup(struct kyrka *ctx, const u_int8_t *key, size_t len)
{
	struct cipher_aes_gcm	*cipher;

	PRECOND(ctx != NULL);
	PRECOND(key != NULL);
	PRECOND(len == KYRKA_KEY_LENGTH);

	if ((cipher = calloc(1, sizeof(*cipher))) == NULL) {
		ctx->last_error = KYRKA_ERROR_SYSTEM;
		return (NULL);
	}

	nyfe_zeroize_register(cipher, sizeof(*cipher));
	nyfe_memcpy(cipher->key, key, len);

	return (cipher);
}

/*
 * Returns the overhead for AES-GCM. In this case it's the
 * 16 byte tag.
 */
size_t
kyrka_cipher_overhead(void)
{
	return (CIPHER_AES_GCM_TAG_SIZE);
}

/*
 * Encrypt the packet data.
 * Automatically adds the integrity tag at the end of the ciphertext.
 */
int
kyrka_cipher_encrypt(struct kyrka *ctx, void *arg, const void *nonce,
    size_t nonce_len, const void *aad, size_t aad_len, struct kyrka_packet *pkt)
{
	int			len;
	EVP_CIPHER_CTX		*evp;
	struct cipher_aes_gcm	*cipher;
	u_int8_t		*data, *tag;

	PRECOND(arg != NULL);
	PRECOND(nonce != NULL);
	PRECOND(aad != NULL);
	PRECOND(pkt != NULL);

	PRECOND(pkt->length + CIPHER_AES_GCM_TAG_SIZE < sizeof(pkt->data));

	cipher = arg;
	data = kyrka_packet_data(pkt);
	tag = data + pkt->length;

	if ((evp = EVP_CIPHER_CTX_new()) == NULL) {
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		return (-1);
	}

	if (EVP_EncryptInit_ex(evp, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
		EVP_CIPHER_CTX_free(evp);
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		return (-1);
	}

	if (EVP_CIPHER_CTX_ctrl(evp,
	    EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL) != 1) {
		EVP_CIPHER_CTX_free(evp);
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		return (-1);
	}

	if (EVP_EncryptInit_ex(evp, NULL, NULL, cipher->key, nonce) != 1) {
		EVP_CIPHER_CTX_free(evp);
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		return (-1);
	}

	if (EVP_EncryptUpdate(evp, NULL, &len, aad, aad_len) != 1) {
		EVP_CIPHER_CTX_free(evp);
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		return (-1);
	}

	if (EVP_EncryptUpdate(evp, data, &len, data, pkt->length) != 1) {
		EVP_CIPHER_CTX_free(evp);
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		return (-1);
	}

	if (EVP_EncryptFinal_ex(evp, data + len, &len) != 1) {
		EVP_CIPHER_CTX_free(evp);
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		return (-1);
	}

	if (EVP_CIPHER_CTX_ctrl(evp,
	    EVP_CTRL_GCM_GET_TAG, CIPHER_AES_GCM_TAG_SIZE, tag) != 1) {
		EVP_CIPHER_CTX_free(evp);
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		return (-1);
	}

	EVP_CIPHER_CTX_free(evp);

	pkt->length += CIPHER_AES_GCM_TAG_SIZE;

	return (0);
}

/*
 * Verify and decrypts a given packet.
 */
int
kyrka_cipher_decrypt(struct kyrka *ctx, void *arg, const void *nonce,
    size_t nonce_len, const void *aad, size_t aad_len, struct kyrka_packet *pkt)
{
	EVP_CIPHER_CTX		*evp;
	struct cipher_aes_gcm	*cipher;
	int			ret, olen;
	size_t			ctlen, len;
	u_int8_t		*data, *tag;

	PRECOND(arg != NULL);
	PRECOND(nonce != NULL);
	PRECOND(aad != NULL);
	PRECOND(pkt != NULL);

	if (pkt->length <
	    sizeof(struct kyrka_ipsec_hdr) + CIPHER_AES_GCM_TAG_SIZE) {
		ctx->last_error = KYRKA_ERROR_INTERNAL;	
		return (-1);
	}

	cipher = arg;
	len = pkt->length - sizeof(struct kyrka_ipsec_hdr);

	data = kyrka_packet_data(pkt);
	tag = &data[len - CIPHER_AES_GCM_TAG_SIZE];
	ctlen = tag - data;

	if ((evp = EVP_CIPHER_CTX_new()) == NULL) {
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		return (-1);
	}

	if (EVP_DecryptInit_ex(evp, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
		EVP_CIPHER_CTX_free(evp);
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		return (-1);
	}

	if (EVP_CIPHER_CTX_ctrl(evp,
	    EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL) != 1) {
		EVP_CIPHER_CTX_free(evp);
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		return (-1);
	}

	if (EVP_DecryptInit_ex(evp, NULL, NULL, cipher->key, nonce) != 1) {
		EVP_CIPHER_CTX_free(evp);
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		return (-1);
	}

	if (EVP_DecryptUpdate(evp, NULL, &olen, aad, aad_len) != 1) {
		EVP_CIPHER_CTX_free(evp);
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		return (-1);
	}

	if (EVP_DecryptUpdate(evp, data, &olen, data, ctlen) != 1) {
		EVP_CIPHER_CTX_free(evp);
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		return (-1);
	}

	if (EVP_CIPHER_CTX_ctrl(evp,
	    EVP_CTRL_GCM_SET_TAG, CIPHER_AES_GCM_TAG_SIZE, tag) != 1) {
		EVP_CIPHER_CTX_free(evp);
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		return (-1);
	}

	ret = EVP_DecryptFinal_ex(evp, data + olen, &olen);
	EVP_CIPHER_CTX_free(evp);

	if (ret > 0)
		return (0);

	ctx->last_error = KYRKA_ERROR_INTEGRITY;

	return (-1);
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
