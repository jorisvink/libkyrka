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

	if (crypto_aead_aes256gcm_beforenm(&cipher->ctx, key) == -1) {
		free(cipher);
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		return (NULL);
	}

	nyfe_zeroize_register(cipher, sizeof(*cipher));

	return (cipher);
}

/*
 * Returns the overhead for AES-GCM. In this case it's the
 * 16 byte tag.
 */
size_t
kyrka_cipher_overhead(void)
{
	return (crypto_aead_aes256gcm_ABYTES);
}

/*
 * Encrypt the packet data.
 * Automatically adds the integrity tag at the end of the ciphertext.
 */
int
kyrka_cipher_encrypt(struct kyrka *ctx, void *arg, const void *nonce,
    size_t nonce_len, const void *aad, size_t aad_len, struct kyrka_packet *pkt)
{
	unsigned long long	mlen;
	u_int8_t		*data;
	struct cipher_aes_gcm	*cipher;

	PRECOND(ctx != NULL);
	PRECOND(arg != NULL);
	PRECOND(nonce != NULL);
	PRECOND(nonce_len == crypto_aead_aes256gcm_NPUBBYTES);
	PRECOND(aad != NULL);
	PRECOND(pkt != NULL);

	PRECOND(pkt->length + crypto_aead_aes256gcm_ABYTES < sizeof(pkt->data));

	cipher = arg;
	mlen = pkt->length;
	data = kyrka_packet_data(pkt);

	if (crypto_aead_aes256gcm_encrypt_afternm(data, &mlen, data,
	    mlen, aad, aad_len, NULL, nonce, &cipher->ctx) == -1) {
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		return (-1);
	}

	pkt->length += crypto_aead_aes256gcm_ABYTES;

	return (0);
}

/*
 * Verify and decrypts a given packet.
 */
int
kyrka_cipher_decrypt(struct kyrka *ctx, void *arg, const void *nonce,
    size_t nonce_len, const void *aad, size_t aad_len, struct kyrka_packet *pkt)
{
	size_t			len;
	u_int8_t		*data;
	struct cipher_aes_gcm	*cipher;

	PRECOND(ctx != NULL);
	PRECOND(arg != NULL);
	PRECOND(nonce != NULL);
	PRECOND(nonce_len == crypto_aead_aes256gcm_NPUBBYTES);
	PRECOND(aad != NULL);
	PRECOND(pkt != NULL);

	if (pkt->length <
	    sizeof(struct kyrka_ipsec_hdr) + crypto_aead_aes256gcm_ABYTES) {
		ctx->last_error = KYRKA_ERROR_INTERNAL;	
		return (-1);
	}

	cipher = arg;
	data = kyrka_packet_data(pkt);
	len = pkt->length - sizeof(struct kyrka_ipsec_hdr);

	if (crypto_aead_aes256gcm_decrypt_afternm(data, NULL, NULL,
	    data, len, aad, aad_len, nonce, &cipher->ctx) == -1) {
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		return (-1);
	}

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
