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
#include <stdlib.h>
#include <time.h>

#include "libkyrka-int.h"

/*
 * Set the initial information for a kyrka_offer inside of the
 * given kyrka packet.
 */
struct kyrka_offer *
kyrka_offer_init(struct kyrka_packet *pkt, u_int32_t spi,
    u_int64_t magic, u_int8_t type)
{
	struct timespec		ts;
	struct kyrka_offer	*op;

	PRECOND(pkt != NULL);
	PRECOND(type == KYRKA_OFFER_TYPE_KEY ||
	    type == KYRKA_OFFER_TYPE_AMBRY ||
	    type == KYRKA_OFFER_TYPE_INFO ||
	    type == KYRKA_OFFER_TYPE_LITURGY ||
	    type == KYRKA_OFFER_TYPE_EXCHANGE);

	pkt->length = sizeof(*op);
	op = kyrka_packet_head(pkt);

	op->data.type = type;
	op->hdr.spi = htobe32(spi);
	op->hdr.magic = htobe64(magic);

	kyrka_random_bytes(&op->extra, sizeof(op->extra));
	kyrka_random_bytes(op->hdr.seed, sizeof(op->hdr.seed));
	kyrka_random_bytes(&op->hdr.flock_src, sizeof(op->hdr.flock_src));
	kyrka_random_bytes(&op->hdr.flock_dst, sizeof(op->hdr.flock_dst));

	(void)clock_gettime(CLOCK_REALTIME, &ts);
	op->data.timestamp = htobe64((u_int64_t)ts.tv_sec);

	return (op);
}

/*
 * Encrypt and authenticate a kyrka_offer data structure.
 * Note: does not zeroize the key, this is the caller its responsibility.
 */
int
kyrka_offer_encrypt(struct kyrka_key *key, struct kyrka_offer *op)
{
	struct kyrka_cipher	cipher;
	u_int8_t		nonce[KYRKA_NONCE_LENGTH];

	PRECOND(key != NULL);
	PRECOND(op != NULL);

	cipher.ctx = kyrka_cipher_setup(key->key, sizeof(key->key));
	if (cipher.ctx == NULL)
		return (-1);

	cipher.aad = &op->hdr;
	cipher.aad_len = sizeof(op->hdr);

	kyrka_offer_nonce(nonce, sizeof(nonce));
	cipher.nonce_len = sizeof(nonce);
	cipher.nonce = nonce;

	cipher.pt = &op->data;
	cipher.ct = &op->data;
	cipher.tag = &op->tag[0];
	cipher.data_len = sizeof(op->data) + sizeof(op->extra);

	if (kyrka_cipher_encrypt(&cipher) == -1) {
		kyrka_cipher_cleanup(cipher.ctx);
		return (-1);
	}

	kyrka_cipher_cleanup(cipher.ctx);

	return (0);
}

/*
 * Sign an offer sent to our cathedral with our secret signing key.
 */
int
kyrka_offer_sign(struct kyrka *ctx, struct kyrka_offer *op)
{
	PRECOND(ctx != NULL);
	PRECOND(op != NULL);
	PRECOND(op->data.type == KYRKA_OFFER_TYPE_INFO ||
	    op->data.type == KYRKA_OFFER_TYPE_LITURGY);

	kyrka_mask(ctx, ctx->cathedral.sk, sizeof(ctx->cathedral.sk));

	if (kyrka_signature_create(ctx, &op->data,
	    sizeof(op->data), op->extra.sig, sizeof(op->extra.sig)) == -1) {
		kyrka_mask(ctx, ctx->cathedral.sk, sizeof(ctx->cathedral.sk));
		kyrka_logmsg(ctx, "failed to sign cathedral offer");
		return (-1);
	}

	kyrka_mask(ctx, ctx->cathedral.sk, sizeof(ctx->cathedral.sk));

	return (0);
}

/*
 * Verify and decrypt a kyrka_offer packet.
 * Note: does not zeroize the cipher, this is the caller its responsibility.
 */
int
kyrka_offer_decrypt(struct kyrka_key *key, struct kyrka_offer *op, int valid)
{
	struct timespec		ts;
	struct kyrka_cipher	cipher;
	u_int8_t		nonce[KYRKA_NONCE_LENGTH];

	PRECOND(key != NULL);
	PRECOND(op != NULL);
	PRECOND(valid > 0);

	cipher.ctx = kyrka_cipher_setup(key->key, sizeof(key->key));
	if (cipher.ctx == NULL)
		return (-1);

	cipher.aad = &op->hdr;
	cipher.aad_len = sizeof(op->hdr);

	kyrka_offer_nonce(nonce, sizeof(nonce));
	cipher.nonce_len = sizeof(nonce);
	cipher.nonce = nonce;

	cipher.pt = &op->data;
	cipher.ct = &op->data;
	cipher.tag = &op->tag[0];
	cipher.data_len = sizeof(op->data) + sizeof(op->extra);

	if (kyrka_cipher_decrypt(&cipher) == -1) {
		kyrka_cipher_cleanup(cipher.ctx);
		return (-1);
	}

	kyrka_cipher_cleanup(cipher.ctx);

	(void)clock_gettime(CLOCK_REALTIME, &ts);
	op->data.timestamp = be64toh(op->data.timestamp);

	if (op->data.timestamp < ((u_int64_t)ts.tv_sec - valid) ||
	    op->data.timestamp > ((u_int64_t)ts.tv_sec + valid))
		return (-1);

	return (0);
}

/*
 * Return a nonce containing a single 0x01 byte to the caller.
 * We use this for key offers, cathedral messages and ambries.
 *
 * This might look scary but this does not lead to (key, nonce) pair re-use
 * under a stream cipher as the keys for these type of messages are uniquely
 * derived per message. Don't blindly copy this idiom unless you know what
 * you are doing.
 */
void
kyrka_offer_nonce(u_int8_t *nonce, size_t nonce_len)
{
	PRECOND(nonce != NULL);
	PRECOND(nonce_len == KYRKA_NONCE_LENGTH);

	nyfe_mem_zero(nonce, nonce_len);
	nonce[nonce_len - 1] = 0x01;
}
