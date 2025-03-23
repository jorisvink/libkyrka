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
	    type == KYRKA_OFFER_TYPE_LITURGY);

	op = kyrka_packet_head(pkt);

	op->data.type = type;
	op->hdr.spi = htobe32(spi);
	op->hdr.magic = htobe64(magic);

	nyfe_random_bytes(op->hdr.seed, sizeof(op->hdr.seed));
	nyfe_random_bytes(&op->hdr.flock, sizeof(op->hdr.flock));

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
	cipher.data_len = sizeof(op->data);

	if (kyrka_cipher_encrypt(&cipher) == -1) {
		kyrka_cipher_cleanup(cipher.ctx);
		return (-1);
	}

	kyrka_cipher_cleanup(cipher.ctx);

	return (0);
}

/*
 * Provide TFC for the offer when both tfc and encap are enabled, this hides
 * the fact that this is an offer on the wire.
 *
 * We have to include the ipsec header, tail and the cipher overhead
 * so that the offer is indistinguishable from traffic.
 *
 * The remaining bytes in the packet are filled with random data.
 */
void
kyrka_offer_tfc(struct kyrka_packet *pkt)
{
#if 0
	u_int8_t	*data;
	size_t		offset;

	PRECOND(pkt != NULL);
	PRECOND(pkt->length == sizeof(struct kyrka_offer));

	if ((kyrka->flags & SANCTUM_FLAG_TFC_ENABLED) &&
	    (kyrka->flags & SANCTUM_FLAG_ENCAPSULATE)) {
		offset = pkt->length;
		pkt->length = kyrka->tun_mtu +
		    sizeof(struct kyrka_ipsec_hdr) +
		    sizeof(struct kyrka_ipsec_tail) +
		    kyrka_cipher_overhead();
		data = kyrka_packet_head(pkt);
		nyfe_random_bytes(&data[offset], pkt->length - offset);
	}
#endif
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
	cipher.data_len = sizeof(op->data);

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
