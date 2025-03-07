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
 * Note: does not zeroize the cipher, this is the caller its responsibility.
 */
void
kyrka_offer_encrypt(struct nyfe_agelas *cipher, struct kyrka_offer *op)
{
	PRECOND(cipher != NULL);
	PRECOND(op != NULL);

	nyfe_agelas_aad(cipher, &op->hdr, sizeof(op->hdr));
	nyfe_agelas_encrypt(cipher, &op->data, &op->data, sizeof(op->data));
	nyfe_agelas_authenticate(cipher, op->tag, sizeof(op->tag));
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
kyrka_offer_decrypt(struct nyfe_agelas *cipher,
    struct kyrka_offer *op, int valid)
{
	struct timespec		ts;
	u_int8_t		tag[32];

	PRECOND(cipher != NULL);
	PRECOND(op != NULL);
	PRECOND(valid > 0);

	nyfe_agelas_aad(cipher, &op->hdr, sizeof(op->hdr));
	nyfe_agelas_decrypt(cipher, &op->data, &op->data, sizeof(op->data));
	nyfe_agelas_authenticate(cipher, tag, sizeof(tag));

	if (nyfe_mem_cmp(op->tag, tag, sizeof(op->tag)))
		return (-1);

	(void)clock_gettime(CLOCK_REALTIME, &ts);
	op->data.timestamp = be64toh(op->data.timestamp);

	if (op->data.timestamp < ((u_int64_t)ts.tv_sec - valid) ||
	    op->data.timestamp > ((u_int64_t)ts.tv_sec + valid))
		return (-1);

	return (0);
}
