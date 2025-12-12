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

#include "libkyrka-int.h"

/*
 * After how many packets do we rollover the pn and spi when
 * we are applying encapsulation.
 *
 * Doing this just makes it look like we negotiated.
 */
#define PACKET_ENCAP_PKT_MAX		(1 << 20)

/*
 * Returns a pointer to the start of the entire packet buffer.
 */
void *
kyrka_packet_start(struct kyrka_packet *pkt)
{
	PRECOND(pkt != NULL);

	return (&pkt->data[0]);
}

/*
 * Returns a pointer to the packet header (the location of the sanctum header).
 */
void *
kyrka_packet_head(struct kyrka_packet *pkt)
{
	PRECOND(pkt != NULL);

	return (&pkt->data[KYRKA_PACKET_HEAD_OFFSET]);
}

/*
 * Returns a pointer to the packet data (immediately after the sanctum header).
 */
void *
kyrka_packet_data(struct kyrka_packet *pkt)
{
	PRECOND(pkt != NULL);

	return (&pkt->data[KYRKA_PACKET_DATA_OFFSET]);
}

/*
 * Returns a pointer to the packet tail (immediately after the packet data).
 */
void *
kyrka_packet_tail(struct kyrka_packet *pkt)
{
	PRECOND(pkt != NULL);
	PRECOND(pkt->length <= KYRKA_PACKET_DATA_LEN);

	return (&pkt->data[KYRKA_PACKET_DATA_OFFSET + pkt->length]);
}

/*
 * Check if the given packet contains enough data to satisfy
 * an IPSec header, tail and cipher overhead.
 */
int
kyrka_packet_crypto_checklen(struct kyrka_packet *pkt)
{
	PRECOND(pkt != NULL);

	if (pkt->length < sizeof(struct kyrka_proto_hdr) +
	    sizeof(struct kyrka_proto_tail) + KYRKA_TAG_LENGTH)
		return (-1);

	return (0);
}

/*
 * Finalize a packet for sending, encapsulating it if required.
 * Returns a pointer to the data that should be sent onto the wire.
 * Adjusts pkt->length if required.
 */
void *
kyrka_packet_tx_finalize(struct kyrka *ctx, struct kyrka_packet *pkt)
{
	struct nyfe_kmac256		kdf;
	struct kyrka_encap_hdr		*hdr;
	size_t				idx, total;
	u_int8_t			*data, mask[KYRKA_ENCAP_MASK_LEN];

	PRECOND(ctx != NULL);
	PRECOND(pkt != NULL);

	if (!(ctx->flags & KYRKA_FLAG_ENCAPSULATION))
		return (kyrka_packet_head(pkt));

	total = sizeof(*hdr) + pkt->length;
	VERIFY(total > pkt->length && total < KYRKA_PACKET_MAX_LEN);

	hdr = kyrka_packet_start(pkt);
	data = kyrka_packet_head(pkt);

	kyrka_random_bytes(hdr->seed, sizeof(hdr->seed));

	nyfe_kmac256_init(&kdf, ctx->encap.tek, sizeof(ctx->encap.tek),
	    KYRKA_ENCAP_LABEL, sizeof(KYRKA_ENCAP_LABEL) - 1);
	nyfe_kmac256_update(&kdf, hdr, sizeof(*hdr));
	nyfe_kmac256_final(&kdf, mask, sizeof(mask));

	/*
	 * We do not check pkt length here before applying the XOR mask
	 * as the buffer will always have enough space to do this.
	 */
	for (idx = 0; idx < sizeof(mask); idx++)
		data[idx] ^= mask[idx];

	pkt->length += sizeof(*hdr);

	return (hdr);
}
