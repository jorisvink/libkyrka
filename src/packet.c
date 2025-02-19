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
 * Returns a pointer to the start of the entire packet buffer.
 */
void *
kyrka_packet_start(struct kyrka_packet *pkt)
{
	PRECOND(pkt != NULL);

	return (&pkt->data[0]);
}

/*
 * Returns a pointer to the packet header (the location of the ESP header).
 */
void *
kyrka_packet_head(struct kyrka_packet *pkt)
{
	PRECOND(pkt != NULL);

	return (&pkt->data[KYRKA_PACKET_HEAD_OFFSET]);
}

/*
 * Returns a pointer to the packet data (immediately after the ESP header).
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

	if (pkt->length < sizeof(struct kyrka_ipsec_hdr) +
	    sizeof(struct kyrka_ipsec_tail) + kyrka_cipher_overhead())
		return (-1);

	return (0);
}
