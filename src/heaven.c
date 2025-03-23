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
#include <string.h>
#include <time.h>

#include "libkyrka-int.h"

/*
 * Sets the "virtual interface" for the heaven side to the provided callback.
 *
 * This callback is called when arriving data has been verified and decrypted
 * and thus the data passed to this callback is plaintext.
 */
int
kyrka_heaven_ifc(struct kyrka *ctx,
    void (*cb)(const void *, size_t, u_int64_t, void *), void *udata)
{
	if (ctx == NULL)
		return (-1);

	if (cb == NULL) {
		ctx->last_error = KYRKA_ERROR_PARAMETER;
		return (-1);
	}

	ctx->heaven.send = cb;
	ctx->heaven.udata = udata;

	return (0);
}

/*
 * A bunch of data is given as input to the heavens and shall be
 * encrypted under the current TX key (if any).
 *
 * When successful the encrypted data shall be given to purgatory
 * via the purgatory "virtual interface".
 */
int
kyrka_heaven_input(struct kyrka *ctx, const void *data, size_t len)
{
	u_int32_t			spi;
	union kyrka_event		evt;
	struct kyrka_packet		pkt;
	struct kyrka_ipsec_hdr		*hdr;
	struct kyrka_ipsec_tail		*tail;
	struct kyrka_cipher		cipher;
	size_t				overhead;
	u_int8_t			nonce[12], aad[12], *ptr;

	if (ctx == NULL)
		return (-1);

	if (data == NULL || len == 0 || len > KYRKA_PACKET_DATA_LEN) {
		ctx->last_error = KYRKA_ERROR_PARAMETER;
		return (-1);
	}

	if (ctx->purgatory.send == NULL) {
		ctx->last_error = KYRKA_ERROR_NO_CALLBACK;
		return (-1);
	}

	if (ctx->tx.cipher == NULL) {
		ctx->last_error = KYRKA_ERROR_NO_TX_KEY;
		return (-1);
	}

	if (ctx->tx.seqnr >= KYRKA_SA_PACKET_HARD) {
		kyrka_cipher_cleanup(ctx->tx.cipher);
		ctx->tx.cipher = NULL;
		ctx->last_error = KYRKA_ERROR_NO_TX_KEY;

		if (ctx->event != NULL) {
			evt.tx.spi = ctx->tx.spi;
			evt.type = KYRKA_EVENT_TX_EXPIRED;
			ctx->event(ctx, &evt, ctx->udata);
		}

		return (-1);
	}

	overhead = sizeof(*hdr) + sizeof(*tail) + KYRKA_TAG_LENGTH;
	pkt.length = len;

	if ((pkt.length + overhead < pkt.length) ||
	    (pkt.length + overhead > sizeof(pkt.data))) {
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		return (-1);
	}

	ptr = kyrka_packet_data(&pkt);
	memcpy(ptr, data, pkt.length);

	hdr = kyrka_packet_head(&pkt);
	tail = kyrka_packet_tail(&pkt);

	hdr->pn = ctx->tx.seqnr++;
	hdr->esp.spi = htobe32(ctx->tx.spi);
	hdr->esp.seq = htobe32(hdr->pn & 0xffffffff);
	hdr->pn = htobe64(hdr->pn);

	tail->pad = 0;
	tail->next = 0;
	pkt.length += sizeof(*tail);

	memcpy(nonce, &ctx->tx.salt, sizeof(ctx->tx.salt));
	memcpy(&nonce[sizeof(ctx->tx.salt)], &hdr->pn, sizeof(hdr->pn));

	spi = htobe32(ctx->tx.spi);
	memcpy(aad, &spi, sizeof(spi));
	memcpy(&aad[sizeof(spi)], &hdr->pn, sizeof(hdr->pn));

	cipher.ctx = ctx->tx.cipher;

	cipher.aad = aad;
	cipher.aad_len = sizeof(aad);

	cipher.nonce = nonce;
	cipher.nonce_len = sizeof(nonce);

	cipher.pt = ptr;
	cipher.ct = ptr;
	cipher.data_len = pkt.length;
	cipher.tag = ptr + pkt.length;

	if (kyrka_cipher_encrypt(&cipher) == -1)
		return (-1);

	pkt.length += sizeof(*hdr) + KYRKA_TAG_LENGTH;

	ctx->purgatory.send(hdr, pkt.length,
	    ctx->tx.seqnr - 1, ctx->purgatory.udata);

	return (0);
}
