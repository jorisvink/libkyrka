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

#include "libkyrka-int.h"

static int	purgatory_decapsulate(struct kyrka *,
		    struct kyrka_packet *);
static int	purgatory_arwin_check(struct kyrka_sa *,
		    const struct kyrka_proto_hdr *);
static void	purgatory_arwin_update(struct kyrka_sa *,
		    const struct kyrka_proto_hdr *);

/*
 * Sets the "virtual interface" for the purgatory side to the provided callback.
 *
 * This callback is called when encrypted data needs to be sent and thus
 * the data passed to this callback is ciphertext.
 */
int
kyrka_purgatory_ifc(struct kyrka *ctx,
    void (*cb)(const void *, size_t, u_int64_t, void *), void *udata)
{
	if (ctx == NULL)
		return (-1);

	if (cb == NULL) {
		ctx->last_error = KYRKA_ERROR_PARAMETER;
		return (-1);
	}

	ctx->purgatory.send = cb;
	ctx->purgatory.udata = udata;

	return (0);
}

/*
 * A bunch of data is given as input from purgatory and shall be
 * verified and decrypted under the current RX key (if any) or
 * under a shared cathedral secret if the packet indicated it
 * might be a cathedral packet.
 *
 * If a packet was successfully verified and decrypted and the
 * packet was not a cathedral message, we call the heaven
 * "virtual interface" with the plaintext data.
 *
 * We might have to decapsulate the packet first if encapsulation
 * was enabled on the context.
 */
int
kyrka_purgatory_input(struct kyrka *ctx, const void *data, size_t len)
{
	u_int64_t			pn;
	struct kyrka_packet		pkt;
	struct kyrka_proto_tail		*tail;
	size_t				ctlen;
	struct kyrka_cipher		cipher;
	u_int32_t			spi, seq;
	struct kyrka_proto_hdr		*hdr, aad;
	u_int8_t			nonce[12], *ptr;
	u_int64_t			flock_src, flock_dst;

	if (ctx == NULL)
		return (-1);

	if (data == NULL || len == 0 || len > KYRKA_PACKET_DATA_LEN) {
		ctx->last_error = KYRKA_ERROR_PARAMETER;
		return (-1);
	}

	if (len < sizeof(*hdr) + sizeof(*tail) + KYRKA_TAG_LENGTH)
		return (0);

	pkt.length = len;

	if (ctx->flags & KYRKA_FLAG_ENCAPSULATION)
		ptr = kyrka_packet_start(&pkt);
	else
		ptr = kyrka_packet_head(&pkt);

	memcpy(ptr, data, len);

	if (ctx->flags & KYRKA_FLAG_ENCAPSULATION) {
		if (purgatory_decapsulate(ctx, &pkt) == -1)
			return (-1);
	}

	hdr = kyrka_packet_head(&pkt);
	spi = be32toh(hdr->esp.spi);
	seq = be32toh(hdr->esp.seq);
	pn = be64toh(hdr->pn);

	if (spi == 0)
		return (0);

	if ((spi == (KYRKA_KEY_OFFER_MAGIC >> 32)) &&
	    (seq == (KYRKA_KEY_OFFER_MAGIC & 0xffffffff))) {
		kyrka_key_offer_decrypt(ctx, hdr, pkt.length);
		return (0);
	}

	if ((spi == (KYRKA_CATHEDRAL_MAGIC >> 32)) &&
	    (seq == (KYRKA_CATHEDRAL_MAGIC & 0xffffffff)))
		return (kyrka_cathedral_decrypt(ctx, hdr, pkt.length));

	if (ctx->heaven.send == NULL) {
		ctx->last_error = KYRKA_ERROR_NO_CALLBACK;
		return (-1);
	}

	if (ctx->rx.cipher == NULL) {
		ctx->last_error = KYRKA_ERROR_NO_RX_KEY;
		return (-1);
	}

	flock_src = be64toh(hdr->flock.src);
	flock_dst = be64toh(hdr->flock.dst);

	if (flock_src != ctx->cathedral.flock_dst ||
	    flock_dst != ctx->cathedral.flock_src)
		return (0);

	if (spi != ctx->rx.spi)
		return (0);

	if ((pn & 0xffffffff) != seq)
		return (0);

	if (purgatory_arwin_check(&ctx->rx, hdr) == -1)
		return (0);

	memcpy(&aad, hdr, sizeof(*hdr));
	memcpy(nonce, &ctx->rx.salt, sizeof(ctx->rx.salt));
	memcpy(&nonce[sizeof(ctx->rx.salt)], &hdr->pn, sizeof(hdr->pn));

	cipher.ctx = ctx->rx.cipher;

	cipher.aad = &aad;
	cipher.aad_len = sizeof(aad);

	cipher.nonce = nonce;
	cipher.nonce_len = sizeof(nonce);

	ctlen = pkt.length - sizeof(*hdr) - KYRKA_TAG_LENGTH;

	ptr = kyrka_packet_data(&pkt);
	cipher.ct = ptr;
	cipher.pt = ptr;
	cipher.data_len = ctlen;
	cipher.tag = ptr + ctlen;

	if (kyrka_cipher_decrypt(&cipher) == -1) {
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		return (-1);
	}

	purgatory_arwin_update(&ctx->rx, hdr);

	pkt.length -= sizeof(struct kyrka_proto_hdr);
	pkt.length -= sizeof(struct kyrka_proto_tail);
	pkt.length -= KYRKA_TAG_LENGTH;

	tail = kyrka_packet_tail(&pkt);

	if (tail->pad != 0)
		return (0);

	if (tail->next != 0)
		return (0);

	ctx->rx.pkt++;

	ctx->heaven.send(kyrka_packet_data(&pkt),
	    pkt.length, pn, ctx->heaven.udata);

	return (0);
}

/*
 * Check if the given packet was too old, or already seen.
 */
static int
purgatory_arwin_check(struct kyrka_sa *sa, const struct kyrka_proto_hdr *hdr)
{
	u_int64_t	bit, pn;

	PRECOND(sa != NULL);
	PRECOND(hdr != NULL);

	pn = be64toh(hdr->pn);

	if (pn > sa->seqnr)
		return (0);

	if (pn > 0 && KYRKA_ARWIN_SIZE > sa->seqnr - pn) {
		bit = (KYRKA_ARWIN_SIZE - 1) - (sa->seqnr - pn);
		if (sa->bitmap & ((u_int64_t)1 << bit))
			return (-1);
		return (0);
	}

	return (-1);
}

/*
 * Update the anti-replay window.
 */
static void
purgatory_arwin_update(struct kyrka_sa *sa, const struct kyrka_proto_hdr *hdr)
{
	u_int64_t	pn, bit;

	PRECOND(sa != NULL);
	PRECOND(hdr != NULL);

	pn = be64toh(hdr->pn);

	if (pn > sa->seqnr) {
		if (pn - sa->seqnr >= KYRKA_ARWIN_SIZE) {
			sa->bitmap = ((u_int64_t)1 << 63);
		} else {
			sa->bitmap >>= (pn - sa->seqnr);
			sa->bitmap |= ((u_int64_t)1 << 63);
		}

		sa->seqnr = pn;
		return;
	}

	PRECOND(sa->seqnr >= pn);

	bit = (KYRKA_ARWIN_SIZE - 1) - (sa->seqnr - pn);
	sa->bitmap |= ((u_int64_t)1 << bit);
}

/*
 * Decapsulate a packet by unmasking it using a derived mask from
 * our encapsulation key (TEK).
 */
static int
purgatory_decapsulate(struct kyrka *ctx, struct kyrka_packet *pkt)
{
	size_t				idx;
	struct nyfe_kmac256		kdf;
	struct kyrka_encap_hdr		*hdr;
	u_int8_t			*data, mask[KYRKA_ENCAP_MASK_LEN];

	PRECOND(ctx != NULL);
	PRECOND(pkt != NULL);
	PRECOND(ctx->flags & KYRKA_FLAG_ENCAPSULATION);

	if (pkt->length < sizeof(*hdr))
		return (-1);

	hdr = kyrka_packet_start(pkt);
	data = kyrka_packet_head(pkt);

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

	pkt->length -= sizeof(*hdr);

	return (0);
}
