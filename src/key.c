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
#include <unistd.h>

#include "libkyrka-int.h"

#define OFFER_DERIVE_LABEL	"SANCTUM.SACRAMENT.KDF"

/*
 * Generate a new key that can be offered to the other side.
 * Note that this only generates an offer, it must be sent to
 * the peer using kyrka_key_offer().
 */
int
kyrka_key_generate(struct kyrka *ctx)
{
	union kyrka_event	evt;
	struct kyrka_cipher	*next;

	if (ctx == NULL)
		return (-1);

	nyfe_random_bytes(ctx->offer.key, sizeof(ctx->offer.key));
	nyfe_random_bytes(&ctx->offer.spi, sizeof(ctx->offer.spi));
	nyfe_random_bytes(&ctx->offer.salt, sizeof(ctx->offer.salt));

	if (ctx->cfg.spi != 0) {
		ctx->offer.spi = (ctx->offer.spi & 0x0000ffff) |
		    ((u_int32_t)ctx->cfg.spi << 16);
	}

	if ((next = kyrka_cipher_setup(ctx,
	    ctx->offer.key, sizeof(ctx->offer.key))) == NULL)
		return (-1);

	ctx->rx.seqnr = 1;
	ctx->rx.bitmap = 0;
	ctx->rx.spi = ctx->offer.spi;
	ctx->rx.salt = ctx->offer.salt;

	if (ctx->rx.cipher != NULL)
		kyrka_cipher_cleanup(ctx->rx.cipher);

	ctx->rx.cipher = next;

	if (ctx->event != NULL) {
		evt.rx.spi = ctx->rx.spi;
		evt.rx.id = ctx->local_id;
		evt.type = KYRKA_EVENT_RX_ACTIVE;
		ctx->event(ctx, &evt, ctx->udata);
	}

	return (0);
}

/*
 * Send our RX key to the peer, will automatically generate a one
 * if none has been generated.
 */
int
kyrka_key_offer(struct kyrka *ctx)
{
	struct kyrka_packet		pkt;
	struct kyrka_offer		*op;
	struct kyrka_key_offer		*key;
	struct nyfe_agelas		cipher;

	if (ctx == NULL)
		return (-1);

	if (!(ctx->flags & KYRKA_FLAG_SECRET_SET)) {
		ctx->last_error = KYRKA_ERROR_NO_SECRET;
		return (-1);
	}

	if (ctx->purgatory.send == NULL) {
		ctx->last_error = KYRKA_ERROR_NO_CALLBACK;
		return (-1);
	}

	if (ctx->offer.spi == 0) {
		if (kyrka_key_generate(ctx) == -1)
			return (-1);
	}

	op = kyrka_offer_init(&pkt, ctx->offer.spi,
	    KYRKA_KEY_OFFER_MAGIC, KYRKA_OFFER_TYPE_KEY);

	nyfe_zeroize_register(&cipher, sizeof(cipher));

	if (kyrka_cipher_kdf(ctx, ctx->cfg.secret, sizeof(ctx->cfg.secret),
	    OFFER_DERIVE_LABEL, &cipher, op->hdr.seed,
	    sizeof(op->hdr.seed)) == -1) {
		nyfe_zeroize(&cipher, sizeof(cipher));
		ctx->last_error = KYRKA_ERROR_FILE_ERROR;
		return (-1);
	}

	key = &op->data.offer.key;
	key->salt = ctx->offer.salt;
	key->id = htobe64(ctx->local_id);
	nyfe_memcpy(key->key, ctx->offer.key, sizeof(ctx->offer.key));

	kyrka_offer_encrypt(&cipher, op);
	nyfe_zeroize(&cipher, sizeof(cipher));

	ctx->purgatory.send(op, sizeof(*op), 0, ctx->purgatory.udata);

	return (0);
}

/*
 * Attempt to verify and decrypt the given key offer and install the session
 * key inside it as the TX key for our peer.
 */
void
kyrka_key_unwrap(struct kyrka *ctx, const void *data, size_t len)
{
	union kyrka_event		evt;
	struct kyrka_key_offer		*key;
	void				*next;
	struct kyrka_offer		offer;
	struct nyfe_agelas		cipher;

	PRECOND(ctx != NULL);
	PRECOND(data != NULL);

	if (len < sizeof(offer))
		return;

	next = NULL;
	nyfe_zeroize_register(&offer, sizeof(offer));
	nyfe_zeroize_register(&cipher, sizeof(cipher));

	nyfe_memcpy(&offer, data, sizeof(offer));

	if (kyrka_cipher_kdf(ctx, ctx->cfg.secret, sizeof(ctx->cfg.secret),
	    OFFER_DERIVE_LABEL, &cipher, offer.hdr.seed,
	    sizeof(offer.hdr.seed)) == -1)
		goto cleanup;

	if (kyrka_offer_decrypt(&cipher, &offer, 10) == -1)
		goto cleanup;

	if (offer.data.type != KYRKA_OFFER_TYPE_KEY)
		goto cleanup;

	offer.hdr.spi = be32toh(offer.hdr.spi);
	if (offer.hdr.spi == ctx->last_spi)
		goto cleanup;

	key = &offer.data.offer.key;
	key->id = be64toh(key->id);

	if (key->id == ctx->local_id)
		goto cleanup;

	ctx->tx.seqnr = 1;
	ctx->tx.salt = key->salt;
	ctx->tx.spi = offer.hdr.spi;

	if ((next = kyrka_cipher_setup(ctx,
	    key->key, sizeof(key->key))) == NULL)
		goto cleanup;

	if (ctx->tx.cipher != NULL)
		kyrka_cipher_cleanup(ctx->tx.cipher);

	ctx->tx.cipher = next;
	next = NULL;

	if (ctx->event != NULL) {
		evt.tx.id = key->id;
		evt.tx.spi = offer.hdr.spi;
		evt.type = KYRKA_EVENT_TX_ACTIVE;
		ctx->event(ctx, &evt, ctx->udata);
	}

	ctx->peer_id = key->id;
	ctx->last_spi = offer.hdr.spi;

cleanup:
	if (next != NULL)
		kyrka_cipher_cleanup(next);

	nyfe_zeroize(&offer, sizeof(offer));
	nyfe_zeroize(&cipher, sizeof(cipher));
}

/*
 * Load some key material from a given path and store it into given buffer.
 */
int
kyrka_key_load_from_path(struct kyrka *ctx, const char *path,
    u_int8_t *buf, size_t buflen)
{
	int		fd;

	PRECOND(ctx != NULL);
	PRECOND(path != NULL);
	PRECOND(buf != NULL);
	PRECOND(buflen == KYRKA_KEY_LENGTH);

	if ((fd = kyrka_file_open(ctx, path)) == -1)
		return (-1);

	if (nyfe_file_read(fd, buf, buflen) != buflen) {
		(void)close(fd);
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		return (-1);
	}

	(void)close(fd);

	return (0);
}
