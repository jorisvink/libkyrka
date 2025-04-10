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
#include <unistd.h>

#include <sodium.h>

#include "libkyrka-int.h"

/* The KDF label for deriving a key for encrypting an offer. */
#define OFFER_DERIVE_LABEL	"SANCTUM.SACRAMENT.KDF"

static void	key_offer_clear(struct kyrka *);
static int	key_offer_send(struct kyrka *, u_int64_t);
static int	key_offer_check(struct kyrka *, u_int64_t);
static int	key_offer_create(struct kyrka *, u_int64_t);

static void	key_install(struct kyrka *, const u_int8_t *, size_t,
		    const u_int8_t *, size_t, struct kyrka_offer *);

/*
 * Called every event tick by the user of the library. We figure out if we
 * need to generate a key offer, or send an active one, or stop the sending.
 */
int
kyrka_key_manage(struct kyrka *ctx)
{
	struct timespec		ts;

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

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);

	if (ctx->offer.spi != 0) {
		if (ctx->offer.spi == ctx->rx.spi && ctx->rx.pkt > 0) {
			key_offer_clear(ctx);
		} else if ((u_int64_t)ts.tv_sec >= ctx->offer.pulse) {
			key_offer_send(ctx, ts.tv_sec);
		}
	} else {
		if (key_offer_check(ctx, ts.tv_sec) == -1)
			return (-1);
	}

	return (0);
}

/*
 * Verify and decrypt the received key offer, if we are able to do so
 * finalize our asymmetrical negotiation and derive the new traffic
 * keys that are installed in the RX and TX slots.
 */
void
kyrka_key_unwrap(struct kyrka *ctx, const void *data, size_t len)
{
	struct timespec			ts;
	union kyrka_event		evt;
	struct kyrka_key		okm;
	struct kyrka_kex		kex;
	struct kyrka_key_offer		*key;
	struct kyrka_offer		offer;
	const u_int8_t			*rx, *tx;
	u_int8_t			km[KYRKA_KEY_LENGTH * 2];

	PRECOND(ctx != NULL);
	PRECOND(data != NULL);

	if (len < sizeof(offer))
		return;

	nyfe_zeroize_register(km, sizeof(km));
	nyfe_zeroize_register(&kex, sizeof(kex));
	nyfe_zeroize_register(&okm, sizeof(okm));
	nyfe_zeroize_register(&offer, sizeof(offer));

	nyfe_memcpy(&offer, data, sizeof(offer));

	kyrka_offer_kdf(ctx->cfg.secret, sizeof(ctx->cfg.secret),
	    OFFER_DERIVE_LABEL, &okm, offer.hdr.seed, sizeof(offer.hdr.seed));

	if (kyrka_offer_decrypt(&okm, &offer, 10) == -1)
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

	if (ctx->offer.spi != 0 && ctx->peer_id != 0 && key->id != ctx->peer_id)
		key_offer_clear(ctx);

	if (ctx->offer.spi == 0) {
		(void)clock_gettime(CLOCK_MONOTONIC, &ts);
		key_offer_create(ctx, ts.tv_sec);

		if (ctx->event != NULL) {
			evt.type = KYRKA_EVENT_EXCHANGE_INFO;
			evt.exchange.reason = "peer renegotiation";
			ctx->event(ctx, &evt, ctx->udata);
		}
	}

	nyfe_memcpy(kex.remote, key->key, sizeof(key->key));
	nyfe_memcpy(kex.private, ctx->offer.key, sizeof(ctx->offer.key));

	if (key->id < ctx->local_id) {
		nyfe_memcpy(kex.pub1, ctx->offer.public,
		    sizeof(ctx->offer.public));
		nyfe_memcpy(kex.pub2, key->key, sizeof(key->key));
	} else {
		nyfe_memcpy(kex.pub1, key->key, sizeof(key->key));
		nyfe_memcpy(kex.pub2, ctx->offer.public,
		    sizeof(ctx->offer.public));
	}

	if (kyrka_traffic_kdf(ctx, &kex, km, sizeof(km)) == -1)
		goto cleanup;

	if (key->id < ctx->local_id) {
		rx = &km[0];
		tx = &km[KYRKA_KEY_LENGTH];
	} else {
		tx = &km[0];
		rx = &km[KYRKA_KEY_LENGTH];
	}

	key_install(ctx, rx, KYRKA_KEY_LENGTH, tx, KYRKA_KEY_LENGTH, &offer);

	ctx->peer_id = key->id;
	ctx->last_spi = offer.hdr.spi;

	ctx->offer.next = 0;
	ctx->offer.default_ttl = 5;
	ctx->offer.default_next_send = 1;

cleanup:
	nyfe_zeroize(km, sizeof(km));
	nyfe_zeroize(&kex, sizeof(kex));
	nyfe_zeroize(&okm, sizeof(okm));
	nyfe_zeroize(&offer, sizeof(offer));
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

/*
 * Check if a new offer should be generated.
 */
static int
key_offer_check(struct kyrka *ctx, u_int64_t now)
{
	union kyrka_event	evt;
	const char		*reason;
	int			offer_now;

	PRECOND(ctx != NULL);
	PRECOND(ctx->offer.spi == 0);

	if (now < ctx->offer.next)
		return (0);

	offer_now = 0;
	reason = NULL;

	if (ctx->rx.spi != 0) {
		ctx->offer.default_ttl = 6;
		ctx->offer.default_next_send = 10;

		if (ctx->rx.pkt > KYRKA_SA_PACKET_SOFT) {
			offer_now = 1;
			reason = "SA packet limit";
		}
	} else {
		offer_now = 1;
		reason = "no keys";
	}

	if (offer_now == 0)
		return (0);

	if (ctx->offer.spi != 0)
		return (0);

	if (key_offer_create(ctx, now) == -1)
		return (-1);

	if (ctx->event != NULL) {
		evt.type = KYRKA_EVENT_EXCHANGE_INFO;
		evt.exchange.reason = reason;
		ctx->event(ctx, &evt, ctx->udata);
	}

	return (0);
}

/*
 * Generate a new key that can be offered to the other side.
 */
static int
key_offer_create(struct kyrka *ctx, u_int64_t now)
{
	PRECOND(ctx != NULL);
	PRECOND(ctx->offer.spi == 0);

	nyfe_random_bytes(ctx->offer.key, sizeof(ctx->offer.key));
	nyfe_random_bytes(&ctx->offer.spi, sizeof(ctx->offer.spi));
	nyfe_random_bytes(&ctx->offer.salt, sizeof(ctx->offer.salt));

	if (crypto_scalarmult_curve25519_base(ctx->offer.public,
	    ctx->offer.key) == -1) {
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		return (-1);
	}

	if (ctx->cfg.spi != 0) {
		ctx->offer.spi = (ctx->offer.spi & 0x0000ffff) |
		    ((u_int32_t)ctx->cfg.spi << 16);
	}

	ctx->offer.pulse = now;
	ctx->offer.ttl = ctx->offer.default_ttl;

	return (0);
}

/*
 * Send the current active offer to our peer via the purgatory interface.
 */
static int
key_offer_send(struct kyrka *ctx, u_int64_t now)
{
	int				ret;
	struct kyrka_packet		pkt;
	struct kyrka_key		okm;
	struct kyrka_offer		*op;
	struct kyrka_key_offer		*key;

	PRECOND(ctx != NULL);
	PRECOND(ctx->purgatory.send != NULL);

	ret = -1;

	ctx->offer.ttl--;
	ctx->offer.pulse = now + ctx->offer.default_next_send;

	op = kyrka_offer_init(&pkt, ctx->offer.spi,
	    KYRKA_KEY_OFFER_MAGIC, KYRKA_OFFER_TYPE_KEY);

	if (ctx->flags & KYRKA_FLAG_CATHEDRAL_CONFIG)
		op->hdr.flock = htobe64(ctx->cathedral.flock);

	nyfe_zeroize_register(&okm, sizeof(okm));

	kyrka_offer_kdf(ctx->cfg.secret, sizeof(ctx->cfg.secret),
	    OFFER_DERIVE_LABEL, &okm, op->hdr.seed, sizeof(op->hdr.seed));

	key = &op->data.offer.key;
	key->salt = ctx->offer.salt;
	key->id = htobe64(ctx->local_id);
	nyfe_memcpy(key->key, ctx->offer.public, sizeof(ctx->offer.public));

	if (kyrka_offer_encrypt(&okm, op) == -1) {
		nyfe_zeroize(&okm, sizeof(okm));
		goto cleanup;
	}

	nyfe_zeroize(&okm, sizeof(okm));
	ctx->purgatory.send(op, sizeof(*op), 0, ctx->purgatory.udata);

	ret = 0;

cleanup:
	if (ctx->offer.ttl == 0)
		key_offer_clear(ctx);

	return (ret);
}

/*
 * Clear the pending current offer.
 */
static void
key_offer_clear(struct kyrka *ctx)
{
	union kyrka_event	evt;

	PRECOND(ctx != NULL);
	PRECOND(ctx->offer.spi != 0);

	nyfe_mem_zero(&ctx->offer, sizeof(ctx->offer));

	ctx->offer.default_ttl = 5;
	ctx->offer.default_next_send = 1;

	if (ctx->event != NULL) {
		evt.type = KYRKA_EVENT_EXCHANGE_INFO;
		evt.exchange.reason = "key offer cleared";
		ctx->event(ctx, &evt, ctx->udata);
	}
}

/*
 * Install both the RX and TX keys into the context so that they become
 * immediately active for use.
 */
static void
key_install(struct kyrka *ctx, const u_int8_t *rx, size_t rxlen,
    const u_int8_t *tx, size_t txlen, struct kyrka_offer *offer)
{
	union kyrka_event		evt;
	struct kyrka_key_offer		*key;
	void				*next;

	PRECOND(ctx != NULL);
	PRECOND(rx != NULL);
	PRECOND(rxlen == KYRKA_KEY_LENGTH);
	PRECOND(tx != NULL);
	PRECOND(txlen == KYRKA_KEY_LENGTH);
	PRECOND(offer != NULL);

	key = &offer->data.offer.key;

	ctx->tx.pkt = 0;
	ctx->tx.seqnr = 1;
	ctx->tx.salt = key->salt;
	ctx->tx.spi = offer->hdr.spi;

	if ((next = kyrka_cipher_setup(tx, txlen)) == NULL)
		return;

	if (ctx->tx.cipher != NULL)
		kyrka_cipher_cleanup(ctx->tx.cipher);

	ctx->tx.cipher = next;

	if ((next = kyrka_cipher_setup(rx, rxlen)) == NULL)
		return;

	ctx->rx.pkt = 0;
	ctx->rx.seqnr = 1;
	ctx->rx.bitmap = 0;
	ctx->rx.spi = ctx->offer.spi;
	ctx->rx.salt = ctx->offer.salt;

	if (ctx->rx.cipher != NULL)
		kyrka_cipher_cleanup(ctx->rx.cipher);

	ctx->rx.cipher = next;

	if (ctx->event != NULL) {
		evt.type = KYRKA_EVENT_KEYS_INFO;
		evt.keys.peer_id = key->id;
		evt.keys.tx_spi = ctx->tx.spi;
		evt.keys.rx_spi = ctx->rx.spi;
		ctx->event(ctx, &evt, ctx->udata);
	}
}
