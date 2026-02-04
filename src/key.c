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

static void	key_offer_clear(struct kyrka *);
static int	key_offer_send(struct kyrka *, u_int64_t);
static int	key_offer_check(struct kyrka *, u_int64_t);
static int	key_offer_create(struct kyrka *, u_int64_t);
static int	key_offer_send_fragment(struct kyrka *, int, u_int8_t);

static int	key_make_active(struct kyrka_sa *, struct kyrka_xchg_info *,
		    const u_int8_t *, size_t, time_t);

static void	key_exchange(struct kyrka *, struct kyrka_offer *);
static void	key_exchange_encapsulate(struct kyrka *,
		    struct kyrka_offer *, time_t);
static void	key_exchange_decapsulate(struct kyrka *,
		    struct kyrka_offer *, time_t);
static void	key_exchange_finalize(struct kyrka *,
		    struct kyrka_offer *, time_t, u_int8_t);

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

	if (ctx->offer.local.spi != 0) {
		if (ctx->offer.local.spi == ctx->rx.spi && ctx->rx.pkt > 0) {
			ctx->flags &= ~KYRKA_FLAG_AMBRY_NEGOTIATION;
			ctx->offer.flags &= ~KYRKA_OFFER_INCLUDE_KEM_CT;
			if (ctx->offer.flags == 0)
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
 * Attempt to verify the given key offer that should be in data.
 *
 * If we can verify that it was sent by the peer, and it is not
 * too old we will use it to perform a key exchange which may either
 * already be active or needs to be started.
 */
void
kyrka_key_offer_decrypt(struct kyrka *ctx, const void *data, size_t len)
{
	struct kyrka_key		okm;
	struct kyrka_offer		offer;
	struct kyrka_exchange_offer	*exchange;

	PRECOND(ctx != NULL);
	PRECOND(data != NULL);

	if (len < sizeof(offer))
		return;

	nyfe_zeroize_register(&okm, sizeof(okm));
	nyfe_zeroize_register(&offer, sizeof(offer));

	nyfe_memcpy(&offer, data, sizeof(offer));

	kyrka_mask(ctx, ctx->cfg.secret, sizeof(ctx->cfg.secret));
	kyrka_offer_kdf(ctx, ctx->cfg.secret, sizeof(ctx->cfg.secret),
	    KYRKA_CHAPEL_DERIVE_LABEL, &okm, offer.hdr.seed,
	    sizeof(offer.hdr.seed), ctx->cathedral.flock_src,
	    ctx->cathedral.flock_dst);
	kyrka_mask(ctx, ctx->cfg.secret, sizeof(ctx->cfg.secret));

	if (kyrka_offer_decrypt(&okm, &offer, 10) == -1)
		goto cleanup;

	if (offer.data.type != KYRKA_OFFER_TYPE_EXCHANGE)
		goto cleanup;

	exchange = &offer.data.offer.exchange;
	exchange->id = be64toh(exchange->id);

	if (exchange->id == ctx->local_id)
		goto cleanup;

	offer.hdr.spi = be32toh(offer.hdr.spi);
	key_exchange(ctx, &offer);

cleanup:
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
	PRECOND(buflen == KYRKA_KEY_LENGTH ||
	    buflen == KYRKA_ED25519_SIGN_SECRET_LENGTH);

	if ((fd = kyrka_file_open(ctx, path)) == -1)
		return (-1);

	if (nyfe_file_read(fd, buf, buflen) != buflen) {
		(void)close(fd);
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		kyrka_logmsg(ctx, "failed to read key '%s'", path);
		return (-1);
	}

	kyrka_mask(ctx, buf, buflen);

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
	PRECOND(ctx->offer.local.spi == 0);

	if (now < ctx->offer.next)
		return (0);

	offer_now = 0;
	reason = NULL;

	if (ctx->offer.force) {
		offer_now = 1;
		reason = "re-sync";
		ctx->offer.force = 0;
	} else if (ctx->rx.spi != 0) {
		ctx->offer.default_ttl = 15;
		ctx->offer.default_next_send = 1;

		if (ctx->rx.pkt > KYRKA_SA_PACKET_SOFT) {
			offer_now = 1;
			reason = "SA packet limit";
		} else if ((now - ctx->rx.age) > KYRKA_SA_LIFETIME_SOFT) {
			offer_now = 1;
			reason = "SA age limit";
		} else if (ctx->flags & KYRKA_FLAG_AMBRY_NEGOTIATION) {
			offer_now = 1;
			reason = "new ambry";
		}
	} else {
		offer_now = 1;
		reason = "no keys";
	}

	if (offer_now == 0)
		return (0);

	ctx->flags &= ~KYRKA_FLAG_AMBRY_NEGOTIATION;

	if (ctx->offer.local.spi != 0)
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
	PRECOND(ctx->offer.local.spi == 0);

	kyrka_random_bytes(&ctx->offer.local.spi,
	    sizeof(ctx->offer.local.spi));
	kyrka_random_bytes(&ctx->offer.local.salt,
	    sizeof(ctx->offer.local.salt));

	kyrka_random_bytes(ctx->offer.local.random,
	    sizeof(ctx->offer.local.random));
	kyrka_random_bytes(ctx->offer.remote.random,
	    sizeof(ctx->offer.remote.random));

	if (ctx->cfg.spi != 0) {
		ctx->offer.local.spi = (ctx->offer.local.spi & 0x0000ffff) |
		    ((u_int32_t)ctx->cfg.spi << 16);
	}

	kyrka_mlkem1024_keypair(&ctx->offer.local.kem);

	if (kyrka_asymmetry_keygen(ctx->offer.local.private,
	    sizeof(ctx->offer.local.private), ctx->offer.local.public,
	    sizeof(ctx->offer.local.public)) == -1) {
		nyfe_mem_zero(&ctx->offer, sizeof(ctx->offer));
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		kyrka_logmsg(ctx,
		    "failed to generate a local keypair for the key exchange");
		return (-1);
	}

	if (kyrka_asymmetry_keygen(ctx->offer.remote.private,
	    sizeof(ctx->offer.remote.private), ctx->offer.remote.public,
	    sizeof(ctx->offer.remote.public)) == -1) {
		nyfe_mem_zero(&ctx->offer, sizeof(ctx->offer));
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		kyrka_logmsg(ctx,
		    "failed to generate a remote keypair for the key exchange");
		return (-1);
	}

	ctx->offer.pulse = now;
	ctx->offer.ttl = ctx->offer.default_ttl;
	ctx->offer.flags = KYRKA_OFFER_INCLUDE_KEM_PK;

	return (0);
}

/*
 * Send the current active offer to our peer via the purgatory interface.
 */
static int
key_offer_send(struct kyrka *ctx, u_int64_t now)
{
	u_int8_t	frag;

	PRECOND(ctx != NULL);
	PRECOND(ctx->purgatory.send != NULL);

	ctx->offer.ttl--;
	ctx->offer.pulse = now + ctx->offer.default_next_send;

	if (ctx->offer.flags & KYRKA_OFFER_INCLUDE_KEM_PK) {
		for (frag = 0; frag < KYRKA_OFFER_KEM_FRAGMENTS; frag++) {
			if (key_offer_send_fragment(ctx,
			    KYRKA_OFFER_INCLUDE_KEM_PK, frag) == -1)
				return (-1);
		}
	}

	if (ctx->offer.flags & KYRKA_OFFER_INCLUDE_KEM_CT) {
		for (frag = 0; frag < KYRKA_OFFER_KEM_FRAGMENTS; frag++) {
			if (key_offer_send_fragment(ctx,
			    KYRKA_OFFER_INCLUDE_KEM_CT, frag) == -1)
				return (-1);
		}
	}

	if (ctx->offer.ttl == 0)
		key_offer_clear(ctx);

	return (0);
}

/*
 * Send a fragment of the requested packet to our peer.
 */
static int
key_offer_send_fragment(struct kyrka *ctx, int which, u_int8_t frag)
{
	struct kyrka_packet		pkt;
	struct kyrka_key		okm;
	struct kyrka_offer		*op;
	u_int8_t			*ptr;
	struct kyrka_xchg_info		*info;
	size_t				offset;
	struct kyrka_exchange_offer	*exchange;

	PRECOND(ctx != NULL);
	PRECOND(which == KYRKA_OFFER_INCLUDE_KEM_PK ||
	    which == KYRKA_OFFER_INCLUDE_KEM_CT);
	PRECOND(frag < KYRKA_OFFER_KEM_FRAGMENTS);

	if (which == KYRKA_OFFER_INCLUDE_KEM_CT)
		info = &ctx->offer.remote;
	else
		info = &ctx->offer.local;

	op = kyrka_offer_init(&pkt, ctx->offer.local.spi,
	    KYRKA_KEY_OFFER_MAGIC, KYRKA_OFFER_TYPE_EXCHANGE);

	if (ctx->flags & KYRKA_FLAG_CATHEDRAL_CONFIG) {
		op->hdr.flock_src = htobe64(ctx->cathedral.flock_src);
		op->hdr.flock_dst = htobe64(ctx->cathedral.flock_dst);
	}

	nyfe_zeroize_register(&okm, sizeof(okm));

	kyrka_mask(ctx, ctx->cfg.secret, sizeof(ctx->cfg.secret));
	kyrka_offer_kdf(ctx, ctx->cfg.secret, sizeof(ctx->cfg.secret),
	    KYRKA_CHAPEL_DERIVE_LABEL, &okm, op->hdr.seed, sizeof(op->hdr.seed),
	    ctx->cathedral.flock_src, ctx->cathedral.flock_dst);
	kyrka_mask(ctx, ctx->cfg.secret, sizeof(ctx->cfg.secret));

	exchange = &op->data.offer.exchange;

	exchange->fragment = frag;
	exchange->salt = info->salt;
	exchange->spi = htobe32(info->spi);
	exchange->id = htobe64(ctx->local_id);

	nyfe_memcpy(exchange->ecdh, info->public, sizeof(info->public));
	nyfe_memcpy(op->extra.random, info->random, sizeof(info->random));

	offset = frag * KYRKA_OFFER_KEM_FRAGMENT_SIZE;

	if (which == KYRKA_OFFER_INCLUDE_KEM_CT) {
		exchange->state = KYRKA_OFFER_STATE_KEM_CT_FRAGMENT;
		nyfe_memcpy(exchange->kem, &ctx->offer.remote.kem.ct[offset],
		    KYRKA_OFFER_KEM_FRAGMENT_SIZE);
	} else {
		exchange->state = KYRKA_OFFER_STATE_KEM_PK_FRAGMENT;
		nyfe_memcpy(exchange->kem, &ctx->offer.local.kem.pk[offset],
		    KYRKA_OFFER_KEM_FRAGMENT_SIZE);
	}

	if (kyrka_offer_encrypt(&okm, op) == -1) {
		nyfe_zeroize(&okm, sizeof(okm));
		return (-1);
	}

	nyfe_zeroize(&okm, sizeof(okm));

	ptr = kyrka_packet_tx_finalize(ctx, &pkt);
	ctx->purgatory.send(ptr, pkt.length, 0, ctx->purgatory.udata);

	return (0);
}

/*
 * Performing a key exchange boils down to the following:
 *
 *	Both sides start by sending out offerings that contain an ML-KEM-1024
 *	public key and an x25519 public key.
 *
 *	Both sides upon receiving these offerings will perform ML-KEM-1024
 *	encapsulation and send back the ciphertext and their own x25519
 *	public key which differs from the one sent in the initial offering.
 *
 *	When a side performs encapsulation it will derive a fresh
 *	RX session key using all of that key material and install the
 *	key as a pending RX key.
 *
 *	When a side performs decapsulation it will derive a fresh
 *	TX session key using all of that key material and install the
 *	key as the active TX key.
 *
 * In both cases this results in unique shared secrets for x25519
 * and ML-KEM-1024 in each direction, while allowing us to gracefully
 * install pending RX keys so that we do not miss a beat.
 */
static void
key_exchange(struct kyrka *ctx, struct kyrka_offer *op)
{
	struct timespec			ts;
	struct kyrka_exchange_offer	*exchange;

	PRECOND(ctx != NULL);
	PRECOND(op != NULL);

	exchange = &op->data.offer.exchange;
	exchange->spi = be32toh(exchange->spi);

	if (exchange->spi == 0) {
		kyrka_logmsg(ctx, "peer sent invalid spi of 0x00");
		return;
	}

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);

	switch (exchange->state) {
	case KYRKA_OFFER_STATE_KEM_PK_FRAGMENT:
		key_exchange_encapsulate(ctx, op, ts.tv_sec);
		break;
	case KYRKA_OFFER_STATE_KEM_CT_FRAGMENT:
		key_exchange_decapsulate(ctx, op, ts.tv_sec);
		break;
	default:
		kyrka_logmsg(ctx, "ignoring unknown offer packet");
		break;
	}

	ctx->peer_id = exchange->id;
}

/*
 * We received a PK fragment from our peer. We copy it into the correct
 * place (offer->remote.kem.pk) and if we received all fragments we
 * do ML-KEM-1024-ENCAP(). This will create a ciphertext which we
 * will send out next time we pulse out offers (OFFER_INCLUDE_KEM_CT).
 *
 * The resulting secret is then installed as the RX key.
 */
static void
key_exchange_encapsulate(struct kyrka *ctx, struct kyrka_offer *op, time_t now)
{
	size_t				off;
	struct kyrka_exchange_offer	*xchg;

	PRECOND(ctx != NULL);
	PRECOND(op != NULL);

	xchg = &op->data.offer.exchange;

	if (xchg->spi == ctx->last_spi)
		return;

	if (ctx->offer.local.spi == 0) {
		if (key_offer_create(ctx, now) == -1)
			return;
	}

	if (ctx->offer.pk_frag == KYRKA_OFFER_KEM_FRAGMENTS_DONE) {
		if (xchg->id != ctx->peer_id && ctx->offer.local.spi != 0) {
			key_offer_clear(ctx);
			if (key_offer_create(ctx, now) == -1)
				return;
		} else {
			return;
		}
	}

	if (xchg->fragment >= KYRKA_OFFER_KEM_FRAGMENTS)
		return;

	if (ctx->offer.pk_frag & (1 << xchg->fragment))
		return;

	off = xchg->fragment * KYRKA_OFFER_KEM_FRAGMENT_SIZE;
	nyfe_memcpy(&ctx->offer.remote.kem.pk[off],
	    xchg->kem, sizeof(xchg->kem));

	ctx->offer.pk_frag |= (1 << xchg->fragment);
	if (ctx->offer.pk_frag != KYRKA_OFFER_KEM_FRAGMENTS_DONE)
		return;

	ctx->offer.remote.spi = xchg->spi;
	ctx->offer.remote.salt = xchg->salt;
	ctx->offer.ttl = ctx->offer.default_ttl;
	ctx->offer.flags |= KYRKA_OFFER_INCLUDE_KEM_CT;

	ctx->last_spi = xchg->spi;
	kyrka_mlkem1024_encapsulate(&ctx->offer.remote.kem);
	key_exchange_finalize(ctx, op, now, KYRKA_KEY_DIRECTION_RX);
}

/*
 * We received the encapsulated secret as ciphertext. We will do
 * ML-KEM-1024-DECAP() using our secret key.
 *
 * The resulting secret is then installed as the TX session key.
 */
static void
key_exchange_decapsulate(struct kyrka *ctx, struct kyrka_offer *op, time_t now)
{
	size_t				off;
	struct kyrka_exchange_offer	*xchg;

	PRECOND(ctx != NULL);
	PRECOND(op != NULL);

	if (ctx->offer.local.spi == 0 || ctx->offer.remote.spi == 0)
		return;

	xchg = &op->data.offer.exchange;

	if (xchg->spi != ctx->offer.local.spi) {
		key_offer_clear(ctx);
		ctx->offer.force = 1;
		return;
	}

	if (!(ctx->offer.flags & KYRKA_OFFER_INCLUDE_KEM_PK))
		return;

	if (ctx->offer.ct_frag & (1 << xchg->fragment))
		return;

	if (xchg->fragment >= KYRKA_OFFER_KEM_FRAGMENTS)
		return;

	off = xchg->fragment * KYRKA_OFFER_KEM_FRAGMENT_SIZE;
	nyfe_memcpy(&ctx->offer.local.kem.ct[off],
	    xchg->kem, sizeof(xchg->kem));

	ctx->offer.ct_frag |= (1 << xchg->fragment);
	if (ctx->offer.ct_frag != KYRKA_OFFER_KEM_FRAGMENTS_DONE)
		return;

	ctx->offer.flags &= ~KYRKA_OFFER_INCLUDE_KEM_PK;
	kyrka_mlkem1024_decapsulate(&ctx->offer.local.kem);
	key_exchange_finalize(ctx, op, now, KYRKA_KEY_DIRECTION_TX);
}

/*
 * Derive a new session key for the given direction based upon the
 * shared secrets we negotiated, in combination with a derivative
 * of our shared symmetrical secret.
 */
static void
key_exchange_finalize(struct kyrka *ctx, struct kyrka_offer *op,
    time_t now, u_int8_t dir)
{
	union kyrka_event		evt;
	struct kyrka_kex		kex;
	struct kyrka_xchg_info		*info;
	struct kyrka_exchange_offer	*exchange;
	u_int8_t			okm[KYRKA_KEY_LENGTH];

	PRECOND(ctx != NULL);
	PRECOND(op != NULL);
	PRECOND(ctx->offer.local.spi != 0);
	PRECOND(dir == KYRKA_KEY_DIRECTION_RX || dir == KYRKA_KEY_DIRECTION_TX);

	exchange = &op->data.offer.exchange;

	nyfe_zeroize_register(okm, sizeof(okm));
	nyfe_zeroize_register(&kex, sizeof(kex));

	nyfe_memcpy(kex.remote, exchange->ecdh, sizeof(exchange->ecdh));

	if (dir == KYRKA_KEY_DIRECTION_RX) {
		info = &ctx->offer.remote;
		nyfe_memcpy(kex.kem, ctx->offer.remote.kem.ss, sizeof(kex.kem));
	} else {
		info = &ctx->offer.local;
		nyfe_memcpy(kex.kem, ctx->offer.local.kem.ss, sizeof(kex.kem));
	}

	nyfe_memcpy(kex.private, info->private, sizeof(info->private));

	if (exchange->id < ctx->local_id) {
		nyfe_memcpy(kex.pub1, info->public, sizeof(info->public));
		nyfe_memcpy(kex.pub2, exchange->ecdh, sizeof(exchange->ecdh));

		nyfe_memcpy(kex.random, info->random, sizeof(info->random));
		nyfe_memcpy(&kex.random[sizeof(info->random)],
		    op->extra.random, sizeof(op->extra.random));

		if (dir == KYRKA_KEY_DIRECTION_RX)
			kex.purpose = KYRKA_KDF_PURPOSE_KEY_TRAFFIC_RX;
		else
			kex.purpose = KYRKA_KDF_PURPOSE_KEY_TRAFFIC_TX;
	} else {
		nyfe_memcpy(kex.pub1, exchange->ecdh, sizeof(exchange->ecdh));
		nyfe_memcpy(kex.pub2, info->public, sizeof(info->public));

		nyfe_memcpy(kex.random, op->extra.random,
		    sizeof(op->extra.random));
		nyfe_memcpy(&kex.random[sizeof(op->extra.random)],
		    info->random, sizeof(info->random));

		if (dir == KYRKA_KEY_DIRECTION_RX)
			kex.purpose = KYRKA_KDF_PURPOSE_KEY_TRAFFIC_TX;
		else
			kex.purpose = KYRKA_KDF_PURPOSE_KEY_TRAFFIC_RX;
	}

	if (kyrka_traffic_kdf(ctx, &kex, okm, sizeof(okm)) == -1)
		goto cleanup;

	if (dir == KYRKA_KEY_DIRECTION_RX) {
		if (key_make_active(&ctx->rx,
		    &ctx->offer.local, okm, sizeof(okm), now) == -1)
			goto cleanup;
	} else {
		if (key_make_active(&ctx->tx,
		    &ctx->offer.remote, okm, sizeof(okm), now) == -1)
			goto cleanup;
	}

	if (ctx->event != NULL) {
		evt.type = KYRKA_EVENT_KEYS_INFO;
		evt.keys.tx_spi = ctx->tx.spi;
		evt.keys.rx_spi = ctx->rx.spi;
		evt.keys.peer_id = exchange->id;
		ctx->event(ctx, &evt, ctx->udata);
	}

cleanup:
	nyfe_zeroize(okm, sizeof(okm));
	nyfe_zeroize(&kex, sizeof(kex));
}

/*
 * Clear the pending current offer.
 */
static void
key_offer_clear(struct kyrka *ctx)
{
	union kyrka_event	evt;

	PRECOND(ctx != NULL);
	PRECOND(ctx->offer.local.spi != 0);

	nyfe_mem_zero(&ctx->offer, sizeof(ctx->offer));

	ctx->last_spi = 0;
	ctx->offer.default_ttl = 15;
	ctx->offer.default_next_send = 1;

	if (ctx->event != NULL) {
		evt.type = KYRKA_EVENT_EXCHANGE_INFO;
		evt.exchange.reason = "key offer cleared";
		ctx->event(ctx, &evt, ctx->udata);
	}
}

/*
 * Make the given key material active in the specified SA by
 * allocating a new cipher context and install it into the SA.
 *
 * We reset all stats and counters after doing so.
 */
static int
key_make_active(struct kyrka_sa *sa, struct kyrka_xchg_info *info,
    const u_int8_t *key, size_t len, time_t now)
{
	struct kyrka_cipher		*next;

	PRECOND(sa != NULL);
	PRECOND(info != NULL);
	PRECOND(key != NULL);
	PRECOND(len == KYRKA_KEY_LENGTH);

	if ((next = kyrka_cipher_setup(key, len)) == NULL)
		return (-1);

	if (sa->cipher != NULL)
		kyrka_cipher_cleanup(sa->cipher);

	sa->pkt = 0;
	sa->seqnr = 1;
	sa->bitmap = 0;

	sa->age = now;
	sa->cipher = next;
	sa->spi = info->spi;
	sa->salt = info->salt;

	return (0);
}
