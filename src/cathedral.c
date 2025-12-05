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
#include <unistd.h>

#include "libkyrka-int.h"

/* The half-time a cathedral offer is valid. */
#define CATHEDRAL_OFFER_VALID		10

static int	cathedral_send_offer(struct kyrka *, u_int64_t);
static void	cathedral_p2p_recv(struct kyrka *, struct kyrka_offer *);
static void	cathedral_liturgy_recv(struct kyrka *, struct kyrka_offer *);
static void	cathedral_ambry_recv(struct kyrka *, struct kyrka_offer *);
static void	cathedral_remembrance_recv(struct kyrka *,
		    struct kyrka_offer *);
static void	cathedral_ambry_unwrap(struct kyrka *,
		    struct kyrka_ambry_offer *);
static void	*cathedral_ambry_key_derive(struct kyrka *,
		    struct kyrka_ambry_offer *);

/*
 * Configure the use of a cathedral. You must specify the cathedral secret
 * that is bound to your cathedral identity, your device KEK, the flock
 * and what tunnel we are representing.
 *
 * You specify the callback that is to be used for sending out the
 * cathedral packets.
 *
 * Note that the cathedral secret and device KEK paths may be NULL
 * if you want to load them via kyrka_cathedral_secret_load() and
 * kyrka_device_kek_load().
 */
int
kyrka_cathedral_config(struct kyrka *ctx, struct kyrka_cathedral_cfg *cfg)
{
	if (ctx == NULL)
		return (-1);

	if (cfg == NULL) {
		ctx->last_error = KYRKA_ERROR_PARAMETER;
		return (-1);
	}

	if (cfg->flock_src == 0 || cfg->tunnel == 0 ||
	    cfg->identity == 0 || cfg->send == NULL) {
		ctx->last_error = KYRKA_ERROR_PARAMETER;
		return (-1);
	}

	ctx->cfg.spi = cfg->tunnel;
	ctx->cathedral.group = cfg->group;
	ctx->cathedral.ifc.send = cfg->send;
	ctx->cathedral.hidden = cfg->hidden;
	ctx->cathedral.ifc.udata = cfg->udata;
	ctx->cathedral.identity = cfg->identity;
	ctx->cathedral.flock_src = cfg->flock_src;
	ctx->cathedral.remembrance = cfg->remembrance;

	if (cfg->flock_dst != 0)
		ctx->cathedral.flock_dst = cfg->flock_dst;
	else
		ctx->cathedral.flock_dst = ctx->cathedral.flock_src;

	if (cfg->secret != NULL) {
		if (kyrka_key_load_from_path(ctx, cfg->secret,
		    ctx->cathedral.secret, sizeof(ctx->cathedral.secret)) == -1)
			return (-1);

		ctx->flags |= KYRKA_FLAG_CATHEDRAL_SECRET;
	}

	if (cfg->kek != NULL) {
		if (kyrka_key_load_from_path(ctx, cfg->kek,
		    ctx->cfg.kek, sizeof(ctx->cfg.kek)) == -1)
			return (-1);

		ctx->flags |= KYRKA_FLAG_DEVICE_KEK;
	}

	if (cfg->cosk != NULL) {
		if (kyrka_key_load_from_path(ctx, cfg->cosk,
		    ctx->cathedral.sk, sizeof(ctx->cathedral.sk)) == -1)
			return (-1);

		ctx->flags |= KYRKA_FLAG_CATHEDRAL_SIGNING_KEY;
	}

	ctx->flags |= KYRKA_FLAG_CATHEDRAL_CONFIG;

	return (0);
}

/*
 * Generates a KATEDRAL message for the configured cathedral and gives
 * the packet to the cathedral callback allowing the caller to send
 * it to the cathedral by whatever means.
 */
int
kyrka_cathedral_notify(struct kyrka *ctx)
{
	if (ctx == NULL)
		return (-1);

	if (!(ctx->flags & KYRKA_FLAG_CATHEDRAL_CONFIG)) {
		ctx->last_error = KYRKA_ERROR_NO_CONFIG;
		return (-1);
	}

	if (!(ctx->flags & KYRKA_FLAG_CATHEDRAL_SECRET)) {
		ctx->last_error = KYRKA_ERROR_NO_SECRET;
		return (-1);
	}

	if (!(ctx->flags & KYRKA_FLAG_CATHEDRAL_SIGNING_KEY)) {
		ctx->last_error = KYRKA_ERROR_NO_COSK;
		return (-1);
	}

	return (cathedral_send_offer(ctx, KYRKA_CATHEDRAL_MAGIC));
}

/*
 * Generates a KATEDRAL NAT message for the configured cathedral and gives
 * the packet to the cathedral callback allowing the caller to send
 * it to the cathedral by whatever means.
 */
int
kyrka_cathedral_nat_detection(struct kyrka *ctx)
{
	if (ctx == NULL)
		return (-1);

	if (!(ctx->flags & KYRKA_FLAG_CATHEDRAL_CONFIG)) {
		ctx->last_error = KYRKA_ERROR_NO_CONFIG;
		return (-1);
	}

	if (!(ctx->flags & KYRKA_FLAG_CATHEDRAL_SECRET)) {
		ctx->last_error = KYRKA_ERROR_NO_SECRET;
		return (-1);
	}

	if (!(ctx->flags & KYRKA_FLAG_CATHEDRAL_SIGNING_KEY)) {
		ctx->last_error = KYRKA_ERROR_NO_COSK;
		return (-1);
	}

	return (cathedral_send_offer(ctx, KYRKA_CATHEDRAL_NAT_MAGIC));
}

/*
 * Generates a LITURGY message for the configured cathedral and
 * gives the packet to the cathedral callback allowing the caller
 * to send it to the cathedral by whatever means.
 *
 * The given peers argument is either NULL to be interested in all
 * peers, or an array of 256 bytes indicating which peers one is
 * interested in.
 */
int
kyrka_cathedral_liturgy(struct kyrka *ctx, u_int8_t *peers, size_t len)
{
	if (ctx == NULL)
		return (-1);

	if ((peers == NULL && len != 0) ||
	    (peers != NULL && len != sizeof(ctx->cathedral.peers))) {
		ctx->last_error = KYRKA_ERROR_PARAMETER;
		return (-1);
	}

	if (!(ctx->flags & KYRKA_FLAG_CATHEDRAL_CONFIG)) {
		ctx->last_error = KYRKA_ERROR_NO_CONFIG;
		return (-1);
	}

	if (!(ctx->flags & KYRKA_FLAG_CATHEDRAL_SECRET)) {
		ctx->last_error = KYRKA_ERROR_NO_SECRET;
		return (-1);
	}

	if (peers != NULL) {
		nyfe_memcpy(ctx->cathedral.peers,
		    peers, sizeof(ctx->cathedral.peers));
		ctx->cathedral.liturgy_flags = KYRKA_LITURGY_FLAG_SIGNALING;
	} else {
		ctx->cathedral.liturgy_flags = 0;
		memset(ctx->cathedral.peers, 1, sizeof(ctx->cathedral.peers));
	}

	return (cathedral_send_offer(ctx, KYRKA_CATHEDRAL_LITURGY_MAGIC));
}

/*
 * Internal function to help decrypt a cathedral message that arrived
 * from the purgatory side via kyrka_purgatory_input().
 */
int
kyrka_cathedral_decrypt(struct kyrka *ctx, const void *data, size_t len)
{
	struct kyrka_key	okm;
	struct kyrka_offer	offer;

	PRECOND(ctx != NULL);
	PRECOND(data != NULL);

	if (!(ctx->flags & KYRKA_FLAG_CATHEDRAL_CONFIG) ||
	    !(ctx->flags & KYRKA_FLAG_CATHEDRAL_SECRET)) {
		ctx->last_error = KYRKA_ERROR_CATHEDRAL_CONFIG;
		return (-1);
	}

	if (len < sizeof(offer)) {
		kyrka_logmsg(ctx,
		    "got a cathedral packet of suspicious size (%zu)", len);
		return (0);
	}

	nyfe_zeroize_register(&okm, sizeof(okm));
	nyfe_zeroize_register(&offer, sizeof(offer));

	nyfe_memcpy(&offer, data, sizeof(offer));

	kyrka_mask(ctx, ctx->cathedral.secret, sizeof(ctx->cathedral.secret));
	kyrka_offer_kdf(ctx, ctx->cathedral.secret,
	    sizeof(ctx->cathedral.secret), KYRKA_CATHEDRAL_KDF_LABEL,
	    &okm, offer.hdr.seed, sizeof(offer.hdr.seed),
	    ctx->cathedral.flock_src, 0);
	kyrka_mask(ctx, ctx->cathedral.secret, sizeof(ctx->cathedral.secret));

	if (kyrka_offer_decrypt(&okm, &offer, CATHEDRAL_OFFER_VALID) == -1)
		goto cleanup;

	offer.hdr.spi = be32toh(offer.hdr.spi);
	if (offer.hdr.spi != ctx->cathedral.identity) {
		kyrka_logmsg(ctx,
		    "got a cathedral packet (%02x) not ment for us (%08x)",
		    offer.data.type, offer.hdr.spi);
		goto cleanup;
	}

	switch (offer.data.type) {
	case KYRKA_OFFER_TYPE_AMBRY:
		/* We return an error here if the device KEK is missing. */
		if (!(ctx->flags & KYRKA_FLAG_DEVICE_KEK)) {
			nyfe_zeroize(&okm, sizeof(okm));
			nyfe_zeroize(&offer, sizeof(offer));
			ctx->last_error = KYRKA_ERROR_CATHEDRAL_CONFIG;
			return (-1);
		}
		cathedral_ambry_recv(ctx, &offer);
		break;
	case KYRKA_OFFER_TYPE_INFO:
		cathedral_p2p_recv(ctx, &offer);
		break;
	case KYRKA_OFFER_TYPE_LITURGY:
		cathedral_liturgy_recv(ctx, &offer);
		break;
	case KYRKA_OFFER_TYPE_REMEMBRANCE:
		cathedral_remembrance_recv(ctx, &offer);
		break;
	}

cleanup:
	nyfe_zeroize(&okm, sizeof(okm));
	nyfe_zeroize(&offer, sizeof(offer));

	return (0);
}

/*
 * Send an offer packet to the cathedral which is one of two choices:
 *	1) info, containing our amry generation and tunnel.
 *	2) liturgy, containing our tunnel id.
 */
static int
cathedral_send_offer(struct kyrka *ctx, u_int64_t magic)
{
	struct kyrka_packet		pkt;
	struct kyrka_offer		*op;
	struct kyrka_key		okm;
	struct kyrka_info_offer		*info;
	struct kyrka_liturgy_offer	*liturgy;
	u_int8_t			type, *ptr;

	PRECOND(ctx != NULL);
	PRECOND(ctx->flags & KYRKA_FLAG_CATHEDRAL_CONFIG);
	PRECOND(ctx->flags & KYRKA_FLAG_CATHEDRAL_SECRET);
	PRECOND(ctx->flags & KYRKA_FLAG_CATHEDRAL_SIGNING_KEY);
	PRECOND(ctx->cathedral.ifc.send != NULL);
	PRECOND(magic == KYRKA_CATHEDRAL_MAGIC ||
	    magic == KYRKA_CATHEDRAL_NAT_MAGIC ||
	    magic == KYRKA_CATHEDRAL_LITURGY_MAGIC);

	switch (magic) {
	case KYRKA_CATHEDRAL_MAGIC:
		type = KYRKA_OFFER_TYPE_INFO;
		break;
	case KYRKA_CATHEDRAL_NAT_MAGIC:
		type = KYRKA_OFFER_TYPE_INFO;
		break;
	case KYRKA_CATHEDRAL_LITURGY_MAGIC:
		magic = KYRKA_CATHEDRAL_MAGIC;
		type = KYRKA_OFFER_TYPE_LITURGY;
		break;
	default:
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		kyrka_logmsg(ctx,
		    "failed to send offer to cathedral, invalid magic");
		return (-1);
	}

	op = kyrka_offer_init(&pkt, ctx->cathedral.identity, magic, type);
	op->hdr.flock_src = htobe64(ctx->cathedral.flock_src);

	if (type != KYRKA_OFFER_TYPE_LITURGY) {
		op->hdr.flock_dst = htobe64(ctx->cathedral.flock_dst);

		info = &op->data.offer.info;
		nyfe_mem_zero(info, sizeof(*info));

		info->tunnel = htobe16(ctx->cfg.spi);
		info->instance = htobe64(ctx->local_id);
		info->ambry_generation = htobe32(ctx->cathedral.ambry);
		info->rx_active = ctx->rx.spi;
		info->rx_pending = ctx->rx.spi;

		if (ctx->cathedral.remembrance)
			info->flags = KYRKA_INFO_FLAG_REMEMBRANCE;
	} else {
		op->hdr.flock_dst = 0;

		liturgy = &op->data.offer.liturgy;
		nyfe_mem_zero(liturgy, sizeof(*liturgy));

		liturgy->id = ctx->cfg.spi;
		liturgy->group = htobe16(ctx->cathedral.group);
		liturgy->hidden = ctx->cathedral.hidden;

		if (ctx->cathedral.remembrance)
			liturgy->flags = KYRKA_LITURGY_FLAG_REMEMBRANCE;

		liturgy->flags |= ctx->cathedral.liturgy_flags;

		nyfe_memcpy(liturgy->peers,
		    ctx->cathedral.peers, sizeof(liturgy->peers));
	}

	nyfe_zeroize_register(&okm, sizeof(okm));

	kyrka_mask(ctx, ctx->cathedral.secret, sizeof(ctx->cathedral.secret));
	kyrka_offer_kdf(ctx, ctx->cathedral.secret,
	    sizeof(ctx->cathedral.secret), KYRKA_CATHEDRAL_KDF_LABEL, &okm,
	    op->hdr.seed, sizeof(op->hdr.seed), ctx->cathedral.flock_src, 0);
	kyrka_mask(ctx, ctx->cathedral.secret, sizeof(ctx->cathedral.secret));

	if (kyrka_offer_sign(ctx, op) == -1 ||
	    kyrka_offer_encrypt(&okm, op) == -1) {
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		nyfe_zeroize(&okm, sizeof(okm));
		return (-1);
	}

	nyfe_zeroize(&okm, sizeof(okm));

	ptr = kyrka_packet_tx_finalize(ctx, &pkt);
	ctx->cathedral.ifc.send(ptr,
	    pkt.length, magic, ctx->cathedral.ifc.udata);

	return (0);
}

/*
 * We received a p2p message from the cathedral with information about
 * our peer its ip:port and we can use that to establish a p2p connection.
 */
static void
cathedral_p2p_recv(struct kyrka *ctx, struct kyrka_offer *op)
{
	union kyrka_event		evt;
	struct kyrka_info_offer		*info;

	PRECOND(ctx != NULL);
	PRECOND(op != NULL);
	PRECOND(op->data.type == KYRKA_OFFER_TYPE_INFO);
	PRECOND(ctx->flags & KYRKA_FLAG_CATHEDRAL_CONFIG);
	PRECOND(ctx->flags & KYRKA_FLAG_CATHEDRAL_SECRET);

	if (ctx->event == NULL)
		return;

	info = &op->data.offer.info;
	if (info->peer_ip == info->local_ip)
		return;

	evt.type = KYRKA_EVENT_PEER_DISCOVERY;
	evt.peer.ip = info->peer_ip;
	evt.peer.port = info->peer_port;

	ctx->event(ctx, &evt, ctx->udata);
}

/*
 * We received a response to a liturgy request. Call the event callback
 * with the liturgy information.
 */
static void
cathedral_liturgy_recv(struct kyrka *ctx, struct kyrka_offer *op)
{
	union kyrka_event		evt;
	struct kyrka_liturgy_offer	*liturgy;

	PRECOND(ctx != NULL);
	PRECOND(op != NULL);
	PRECOND(op->data.type == KYRKA_OFFER_TYPE_LITURGY);

	if (ctx->event == NULL)
		return;

	liturgy = &op->data.offer.liturgy;
	liturgy->group = be16toh(liturgy->group);

	if (liturgy->group != ctx->cathedral.group)
		return;

	evt.type = KYRKA_EVENT_LITURGY_RECEIVED;
	memcpy(evt.liturgy.peers, liturgy->peers, sizeof(liturgy->peers));

	ctx->event(ctx, &evt, ctx->udata);
}

/*
 * We received a remembrance update from the cathedral. Pass the received
 * addresses and whatnot directly to the event callback if set.
 */
static void
cathedral_remembrance_recv(struct kyrka *ctx, struct kyrka_offer *op)
{
	int				i;
	union kyrka_event		evt;
	struct kyrka_remembrance_offer	*data;

	PRECOND(ctx != NULL);
	PRECOND(op != NULL);
	PRECOND(op->data.type == KYRKA_OFFER_TYPE_REMEMBRANCE);

	if (ctx->event == NULL)
		return;

	data = &op->data.offer.remembrance;
	evt.type = KYRKA_EVENT_REMEMBRANCE_RECEIVED;

	for (i = 0; i < KYRKA_CATHEDRALS_MAX; i++) {
		evt.remembrance.ips[i] = data->ips[i];
		evt.remembrance.ports[i] = data->ports[i];
	}

	ctx->event(ctx, &evt, ctx->udata);
}

/*
 * We received an ambry update from the cathedral. We do some initial
 * sanity checking on it before attempting to unwrap it with our KEK.
 */
static void
cathedral_ambry_recv(struct kyrka *ctx, struct kyrka_offer *op)
{
	struct kyrka_offer_data		*data;
	u_int16_t			tunnel;
	u_int32_t			generation;

	PRECOND(ctx != NULL);
	PRECOND(op != NULL);
	PRECOND(op->data.type == KYRKA_OFFER_TYPE_AMBRY);
	PRECOND(ctx->flags & KYRKA_FLAG_CATHEDRAL_CONFIG);
	PRECOND(ctx->flags & KYRKA_FLAG_DEVICE_KEK);

	data = &op->data;
	tunnel = be16toh(data->offer.ambry.tunnel);
	generation = be32toh(data->offer.ambry.generation);

	if (tunnel != ctx->cfg.spi) {
		kyrka_logmsg(ctx,
		    "got an ambry not ment for us (%04x)", tunnel);
		return;
	}

	if (generation == ctx->cathedral.ambry) {
		kyrka_logmsg(ctx,
		    "duplicate ambry generation %08x from cathedral",
		    ctx->cathedral.ambry);
		return;
	}

	cathedral_ambry_unwrap(ctx, &data->offer.ambry);
}

/*
 * Verify the integrity and unwrap the given ambry entry with our KEK, if
 * it worked we will install the secret held within as our new shared secret.
 */
static void
cathedral_ambry_unwrap(struct kyrka *ctx, struct kyrka_ambry_offer *ambry)
{
	struct timespec			ts;
	union kyrka_event		evt;
	struct kyrka_ambry_aad		aad;
	struct kyrka_cipher		cipher;
	time_t				expires;
	u_int8_t			nonce[KYRKA_NONCE_LENGTH];

	PRECOND(ctx != NULL);
	PRECOND(ambry != NULL);
	PRECOND(ctx->flags & KYRKA_FLAG_CATHEDRAL_CONFIG);
	PRECOND(ctx->flags & KYRKA_FLAG_DEVICE_KEK);

	if ((cipher.ctx = cathedral_ambry_key_derive(ctx, ambry)) == NULL)
		return;

	aad.expires = ambry->expires;
	aad.tunnel = htobe16(ctx->cfg.spi);
	aad.generation = ambry->generation;
	aad.flock_src = htobe64(ctx->cathedral.flock_src & ~(0xff));
	aad.flock_dst = htobe64(ctx->cathedral.flock_dst & ~(0xff));

	nyfe_memcpy(aad.seed, ambry->seed, sizeof(ambry->seed));

	cipher.aad = &aad;
	cipher.aad_len = sizeof(aad);

	cipher.nonce = nonce;
	cipher.nonce_len = sizeof(nonce);
	kyrka_offer_nonce(nonce, sizeof(nonce));

	cipher.ct = ambry->key;
	cipher.pt = ambry->key;
	cipher.tag = &ambry->tag[0];
	cipher.data_len = sizeof(ambry->key);

	if (kyrka_cipher_decrypt(&cipher) == -1) {
		kyrka_cipher_cleanup(cipher.ctx);
		kyrka_logmsg(ctx, "ambry integrity check failed");
		return;
	}

	kyrka_cipher_cleanup(cipher.ctx);

	ambry->expires = be16toh(ambry->expires);
	ambry->generation = be32toh(ambry->generation);

	expires = (time_t)KYRKA_AMBRY_AGE_EPOCH +
	    ((time_t)ambry->expires * KYRKA_AMBRY_AGE_SECONDS_PER_DAY);

	(void)clock_gettime(CLOCK_REALTIME, &ts);
	if (expires < ts.tv_sec) {
		kyrka_logmsg(ctx, "ambry generation 0x%08x is expired",
		    ambry->generation);
		return;
	}

	ctx->flags |= KYRKA_FLAG_SECRET_SET;
	if (ctx->cathedral.ambry != 0)
		ctx->flags |= KYRKA_FLAG_AMBRY_NEGOTIATION;

	ctx->cathedral.ambry = ambry->generation;

	nyfe_memcpy(ctx->cfg.secret, ambry->key, sizeof(ambry->key));
	kyrka_mask(ctx, ctx->cfg.secret, sizeof(ctx->cfg.secret));

	if (ctx->event != NULL) {
		evt.type = KYRKA_EVENT_AMBRY_RECEIVED;
		evt.ambry.generation = ambry->generation;
		ctx->event(ctx, &evt, ctx->udata);
	}
}

/*
 * Derive an ambry unwrapping key and setup a kyrka_cipher so it
 * can be used to unwrap the ambry key.
 */
static void *
cathedral_ambry_key_derive(struct kyrka *ctx, struct kyrka_ambry_offer *ambry)
{
	u_int8_t		len;
	struct nyfe_kmac256	kdf;
	u_int16_t		tunnel;
	void			*cipher;
	u_int64_t		flock_src, flock_dst;
	u_int8_t		okm[KYRKA_AMBRY_KEY_LEN];

	PRECOND(ctx != NULL);
	PRECOND(ambry != NULL);

	nyfe_zeroize_register(okm, sizeof(okm));
	nyfe_zeroize_register(&kdf, sizeof(kdf));

	flock_src = ctx->cathedral.flock_src & ~(0xff);
	flock_dst = ctx->cathedral.flock_dst & ~(0xff);

	kyrka_mask(ctx, ctx->cfg.kek, sizeof(ctx->cfg.kek));
	kyrka_base_key(ctx->cfg.kek, sizeof(ctx->cfg.kek),
	    KYRKA_KDF_PURPOSE_KEY_KEK_UNWRAP, okm, sizeof(okm),
	    flock_src, flock_dst);
	kyrka_mask(ctx, ctx->cfg.kek, sizeof(ctx->cfg.kek));

	nyfe_kmac256_init(&kdf, okm, sizeof(okm),
	    KYRKA_AMBRY_KDF, strlen(KYRKA_AMBRY_KDF));

	len = sizeof(ambry->seed);
	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, ambry->seed, sizeof(ambry->seed));

	flock_src = htobe64(flock_src);
	flock_dst = htobe64(flock_dst);

	len = sizeof(flock_src);
	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, &flock_src, sizeof(flock_src));
	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, &flock_dst, sizeof(flock_dst));

	len = sizeof(ambry->generation);
	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, &ambry->generation,
	    sizeof(ambry->generation));

	len = sizeof(ctx->cfg.spi);
	tunnel = htobe16(ctx->cfg.spi);
	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, &tunnel, sizeof(tunnel));

	nyfe_kmac256_final(&kdf, okm, sizeof(okm));
	nyfe_zeroize(&kdf, sizeof(kdf));

	cipher = kyrka_cipher_setup(okm, sizeof(okm));
	nyfe_zeroize(&okm, sizeof(okm));

	return (cipher);
}
