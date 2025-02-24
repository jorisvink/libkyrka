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

#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libkyrka-int.h"

#define CATHEDRAL_OFFER_VALID		5

static int	cathedral_send_info(struct kyrka *, u_int64_t);
static void	cathedral_p2p_recv(struct kyrka *, struct kyrka_offer *);
static void	cathedral_ambry_recv(struct kyrka *, struct kyrka_offer *);
static void	cathedral_ambry_unwrap(struct kyrka *,
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

	if (cfg->flock == 0 || cfg->tunnel == 0 ||
	    cfg->identity == 0 || cfg->send == NULL) {
		ctx->last_error = KYRKA_ERROR_PARAMETER;
		return (-1);
	}

	ctx->cfg.spi = cfg->tunnel;
	ctx->cathedral.flock = cfg->flock;
	ctx->cathedral.ifc.send = cfg->send;
	ctx->cathedral.ifc.udata = cfg->udata;
	ctx->cathedral.identity = cfg->identity;

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

	return (cathedral_send_info(ctx, KYRKA_CATHEDRAL_MAGIC));
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

	return (cathedral_send_info(ctx, KYRKA_CATHEDRAL_NAT_MAGIC));
}

/*
 * Internal function to help decrypt a cathedral message that arrived
 * from the purgatory side via kyrka_purgatory_input().
 */
void
kyrka_cathedral_decrypt(struct kyrka *ctx, const void *data, size_t len)
{
	struct kyrka_offer	offer;
	struct nyfe_agelas	cipher;

	PRECOND(ctx != NULL);
	PRECOND(data != NULL);

	if (len < sizeof(offer))
		return;

	if (!(ctx->flags & KYRKA_FLAG_CATHEDRAL_CONFIG) ||
	    !(ctx->flags & KYRKA_FLAG_CATHEDRAL_SECRET) ||
	    !(ctx->flags & KYRKA_FLAG_DEVICE_KEK))
		return;

	nyfe_zeroize_register(&offer, sizeof(offer));
	nyfe_zeroize_register(&cipher, sizeof(cipher));

	nyfe_memcpy(&offer, data, sizeof(offer));

	if (kyrka_cipher_kdf(ctx, ctx->cathedral.secret,
	    sizeof(ctx->cathedral.secret), KYRKA_CATHEDRAL_KDF_LABEL, &cipher,
	    offer.hdr.seed, sizeof(offer.hdr.seed)) == -1)
		goto cleanup;

	if (kyrka_offer_decrypt(&cipher, &offer, CATHEDRAL_OFFER_VALID) == -1)
		goto cleanup;

	switch (offer.data.type) {
	case KYRKA_OFFER_TYPE_AMBRY:
		cathedral_ambry_recv(ctx, &offer);
		break;
	case KYRKA_OFFER_TYPE_INFO:
		cathedral_p2p_recv(ctx, &offer);
		break;
	}

cleanup:
	nyfe_zeroize(&offer, sizeof(offer));
	nyfe_zeroize(&cipher, sizeof(cipher));
}

/*
 * Send a packet to the cathedral with the right magic header.
 */
static int
cathedral_send_info(struct kyrka *ctx, u_int64_t magic)
{
	struct kyrka_packet		pkt;
	struct kyrka_offer		*op;
	struct kyrka_info_offer		*info;
	struct nyfe_agelas		cipher;

	PRECOND(ctx != NULL);
	PRECOND(ctx->flags & KYRKA_FLAG_CATHEDRAL_CONFIG);
	PRECOND(ctx->flags & KYRKA_FLAG_CATHEDRAL_SECRET);
	PRECOND(ctx->cathedral.ifc.send != NULL);
	PRECOND(magic == KYRKA_CATHEDRAL_MAGIC ||
	    magic == KYRKA_CATHEDRAL_NAT_MAGIC);

	op = kyrka_offer_init(&pkt,
	    ctx->cathedral.identity, magic, KYRKA_OFFER_TYPE_INFO);
	op->hdr.flock = htobe64(ctx->cathedral.flock);

	info = &op->data.offer.info;
	nyfe_mem_zero(info, sizeof(*info));

	info->tunnel = htobe16(ctx->cfg.spi);
	info->ambry_generation = htobe32(ctx->cathedral.ambry);

	nyfe_zeroize_register(&cipher, sizeof(cipher));

	if (kyrka_cipher_kdf(ctx, ctx->cathedral.secret,
	    sizeof(ctx->cathedral.secret), KYRKA_CATHEDRAL_KDF_LABEL, &cipher,
	    op->hdr.seed, sizeof(op->hdr.seed)) == -1) {
		nyfe_zeroize(&cipher, sizeof(cipher));
		return (-1);
	}

	kyrka_offer_encrypt(&cipher, op);
	nyfe_zeroize(&cipher, sizeof(cipher));

	ctx->cathedral.ifc.send(op,
	    sizeof(*op), magic, ctx->cathedral.ifc.udata);

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

	evt.type = KYRKA_EVENT_PEER_UPDATE;
	evt.peer.ip = info->peer_ip;
	evt.peer.port = info->peer_port;

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

	PRECOND(ctx != NULL);
	PRECOND(op != NULL);
	PRECOND(op->data.type == KYRKA_OFFER_TYPE_AMBRY);
	PRECOND(ctx->flags & KYRKA_FLAG_CATHEDRAL_CONFIG);
	PRECOND(ctx->flags & KYRKA_FLAG_DEVICE_KEK);

	data = &op->data;
	tunnel = be16toh(data->offer.ambry.tunnel);

	op->hdr.spi = be32toh(op->hdr.spi);

	if (op->hdr.spi != ctx->cathedral.identity || tunnel != ctx->cfg.spi)
		return;

	cathedral_ambry_unwrap(ctx, &data->offer.ambry);
}

/*
 * Verify the integrity and unwrap the given ambry entry with our KEK, if
 * it worked we will install the secret held within as our new shared secret.
 */
static void
cathedral_ambry_unwrap(struct kyrka *ctx, struct kyrka_ambry_offer *ambry)
{
	u_int8_t			len;
	union kyrka_event		evt;
	struct nyfe_kmac256		kdf;
	struct nyfe_agelas		cipher;
	u_int8_t			tag[KYRKA_AMBRY_TAG_LEN];
	u_int8_t			okm[KYRKA_AMBRY_OKM_LEN];

	PRECOND(ctx != NULL);
	PRECOND(ambry != NULL);
	PRECOND(ctx->flags & KYRKA_FLAG_CATHEDRAL_CONFIG);
	PRECOND(ctx->flags & KYRKA_FLAG_DEVICE_KEK);

	nyfe_zeroize_register(okm, sizeof(okm));
	nyfe_zeroize_register(&kdf, sizeof(kdf));
	nyfe_zeroize_register(&cipher, sizeof(cipher));

	nyfe_kmac256_init(&kdf, ctx->cfg.kek, sizeof(ctx->cfg.kek),
	    KYRKA_AMBRY_KDF, strlen(KYRKA_AMBRY_KDF));

	len = KYRKA_AMBRY_OKM_LEN;
	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, ambry->seed, sizeof(ambry->seed));
	nyfe_kmac256_final(&kdf, okm, sizeof(okm));
	nyfe_zeroize(&kdf, sizeof(kdf));

	nyfe_agelas_init(&cipher, okm, sizeof(okm));
	nyfe_zeroize(okm, sizeof(okm));

	nyfe_agelas_aad(&cipher, &ambry->generation, sizeof(ambry->generation));
	nyfe_agelas_aad(&cipher, ambry->seed, sizeof(ambry->seed));
	nyfe_agelas_aad(&cipher, &ambry->tunnel, sizeof(ambry->tunnel));

	nyfe_agelas_decrypt(&cipher,
	    ambry->key, ambry->key, sizeof(ambry->key));
	nyfe_agelas_authenticate(&cipher, tag, sizeof(tag));
	nyfe_zeroize(&cipher, sizeof(cipher));

	if (nyfe_mem_cmp(ambry->tag, tag, sizeof(tag)))
		return;

	ctx->cathedral.ambry = be32toh(ambry->generation);
	nyfe_memcpy(ctx->cfg.secret, ambry->key, sizeof(ambry->key));

	ctx->flags |= KYRKA_FLAG_SECRET_SET;

	evt.type = KYRKA_EVENT_AMBRY_RECEIVED;
	evt.ambry.generation = ctx->cathedral.ambry;

	ctx->event(ctx, &evt, ctx->udata);
}
