/*
 * Copyright (c) 2026 Joris Vink <joris@sanctorum.se>
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

#include "framework.h"
#include "libkyrka-int.h"

#define QUEUE_MAX		64

#define LOSS_TRIALS		64
#define LOSS_PERCENTAGE		85
#define LOSS_PULSES		30
#define CLEAN_PULSES		300

struct peer {
	struct kyrka		*ctx;
	struct peer		*other;
	u_int32_t		received;

	size_t			count;
	struct kyrka_packet	queue[QUEUE_MAX];
};

static struct peer	peer_a;
static struct peer	peer_b;

static void
exchange_send(struct kyrka_packet *pkt, u_int64_t seq, void *udata)
{
	struct peer	*peer = udata;

	VERIFY(peer->other->count < QUEUE_MAX);
	memcpy(&peer->other->queue[peer->other->count++], pkt, sizeof(*pkt));
}

static void
exchange_recv(struct kyrka_packet *pkt, u_int64_t seq, void *udata)
{
	struct peer	*peer = udata;

	peer->received++;
}

static void
exchange_peer_init(struct peer *peer, struct peer *other)
{
	u_int8_t	secret[KYRKA_KEY_LENGTH];

	memset(peer, 0, sizeof(*peer));

	peer->other = other;
	peer->ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(peer->ctx != NULL);

	memset(secret, 0xdd, sizeof(secret));
	VERIFY(kyrka_secret_load(peer->ctx, secret, sizeof(secret)) == 0);

	VERIFY(kyrka_purgatory_ifc(peer->ctx, exchange_send, peer) == 0);
	VERIFY(kyrka_heaven_ifc(peer->ctx, exchange_recv, peer) == 0);
}

static void
exchange_setup(void)
{
	exchange_peer_init(&peer_a, &peer_b);
	exchange_peer_init(&peer_b, &peer_a);
}

static void
exchange_cleanup(void)
{
	kyrka_ctx_free(peer_a.ctx);
	kyrka_ctx_free(peer_b.ctx);
}

static void
exchange_deliver(struct peer *peer, int loss)
{
	size_t		idx;

	for (idx = 0; idx < peer->count; idx++) {
		if (loss > 0 && (rand() % 100) < loss)
			continue;
		(void)kyrka_purgatory_input(peer->ctx, &peer->queue[idx]);
	}

	peer->count = 0;
}

static void
exchange_send_data(struct peer *peer)
{
	struct kyrka_packet	pkt;
	size_t			len;
	void			*ptr;

	memset(&pkt, 0, sizeof(pkt));

	ptr = kyrka_packet_databuf(peer->ctx, &pkt, &len);
	VERIFY(ptr != NULL);

	memset(ptr, 'x', 64);
	pkt.length = 64;

	(void)kyrka_heaven_input(peer->ctx, &pkt);
}

static void
exchange_pulse(int loss_a, int loss_b)
{
	VERIFY(kyrka_key_manage(peer_a.ctx) == 0);
	VERIFY(kyrka_key_manage(peer_b.ctx) == 0);

	exchange_send_data(&peer_a);
	exchange_send_data(&peer_b);

	exchange_deliver(&peer_a, loss_a);
	exchange_deliver(&peer_b, loss_b);

	peer_a.ctx->offer.pulse = 0;
	peer_b.ctx->offer.pulse = 0;
	peer_a.ctx->offer.next = 0;
	peer_b.ctx->offer.next = 0;
}

static int
exchange_traffic_flows(void)
{
	peer_a.received = 0;
	peer_b.received = 0;

	exchange_send_data(&peer_a);
	exchange_send_data(&peer_b);

	exchange_deliver(&peer_a, 0);
	exchange_deliver(&peer_b, 0);

	return (peer_a.received == 1 && peer_b.received == 1);
}

static void
exchange_cathedral_send(struct kyrka_packet *pkt, u_int64_t magic, void *udata)
{
}

static void
exchange_cathedral_init(struct peer *peer)
{
	struct kyrka_cathedral_cfg	cfg;
	u_int8_t			key[KYRKA_KEY_LENGTH];

	memset(&cfg, 0, sizeof(cfg));

	cfg.flock_src = 100;
	cfg.tunnel = 5;
	cfg.identity = 0xaa;
	cfg.send = exchange_cathedral_send;

	VERIFY(kyrka_cathedral_config(peer->ctx, &cfg) == 0);

	memset(key, 0xee, sizeof(key));
	VERIFY(kyrka_cathedral_secret_load(peer->ctx, key, sizeof(key)) == 0);

	memset(key, 0xff, sizeof(key));
	VERIFY(kyrka_device_kek_load(peer->ctx, key, sizeof(key)) == 0);
}

static void
exchange_ambry_wrap(struct kyrka *ctx, struct kyrka_ambry_offer *ambry)
{
	u_int8_t		len;
	struct nyfe_kmac256	kdf;
	struct kyrka_ambry_aad	aad;
	struct kyrka_cipher	cipher;
	u_int16_t		tunnel;
	u_int64_t		flock_src, flock_dst;
	u_int8_t		nonce[KYRKA_NONCE_LENGTH];
	u_int8_t		okm[KYRKA_AMBRY_KEY_LEN];

	flock_src = ctx->cathedral.flock_src & ~(KYRKA_FLOCK_DOMAIN_MASK);
	flock_dst = ctx->cathedral.flock_dst & ~(KYRKA_FLOCK_DOMAIN_MASK);

	kyrka_mask(ctx, ctx->cfg.kek, sizeof(ctx->cfg.kek));
	kyrka_base_key(ctx->cfg.kek, sizeof(ctx->cfg.kek),
	    KYRKA_KDF_PURPOSE_KEY_KEK_UNWRAP, okm, sizeof(okm),
	    flock_src, flock_dst);
	kyrka_mask(ctx, ctx->cfg.kek, sizeof(ctx->cfg.kek));

	flock_src = htobe64(flock_src);
	flock_dst = htobe64(flock_dst);
	tunnel = htobe16(ctx->cfg.spi);

	nyfe_kmac256_init(&kdf, okm, sizeof(okm),
	    KYRKA_AMBRY_KDF, strlen(KYRKA_AMBRY_KDF));

	len = sizeof(ambry->seed);
	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, ambry->seed, sizeof(ambry->seed));

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
	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, &tunnel, sizeof(tunnel));

	nyfe_kmac256_final(&kdf, okm, sizeof(okm));

	cipher.ctx = kyrka_cipher_setup(okm, sizeof(okm));
	VERIFY(cipher.ctx != NULL);

	aad.tunnel = tunnel;
	aad.expires = ambry->expires;
	aad.generation = ambry->generation;
	aad.flock_src = flock_src;
	aad.flock_dst = flock_dst;
	memcpy(aad.seed, ambry->seed, sizeof(ambry->seed));

	kyrka_offer_nonce(nonce, sizeof(nonce));

	cipher.aad = &aad;
	cipher.aad_len = sizeof(aad);
	cipher.nonce = nonce;
	cipher.nonce_len = sizeof(nonce);
	cipher.pt = ambry->key;
	cipher.ct = ambry->key;
	cipher.tag = &ambry->tag[0];
	cipher.data_len = sizeof(ambry->key);

	VERIFY(kyrka_cipher_encrypt(&cipher) == 0);
	kyrka_cipher_cleanup(cipher.ctx);
}

static void
exchange_ambry(struct peer *peer, u_int32_t generation, u_int8_t fill)
{
	struct timespec			ts;
	struct kyrka_key		okm;
	struct kyrka_packet		pkt;
	struct kyrka_offer		*op;
	struct kyrka			*ctx;
	struct kyrka_ambry_offer	*ambry;

	ctx = peer->ctx;
	kyrka_random_init();

	op = kyrka_offer_init(&pkt, ctx->cathedral.identity,
	    KYRKA_CATHEDRAL_MAGIC, KYRKA_OFFER_TYPE_AMBRY);

	(void)clock_gettime(CLOCK_REALTIME, &ts);

	ambry = &op->data.offer.ambry;
	ambry->tunnel = htobe16(ctx->cfg.spi);
	ambry->generation = htobe32(generation);
	ambry->expires = htobe16(((ts.tv_sec - KYRKA_AMBRY_AGE_EPOCH) /
	    KYRKA_AMBRY_AGE_SECONDS_PER_DAY) + 30);

	kyrka_random_bytes(ambry->seed, sizeof(ambry->seed));
	memset(ambry->key, fill, sizeof(ambry->key));

	exchange_ambry_wrap(ctx, ambry);

	kyrka_mask(ctx, ctx->cathedral.secret, sizeof(ctx->cathedral.secret));
	kyrka_offer_kdf(ctx, ctx->cathedral.secret,
	    sizeof(ctx->cathedral.secret), KYRKA_CATHEDRAL_KDF_LABEL, &okm,
	    op->hdr.seed, sizeof(op->hdr.seed), ctx->cathedral.flock_src, 0);
	kyrka_mask(ctx, ctx->cathedral.secret, sizeof(ctx->cathedral.secret));

	VERIFY(kyrka_offer_encrypt(&okm, op) == 0);
	VERIFY(kyrka_cathedral_decrypt(ctx, &pkt) == 0);
	VERIFY(ctx->cathedral.ambry == generation);
}

static void
key_exchange_peer_restart_test(void)
{
	int		idx;

	exchange_setup();

	VERIFY(kyrka_key_manage(peer_b.ctx) == 0);
	VERIFY(kyrka_key_manage(peer_b.ctx) == 0);
	VERIFY(peer_a.count == KYRKA_OFFER_KEM_FRAGMENTS);

	peer_a.count = 2;
	exchange_deliver(&peer_a, 0);
	VERIFY(peer_a.ctx->offer.pk_frag == 0x03);

	kyrka_ctx_free(peer_b.ctx);
	exchange_peer_init(&peer_b, &peer_a);

	for (idx = 0; idx < 10; idx++)
		exchange_pulse(0, 0);

	VERIFY(exchange_traffic_flows());
	VERIFY(peer_a.ctx->tx.spi == peer_b.ctx->rx.spi);
	VERIFY(peer_a.ctx->rx.spi == peer_b.ctx->tx.spi);

	exchange_cleanup();
}

static void
key_exchange_restart_ct_first_test(void)
{
	int		idx;

	exchange_setup();

	VERIFY(kyrka_key_manage(peer_a.ctx) == 0);
	VERIFY(kyrka_key_manage(peer_a.ctx) == 0);
	exchange_deliver(&peer_b, 0);
	VERIFY(peer_b.ctx->rx.cipher != NULL);

	peer_b.ctx->offer.pulse = 0;
	VERIFY(kyrka_key_manage(peer_b.ctx) == 0);
	VERIFY(peer_a.count == KYRKA_OFFER_KEM_FRAGMENTS * 2);

	peer_a.count = KYRKA_OFFER_KEM_FRAGMENTS;
	exchange_deliver(&peer_a, 0);
	VERIFY(peer_a.ctx->offer.pk_frag == KYRKA_OFFER_KEM_FRAGMENTS_DONE);

	kyrka_ctx_free(peer_b.ctx);
	exchange_peer_init(&peer_b, &peer_a);

	peer_a.ctx->offer.pulse = 0;
	VERIFY(kyrka_key_manage(peer_a.ctx) == 0);
	VERIFY(peer_b.count == KYRKA_OFFER_KEM_FRAGMENTS * 2);

	peer_b.count = KYRKA_OFFER_KEM_FRAGMENTS;
	exchange_deliver(&peer_b, 0);
	VERIFY(peer_b.ctx->rx.cipher != NULL);

	peer_b.ctx->offer.pulse = 0;
	VERIFY(kyrka_key_manage(peer_b.ctx) == 0);
	VERIFY(peer_a.count == KYRKA_OFFER_KEM_FRAGMENTS * 2);

	for (idx = 0; idx < KYRKA_OFFER_KEM_FRAGMENTS; idx++) {
		memcpy(&peer_a.queue[idx],
		    &peer_a.queue[idx + KYRKA_OFFER_KEM_FRAGMENTS],
		    sizeof(peer_a.queue[idx]));
	}

	peer_a.count = KYRKA_OFFER_KEM_FRAGMENTS;
	exchange_deliver(&peer_a, 0);

	VERIFY(peer_a.ctx->tx.cipher == NULL);
	VERIFY(peer_a.ctx->peer_id != peer_b.ctx->local_id);

	for (idx = 0; idx < 10; idx++)
		exchange_pulse(0, 0);

	VERIFY(exchange_traffic_flows());
	VERIFY(peer_a.ctx->tx.spi == peer_b.ctx->rx.spi);
	VERIFY(peer_a.ctx->rx.spi == peer_b.ctx->tx.spi);

	exchange_cleanup();
}

static void
key_exchange_partial_pk_test(void)
{
	int			idx;
	struct kyrka_packet	keep[5];
	const int		order[5] = { 0, 4, 5, 6, 7 };

	exchange_setup();

	VERIFY(kyrka_key_manage(peer_a.ctx) == 0);
	VERIFY(kyrka_key_manage(peer_a.ctx) == 0);
	exchange_deliver(&peer_b, 0);
	VERIFY(peer_b.ctx->rx.cipher != NULL);

	peer_a.count = 0;
	peer_b.ctx->offer.pulse = 0;
	VERIFY(kyrka_key_manage(peer_b.ctx) == 0);
	VERIFY(peer_a.count == KYRKA_OFFER_KEM_FRAGMENTS * 2);

	for (idx = 0; idx < 5; idx++) {
		memcpy(&keep[idx],
		    &peer_a.queue[order[idx]], sizeof(keep[idx]));
	}

	for (idx = 0; idx < 5; idx++)
		memcpy(&peer_a.queue[idx], &keep[idx], sizeof(keep[idx]));

	peer_a.count = 5;
	exchange_deliver(&peer_a, 0);

	VERIFY(peer_a.ctx->offer.pk_frag == 0x01);
	VERIFY(peer_a.ctx->tx.cipher == NULL);

	for (idx = 0; idx < 10; idx++)
		exchange_pulse(0, 0);

	VERIFY(exchange_traffic_flows());
	VERIFY(peer_a.ctx->tx.salt == peer_b.ctx->rx.salt);
	VERIFY(peer_b.ctx->tx.salt == peer_a.ctx->rx.salt);

	exchange_cleanup();
}

static void
key_exchange_one_way_loss_test(void)
{
	int		idx;

	exchange_setup();

	VERIFY(kyrka_key_manage(peer_a.ctx) == 0);
	VERIFY(kyrka_key_manage(peer_b.ctx) == 0);

	exchange_pulse(0, 0);

	for (idx = 0; idx < 16; idx++)
		exchange_pulse(100, 0);

	VERIFY(peer_a.ctx->tx.cipher == NULL);

	for (idx = 0; idx < CLEAN_PULSES; idx++)
		exchange_pulse(0, 0);

	VERIFY(exchange_traffic_flows());
	VERIFY(peer_a.ctx->tx.spi == peer_b.ctx->rx.spi);
	VERIFY(peer_a.ctx->rx.spi == peer_b.ctx->tx.spi);

	exchange_cleanup();
}

static void
key_exchange_ambry_switch_test(void)
{
	int		idx;

	exchange_setup();

	exchange_cathedral_init(&peer_a);
	exchange_cathedral_init(&peer_b);

	exchange_ambry(&peer_a, 1, 0x10);
	exchange_ambry(&peer_b, 1, 0x10);

	for (idx = 0; idx < 10; idx++)
		exchange_pulse(0, 0);

	VERIFY(exchange_traffic_flows());
	VERIFY(peer_a.ctx->offer.local.spi == 0);
	VERIFY(peer_b.ctx->offer.local.spi == 0);

	peer_a.ctx->offer.force = 1;
	VERIFY(kyrka_key_manage(peer_a.ctx) == 0);
	VERIFY(kyrka_key_manage(peer_a.ctx) == 0);
	exchange_deliver(&peer_b, 0);
	VERIFY(peer_b.ctx->offer.flags & KYRKA_OFFER_INCLUDE_KEM_CT);

	exchange_ambry(&peer_a, 2, 0x20);
	exchange_ambry(&peer_b, 2, 0x20);

	for (idx = 0; idx < 10; idx++)
		exchange_pulse(0, 0);

	VERIFY(exchange_traffic_flows());
	VERIFY(peer_a.ctx->tx.spi == peer_b.ctx->rx.spi);
	VERIFY(peer_a.ctx->rx.spi == peer_b.ctx->tx.spi);
	VERIFY(peer_a.ctx->cathedral.ambry_switch == 0);
	VERIFY(peer_b.ctx->cathedral.ambry_switch == 0);

	exchange_cleanup();
}

static void
key_exchange_packet_loss(int rekey)
{
	int		trial, idx;

	for (trial = 0; trial < LOSS_TRIALS; trial++) {
		srand(trial);
		exchange_setup();

		if (rekey) {
			for (idx = 0; idx < 10; idx++)
				exchange_pulse(0, 0);

			VERIFY(exchange_traffic_flows());

			peer_a.ctx->offer.force = 1;
			peer_b.ctx->offer.force = rand() & 1;
		}

		for (idx = 0; idx < LOSS_PULSES; idx++)
			exchange_pulse(LOSS_PERCENTAGE, LOSS_PERCENTAGE);

		for (idx = 0; idx < CLEAN_PULSES; idx++)
			exchange_pulse(0, 0);

		if (!exchange_traffic_flows())
			fatal("trial %d: traffic does not flow", trial);

		exchange_cleanup();
	}
}

static void
key_exchange_packet_loss_test(void)
{
	key_exchange_packet_loss(0);
}

static void
key_exchange_packet_loss_rekey_test(void)
{
	key_exchange_packet_loss(1);
}

void
test_entry(void)
{
	test_framework_register("key_exchange_peer_restart_test",
	    key_exchange_peer_restart_test);
	test_framework_register("key_exchange_restart_ct_first_test",
	    key_exchange_restart_ct_first_test);
	test_framework_register("key_exchange_partial_pk_test",
	    key_exchange_partial_pk_test);
	test_framework_register("key_exchange_one_way_loss_test",
	    key_exchange_one_way_loss_test);
	test_framework_register("key_exchange_ambry_switch_test",
	    key_exchange_ambry_switch_test);
	test_framework_register("key_exchange_packet_loss_test",
	    key_exchange_packet_loss_test);
	test_framework_register("key_exchange_packet_loss_rekey_test",
	    key_exchange_packet_loss_rekey_test);

	test_framework_run();
}
