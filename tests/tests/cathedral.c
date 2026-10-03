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
#include <string.h>

#include "framework.h"
#include "libkyrka-int.h"

struct captured {
	int			hits;
	union kyrka_event	evt;
};

static void
cathedral_event_capture(struct kyrka *ctx, union kyrka_event *evt, void *udata)
{
	struct captured	*cap = udata;

	cap->hits++;
	cap->evt = *evt;
}

static void
cathedral_generic_send(struct kyrka_packet *pkt, u_int64_t magic, void *udata)
{
}

static void
cathedral_cfg_defaults(struct kyrka_cathedral_cfg *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	cfg->flock_src = 100;
	cfg->tunnel = 5;
	cfg->identity = 0xaa;
	cfg->send = cathedral_generic_send;
}

static void
cathedral_config_param_test(void)
{
	int				ret;
	struct kyrka			*ctx;
	struct kyrka_cathedral_cfg	cfg;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	ret = kyrka_cathedral_config(NULL, NULL);
	VERIFY(ret == -1);

	ret = kyrka_cathedral_config(ctx, NULL);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);

	cathedral_cfg_defaults(&cfg);
	cfg.flock_src = 0;
	ret = kyrka_cathedral_config(ctx, &cfg);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);

	cathedral_cfg_defaults(&cfg);
	cfg.tunnel = 0;
	ret = kyrka_cathedral_config(ctx, &cfg);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);

	cathedral_cfg_defaults(&cfg);
	cfg.identity = 0;
	ret = kyrka_cathedral_config(ctx, &cfg);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);

	cathedral_cfg_defaults(&cfg);
	cfg.send = NULL;
	ret = kyrka_cathedral_config(ctx, &cfg);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);

	VERIFY(!(ctx->flags & KYRKA_FLAG_CATHEDRAL_CONFIG));
}

static void
cathedral_config_success_test(void)
{
	int				ret;
	struct kyrka			*ctx;
	struct kyrka_cathedral_cfg	cfg;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	VERIFY(ctx->flags & KYRKA_FLAG_P2P_ACTIVE);

	cathedral_cfg_defaults(&cfg);
	ret = kyrka_cathedral_config(ctx, &cfg);
	VERIFY(ret == 0);

	VERIFY(ctx->flags & KYRKA_FLAG_CATHEDRAL_CONFIG);
	VERIFY(!(ctx->flags & KYRKA_FLAG_P2P_ACTIVE));
	VERIFY(ctx->cfg.spi == cfg.tunnel);
	VERIFY(ctx->cathedral.identity == cfg.identity);
	VERIFY(ctx->cathedral.flock_src == cfg.flock_src);

	VERIFY(ctx->cathedral.flock_dst == cfg.flock_src);
}

static void
cathedral_config_explicit_flock_dst_test(void)
{
	int				ret;
	struct kyrka			*ctx;
	struct kyrka_cathedral_cfg	cfg;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	cathedral_cfg_defaults(&cfg);
	cfg.flock_dst = 200;

	ret = kyrka_cathedral_config(ctx, &cfg);
	VERIFY(ret == 0);
	VERIFY(ctx->cathedral.flock_dst == 200);
}

static struct kyrka *
cathedral_ctx_configured(void)
{
	int				ret;
	struct kyrka			*ctx;
	struct kyrka_cathedral_cfg	cfg;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	cathedral_cfg_defaults(&cfg);
	ret = kyrka_cathedral_config(ctx, &cfg);
	VERIFY(ret == 0);

	return (ctx);
}

static void
cathedral_notify_gating_test(void)
{
	int		ret;
	struct kyrka	*ctx;
	u_int8_t	secret[KYRKA_KEY_LENGTH];
	u_int8_t	cosk[KYRKA_ED25519_SIGN_SECRET_LENGTH];

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	ret = kyrka_cathedral_notify(NULL);
	VERIFY(ret == -1);

	ret = kyrka_cathedral_notify(ctx);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_NO_CONFIG);

	ctx = cathedral_ctx_configured();

	ret = kyrka_cathedral_notify(ctx);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_NO_SECRET);

	memset(secret, 0x11, sizeof(secret));
	VERIFY(kyrka_cathedral_secret_load(ctx, secret, sizeof(secret)) == 0);

	ret = kyrka_cathedral_notify(ctx);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_NO_COSK);

	memset(cosk, 0x22, sizeof(cosk));
	VERIFY(kyrka_cathedral_cosk_load(ctx, cosk, sizeof(cosk)) == 0);

	ret = kyrka_cathedral_notify(ctx);
	VERIFY(ret == 0);
}

static void
cathedral_nat_detection_gating_test(void)
{
	int		ret;
	struct kyrka	*ctx;
	u_int8_t	secret[KYRKA_KEY_LENGTH];
	u_int8_t	cosk[KYRKA_ED25519_SIGN_SECRET_LENGTH];

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	ret = kyrka_cathedral_nat_detection(NULL);
	VERIFY(ret == -1);

	ret = kyrka_cathedral_nat_detection(ctx);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_NO_CONFIG);

	ctx = cathedral_ctx_configured();

	ret = kyrka_cathedral_nat_detection(ctx);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_NO_SECRET);

	memset(secret, 0x33, sizeof(secret));
	VERIFY(kyrka_cathedral_secret_load(ctx, secret, sizeof(secret)) == 0);

	ret = kyrka_cathedral_nat_detection(ctx);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_NO_COSK);

	memset(cosk, 0x44, sizeof(cosk));
	VERIFY(kyrka_cathedral_cosk_load(ctx, cosk, sizeof(cosk)) == 0);

	ret = kyrka_cathedral_nat_detection(ctx);
	VERIFY(ret == 0);
}

static void
cathedral_liturgy_param_test(void)
{
	int		ret;
	struct kyrka	*ctx;
	u_int8_t	short_peers[4];
	u_int8_t	secret[KYRKA_KEY_LENGTH];
	u_int8_t	peers[KYRKA_PEERS_PER_FLOCK];
	u_int8_t	cosk[KYRKA_ED25519_SIGN_SECRET_LENGTH];

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	ret = kyrka_cathedral_liturgy(NULL, NULL, 0);
	VERIFY(ret == -1);

	ret = kyrka_cathedral_liturgy(ctx, NULL, 1);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);

	ret = kyrka_cathedral_liturgy(ctx, short_peers, sizeof(short_peers));
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_PARAMETER);

	ret = kyrka_cathedral_liturgy(ctx, NULL, 0);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_NO_CONFIG);

	ctx = cathedral_ctx_configured();

	ret = kyrka_cathedral_liturgy(ctx, NULL, 0);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_NO_SECRET);

	memset(secret, 0x55, sizeof(secret));
	VERIFY(kyrka_cathedral_secret_load(ctx, secret, sizeof(secret)) == 0);
	memset(cosk, 0x66, sizeof(cosk));
	VERIFY(kyrka_cathedral_cosk_load(ctx, cosk, sizeof(cosk)) == 0);

	ret = kyrka_cathedral_liturgy(ctx, NULL, 0);
	VERIFY(ret == 0);
	VERIFY(ctx->cathedral.liturgy_flags == 0);

	memset(peers, 0x01, sizeof(peers));
	ret = kyrka_cathedral_liturgy(ctx, peers, sizeof(peers));
	VERIFY(ret == 0);
	VERIFY(ctx->cathedral.liturgy_flags == KYRKA_LITURGY_FLAG_SIGNALING);
	VERIFY(memcmp(ctx->cathedral.peers, peers, sizeof(peers)) == 0);
}

static void
cathedral_decrypt_requires_config_test(void)
{
	int			ret;
	struct kyrka		*ctx;
	struct kyrka_packet	pkt;

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	pkt.length = sizeof(struct kyrka_offer);

	ret = kyrka_cathedral_decrypt(ctx, &pkt);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_CATHEDRAL_CONFIG);
}

static void
cathedral_decrypt_short_packet_test(void)
{
	int			ret;
	struct kyrka		*ctx;
	struct kyrka_packet	pkt;
	u_int8_t		secret[KYRKA_KEY_LENGTH];

	ctx = cathedral_ctx_configured();

	memset(secret, 0x77, sizeof(secret));
	VERIFY(kyrka_cathedral_secret_load(ctx, secret, sizeof(secret)) == 0);

	pkt.length = 4;
	ret = kyrka_cathedral_decrypt(ctx, &pkt);
	VERIFY(ret == 0);
}

static void
cathedral_build_info_offer(struct kyrka *ctx, struct kyrka_packet *pkt,
    u_int32_t peer_ip, u_int32_t local_ip)
{
	struct kyrka_key	okm;
	struct kyrka_offer	*op;
	struct kyrka_info_offer	*info;

	kyrka_random_init();

	op = kyrka_offer_init(pkt, ctx->cathedral.identity,
	    KYRKA_CATHEDRAL_MAGIC, KYRKA_OFFER_TYPE_INFO);

	info = &op->data.offer.info;
	info->peer_ip = peer_ip;
	info->local_ip = local_ip;

	kyrka_mask(ctx, ctx->cathedral.secret, sizeof(ctx->cathedral.secret));
	kyrka_offer_kdf(ctx, ctx->cathedral.secret,
	    sizeof(ctx->cathedral.secret), KYRKA_CATHEDRAL_KDF_LABEL, &okm,
	    op->hdr.seed, sizeof(op->hdr.seed), ctx->cathedral.flock_src, 0);
	kyrka_mask(ctx, ctx->cathedral.secret, sizeof(ctx->cathedral.secret));

	VERIFY(kyrka_offer_encrypt(&okm, op) == 0);
}

static void
cathedral_decrypt_peer_discovery_test(void)
{
	int			ret;
	struct kyrka		*ctx;
	struct captured		cap;
	struct kyrka_packet	pkt;
	u_int8_t		secret[KYRKA_KEY_LENGTH];

	memset(&cap, 0, sizeof(cap));

	ctx = kyrka_ctx_alloc(cathedral_event_capture, &cap);
	VERIFY(ctx != NULL);

	{
		struct kyrka_cathedral_cfg	cfg;

		cathedral_cfg_defaults(&cfg);
		VERIFY(kyrka_cathedral_config(ctx, &cfg) == 0);
	}

	memset(secret, 0x88, sizeof(secret));
	VERIFY(kyrka_cathedral_secret_load(ctx, secret, sizeof(secret)) == 0);

	cathedral_build_info_offer(ctx, &pkt, 1, 0);

	ret = kyrka_cathedral_decrypt(ctx, &pkt);
	VERIFY(ret == 0);

	VERIFY(cap.hits == 1);
	VERIFY(cap.evt.type == KYRKA_EVENT_PEER_DISCOVERY);
	VERIFY(cap.evt.peer.ip == 1);
}

static void
cathedral_decrypt_wrong_identity_ignored_test(void)
{
	int			ret;
	struct kyrka		*ctx;
	struct captured		cap;
	struct kyrka_packet	pkt;
	u_int8_t		secret[KYRKA_KEY_LENGTH];

	memset(&cap, 0, sizeof(cap));

	ctx = kyrka_ctx_alloc(cathedral_event_capture, &cap);
	VERIFY(ctx != NULL);

	{
		struct kyrka_cathedral_cfg	cfg;

		cathedral_cfg_defaults(&cfg);
		VERIFY(kyrka_cathedral_config(ctx, &cfg) == 0);
	}

	memset(secret, 0x99, sizeof(secret));
	VERIFY(kyrka_cathedral_secret_load(ctx, secret, sizeof(secret)) == 0);

	ctx->cathedral.identity = 0xbb;
	cathedral_build_info_offer(ctx, &pkt, 1, 0);
	ctx->cathedral.identity = 0xaa;

	ret = kyrka_cathedral_decrypt(ctx, &pkt);
	VERIFY(ret == 0);

	VERIFY(cap.hits == 1);
	VERIFY(cap.evt.type == KYRKA_EVENT_LOGMSG);
}

static void
cathedral_decrypt_ambry_requires_kek_test(void)
{
	int			ret;
	struct kyrka		*ctx;
	struct kyrka_key	okm;
	struct kyrka_offer	*op;
	struct kyrka_packet	pkt;
	u_int8_t		secret[KYRKA_KEY_LENGTH];

	ctx = cathedral_ctx_configured();

	memset(secret, 0xaa, sizeof(secret));
	VERIFY(kyrka_cathedral_secret_load(ctx, secret, sizeof(secret)) == 0);

	kyrka_random_init();

	op = kyrka_offer_init(&pkt, ctx->cathedral.identity,
	    KYRKA_CATHEDRAL_MAGIC, KYRKA_OFFER_TYPE_AMBRY);

	kyrka_mask(ctx, ctx->cathedral.secret, sizeof(ctx->cathedral.secret));
	kyrka_offer_kdf(ctx, ctx->cathedral.secret,
	    sizeof(ctx->cathedral.secret), KYRKA_CATHEDRAL_KDF_LABEL, &okm,
	    op->hdr.seed, sizeof(op->hdr.seed), ctx->cathedral.flock_src, 0);
	kyrka_mask(ctx, ctx->cathedral.secret, sizeof(ctx->cathedral.secret));

	VERIFY(kyrka_offer_encrypt(&okm, op) == 0);

	ret = kyrka_cathedral_decrypt(ctx, &pkt);
	VERIFY(ret == -1);
	VERIFY(kyrka_last_error(ctx) == KYRKA_ERROR_CATHEDRAL_CONFIG);
}

void
test_entry(void)
{
	test_framework_register("cathedral_config_param_test",
	    cathedral_config_param_test);
	test_framework_register("cathedral_config_success_test",
	    cathedral_config_success_test);
	test_framework_register("cathedral_config_explicit_flock_dst_test",
	    cathedral_config_explicit_flock_dst_test);

	test_framework_register("cathedral_notify_gating_test",
	    cathedral_notify_gating_test);
	test_framework_register("cathedral_nat_detection_gating_test",
	    cathedral_nat_detection_gating_test);
	test_framework_register("cathedral_liturgy_param_test",
	    cathedral_liturgy_param_test);

	test_framework_register("cathedral_decrypt_requires_config_test",
	    cathedral_decrypt_requires_config_test);
	test_framework_register("cathedral_decrypt_short_packet_test",
	    cathedral_decrypt_short_packet_test);
	test_framework_register("cathedral_decrypt_peer_discovery_test",
	    cathedral_decrypt_peer_discovery_test);
	test_framework_register("cathedral_decrypt_wrong_identity_ignored_test",
	    cathedral_decrypt_wrong_identity_ignored_test);
	test_framework_register("cathedral_decrypt_ambry_requires_kek_test",
	    cathedral_decrypt_ambry_requires_kek_test);

	test_framework_run();
}
