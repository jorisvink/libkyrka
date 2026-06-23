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
#include <unistd.h>

#include "libkyrka-int.h"

/*
 * Derive a shroud key based on the given purpose.
 */
void
kyrka_shroud_kdf(struct kyrka *ctx, int purpose)
{
	u_int8_t	*key, *okm;
	size_t		len, okm_len;
	u_int64_t	flock_src, flock_dst;

	PRECOND(ctx != NULL);
	PRECOND(purpose == KYRKA_KDF_PURPOSE_SHROUD_CATHEDRAL ||
	    purpose == KYRKA_KDF_PURPOSE_SHROUD_PEER);
	VERIFY(ctx->flags & KYRKA_FLAG_USE_SHROUD);

	flock_src = ctx->cathedral.flock_src;
	flock_dst = ctx->cathedral.flock_dst;

	if (purpose == KYRKA_KDF_PURPOSE_SHROUD_CATHEDRAL) {
		flock_src &= ~(KYRKA_FLOCK_DOMAIN_MASK);
		flock_dst &= ~(KYRKA_FLOCK_DOMAIN_MASK);

		key = ctx->cathedral.secret;
		len = sizeof(ctx->cathedral.secret);

		okm = ctx->shroud.cathedral;
		okm_len = sizeof(ctx->shroud.cathedral);
	} else {
		key = ctx->cfg.secret;
		len = sizeof(ctx->cfg.secret);

		okm = ctx->shroud.peer;
		okm_len = sizeof(ctx->shroud.peer);
	}

	kyrka_mask(ctx, key, len);

	kyrka_base_key(key, len, purpose, okm, okm_len,
	    flock_src, flock_dst);

	kyrka_mask(ctx, key, len);
}

/*
 * Checks if shroud is active and if it is if the given key has
 * been derived.
 */
int
kyrka_shroud_has_key(struct kyrka *ctx, u_int32_t which)
{
	PRECOND(ctx != NULL);
	PRECOND(which == KYRKA_SHROUD_PEER_KEY ||
	    which == KYRKA_SHROUD_CATHEDRAL_KEY);

	if (!(ctx->flags & KYRKA_FLAG_USE_SHROUD))
		return (0);

	if (ctx->shroud.flags & which)
		return (0);

	ctx->last_error = KYRKA_ERROR_SHROUD_NO_KEYS;

	return (-1);
}

/*
 * Derive a shroud base identity based on the given parameters.
 */
void
kyrka_shroud_base_identity(struct kyrka *ctx)
{
	u_int32_t		id;
	struct nyfe_kmac256	kmac;
	u_int8_t		in_len;
	char			zeroes[KYRKA_KEY_LENGTH];
	u_int64_t		flock_a, flock_b, flock_src, flock_dst;

	PRECOND(ctx != NULL);

	nyfe_mem_zero(zeroes, sizeof(zeroes));
	nyfe_zeroize_register(&kmac, sizeof(kmac));

	flock_src = ctx->cathedral.flock_src & ~(KYRKA_FLOCK_DOMAIN_MASK);
	flock_dst = ctx->cathedral.flock_dst & ~(KYRKA_FLOCK_DOMAIN_MASK);

	if (flock_src < flock_dst) {
		flock_a = htobe64(flock_src);
		flock_b = htobe64(flock_dst);
	} else {
		flock_a = htobe64(flock_dst);
		flock_b = htobe64(flock_src);
	}

	nyfe_kmac256_init(&kmac, zeroes, sizeof(zeroes),
	    KYRKA_SHROUD_IDENTITY_BASE_KDF_LABEL,
	    sizeof(KYRKA_SHROUD_IDENTITY_BASE_KDF_LABEL) - 1);

	id = htobe32(ctx->cathedral.identity);

	in_len = 8;
	nyfe_kmac256_update(&kmac, &in_len, sizeof(in_len));
	nyfe_kmac256_update(&kmac, &flock_a, sizeof(flock_a));
	nyfe_kmac256_update(&kmac, &in_len, sizeof(in_len));
	nyfe_kmac256_update(&kmac, &flock_b, sizeof(flock_b));

	in_len = 4;
	nyfe_kmac256_update(&kmac, &in_len, sizeof(in_len));
	nyfe_kmac256_update(&kmac, &id, sizeof(id));

	nyfe_kmac256_final(&kmac, ctx->shroud.base, sizeof(ctx->shroud.base));
	nyfe_zeroize(&kmac, sizeof(kmac));

	kyrka_mask(ctx, ctx->shroud.base, sizeof(ctx->shroud.base));
}

/*
 * Generate a new seed from our PRNG and using that derive a new shroud id.
 */
void
kyrka_shroud_identity(struct kyrka *ctx)
{
	struct nyfe_kmac256	kmac;

	PRECOND(ctx != NULL);
	VERIFY(ctx->flags & KYRKA_FLAG_USE_SHROUD);

	nyfe_zeroize_register(&kmac, sizeof(kmac));

	kyrka_mask(ctx, ctx->shroud.base, sizeof(ctx->shroud.base));
	nyfe_kmac256_init(&kmac, ctx->shroud.base, sizeof(ctx->shroud.base),
	    KYRKA_SHROUD_IDENTITY_KDF_LABEL,
	    sizeof(KYRKA_SHROUD_IDENTITY_KDF_LABEL) - 1);
	kyrka_mask(ctx, ctx->shroud.base, sizeof(ctx->shroud.base));

	kyrka_random_bytes(ctx->shroud.seed, sizeof(ctx->shroud.seed));
	nyfe_kmac256_update(&kmac, ctx->shroud.seed, sizeof(ctx->shroud.seed));

	nyfe_kmac256_final(&kmac, ctx->shroud.id, sizeof(ctx->shroud.id));
	nyfe_zeroize(&kmac, sizeof(kmac));
}

/*
 * Shroud a packet before we send it onto its way. The key to use is
 * determined by what the caller set in the shroud member of the packet.
 *
 * Packets going to a cathedral will use our generated shroud id and seed,
 * anything else gets randomized data in those fields.
 */
int
kyrka_shroud_packet(struct kyrka *ctx, struct kyrka_packet *pkt)
{
	struct kyrka_shroud_hdr		*hdr;

	PRECOND(ctx != NULL);
	PRECOND(pkt != NULL);
	VERIFY(ctx->flags & KYRKA_FLAG_USE_SHROUD);
	VERIFY((pkt->length + sizeof(*hdr) + 1) < sizeof(pkt->data));

	if (ctx->cfg.mtu == 0) {
		ctx->last_error = KYRKA_ERROR_MTU_SIZE;
		return (-1);
	}

	hdr = kyrka_packet_start(pkt);
	kyrka_random_bytes(hdr->seed_data, sizeof(hdr->seed_data));

	if (pkt->shroud == KYRKA_PACKET_SHROUD_CATHEDRAL) {
		nyfe_memcpy(hdr->id, ctx->shroud.id, sizeof(ctx->shroud.id));
		nyfe_memcpy(hdr->seed_id,
		    ctx->shroud.seed, sizeof(ctx->shroud.seed));
	} else {
		kyrka_random_bytes(hdr->id, sizeof(hdr->id));
		kyrka_random_bytes(hdr->seed_id, sizeof(hdr->seed_id));
	}

	if (kyrka_shroud_xor(ctx, pkt, 0) == -1)
		return (-1);

	return (0);
}

/*
 * Calculate the shroud mask and xor it onto the entire packet.
 */
int
kyrka_shroud_xor(struct kyrka *ctx, struct kyrka_packet *pkt, int unshroud)
{
	struct nyfe_kmac256		kdf;
	struct kyrka_shroud_hdr		*hdr;
	const u_int8_t			*key;
	u_int32_t			which;
	int				steps;
	size_t				idx, len, length;
	u_int32_t			min, avail, grow, orig;
	u_int8_t			*data, mask[KYRKA_SHROUD_MASK_MAX];

	PRECOND(ctx != NULL);
	PRECOND(pkt != NULL);
	VERIFY(ctx->flags & KYRKA_FLAG_USE_SHROUD);

	switch (pkt->shroud) {
	case KYRKA_PACKET_SHROUD_CATHEDRAL:
		key = ctx->shroud.cathedral;
		len = sizeof(ctx->shroud.cathedral);
		which = KYRKA_SHROUD_CATHEDRAL_KEY;
		break;
	case KYRKA_PACKET_SHROUD_PEER:
		key = ctx->shroud.peer;
		len = sizeof(ctx->shroud.peer);
		which = KYRKA_SHROUD_PEER_KEY;
		break;
	default:
		kyrka_logmsg(ctx, "bad shroud in packet (%u)", pkt->shroud);
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		return (-1);
	}

	if (!(ctx->flags & which)) {
		ctx->last_error = KYRKA_ERROR_SHROUD_NO_KEYS;
		return (-1);
	}

	hdr = kyrka_packet_start(pkt);
	data = kyrka_packet_head(pkt);

	if (unshroud) {
		VERIFY(pkt->length >= sizeof(*hdr));
		length = pkt->length - sizeof(*hdr);
	} else {
		length = sizeof(*hdr) + pkt->length + 1;
		VERIFY(length > pkt->length && length <= ctx->cfg.mtu);

		data[pkt->length++] = 0xff;

		orig = pkt->length;
		pkt->length += sizeof(*hdr);

		if (pkt->length < ctx->cfg.mtu) {
			avail = ctx->cfg.mtu - pkt->length;

			if (avail >= 2) {
				min = -avail % avail;
				for (;;) {
					kyrka_random_bytes(&grow, sizeof(grow));
					if (grow >= min)
						break;
				}
			} else {
				grow = 0;
			}

			grow = grow % avail;
			if (grow > 0)
				memset(&data[orig], 0, grow);

			pkt->length += grow;
			VERIFY(pkt->length < KYRKA_PACKET_MAX_LEN);
		}

		length = pkt->length - sizeof(*hdr);
	}

	nyfe_zeroize_register(&kdf, sizeof(kdf));
	nyfe_kmac256_init(&kdf, key, len, KYRKA_SHROUD_LABEL,
	    sizeof(KYRKA_SHROUD_LABEL) - 1);
	nyfe_kmac256_update(&kdf, hdr, sizeof(*hdr));
	nyfe_kmac256_final(&kdf, mask, length);
	nyfe_zeroize(&kdf, sizeof(kdf));

	for (idx = 0; idx < length; idx++)
		data[idx] ^= mask[idx];

	if (unshroud) {
		pkt->length -= sizeof(*hdr);

		steps = 0;
		orig = pkt->length;

		while (pkt->length > 0 && data[pkt->length - 1] == 0x00) {
			pkt->length--;
			steps++;
		}

		if (pkt->length == 0)
			return (-1);

		if (steps > 0 && data[pkt->length - 1] != 0xff)
			pkt->length = orig;
		else if (steps > 0 || data[pkt->length - 1] == 0xff)
			pkt->length--;
	}

	return (0);
}
