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
#include <string.h>
#include <unistd.h>

#include <sodium.h>

#include "libkyrka-int.h"

/* The KDF label for offer key derivation from shared secret. */
#define KDF_KEY_OFFER_LABEL		"SANCTUM.KEY.OFFER.KDF"

/* The KDF label for traffic key derivation from shared secret. */
#define KDF_KEY_TRAFFIC_LABEL		"SANCTUM.KEY.TRAFFIC.KDF"

/* The KDF label when deriving traffic keys. */
#define KDF_TRAFFIC_LABEL		"SANCTUM.TRAFFIC.KDF"

static void	kdf_derive_key(const u_int8_t *, size_t, int, void *, size_t);

/*
 * Derive a symmetrical key from the given secret and the given seed + label
 * for the purpose of encrypting offerings.
 */
void
kyrka_offer_kdf(const u_int8_t *secret, size_t secret_len,
    const char *label, struct kyrka_key *okm, void *seed, size_t seed_len)
{
	struct nyfe_kmac256	kdf;
	u_int8_t		len, key[KYRKA_KEY_LENGTH];

	PRECOND(secret != NULL);
	PRECOND(secret_len == KYRKA_KEY_LENGTH);
	PRECOND(label != NULL);
	PRECOND(okm != NULL);
	PRECOND(seed != NULL);
	PRECOND(seed_len == 64);

	nyfe_zeroize_register(key, sizeof(key));
	nyfe_zeroize_register(&kdf, sizeof(kdf));

	len = 64;
	kdf_derive_key(secret, secret_len, 1, key, sizeof(key));

	nyfe_kmac256_init(&kdf, key, sizeof(key), label, strlen(label));
	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, seed, seed_len);
	nyfe_kmac256_final(&kdf, okm->key, sizeof(okm->key));

	nyfe_zeroize(key, sizeof(key));
	nyfe_zeroize(&kdf, sizeof(kdf));
}

/*
 * Derive a new traffic key based on our shared secret, the derived secret
 * from the ecdh exchange and the direction-specific derived secret from
 * the ML-KEM-1024 exchange.
 *
 * IKM = len(ecdh_ss) || ecdh_ss || len(mlkem1024_ss) || mlkem1024_ss ||
 *       len(local.pub) || local.pub || len(offer.pub) || offer.pub || dir
 * OKM = KMAC256(traffic_key, IKM)
 */
int
kyrka_traffic_kdf(struct kyrka *ctx, struct kyrka_kex *kx,
    u_int8_t *okm, size_t okm_len)
{
	struct nyfe_kmac256	kdf;
	u_int8_t		len;
	u_int8_t		ikm[KYRKA_KEY_LENGTH];
	u_int8_t		secret[KYRKA_KEY_LENGTH];

	PRECOND(ctx != NULL);
	PRECOND(kx != NULL);
	PRECOND(okm != NULL);
	PRECOND(okm_len == KYRKA_KEY_LENGTH);

	nyfe_zeroize_register(ikm, sizeof(ikm));

	if (crypto_scalarmult_curve25519(ikm, kx->private, kx->remote) == -1) {
		nyfe_zeroize(ikm, sizeof(ikm));
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		return (-1);
	}

	nyfe_zeroize_register(&kdf, sizeof(kdf));
	nyfe_zeroize_register(secret, sizeof(secret));

	kdf_derive_key(ctx->cfg.secret,
	    sizeof(ctx->cfg.secret), 0, secret, sizeof(secret));

	nyfe_kmac256_init(&kdf, secret, sizeof(secret),
	    KDF_TRAFFIC_LABEL, strlen(KDF_TRAFFIC_LABEL));

	len = sizeof(ikm);
	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, ikm, sizeof(ikm));

	len = sizeof(kx->kem);
	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, kx->kem, sizeof(kx->kem));

	len = sizeof(kx->pub1);
	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, kx->pub1, sizeof(kx->pub1));

	len = sizeof(kx->pub2);
	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, kx->pub2, sizeof(kx->pub2));

	nyfe_kmac256_final(&kdf, okm, okm_len);

	nyfe_zeroize(ikm, sizeof(ikm));
	nyfe_zeroize(&kdf, sizeof(kdf));
	nyfe_zeroize(secret, sizeof(secret));

	return (0);
}

/*
 * Derive a key for a given purpose from our shared secret.
 */
static void
kdf_derive_key(const u_int8_t *secret, size_t secret_len, int is_offer,
    void *out, size_t out_len)
{
	struct nyfe_kmac256	kdf;
	const char		*label;

	PRECOND(secret != NULL);
	PRECOND(secret_len == KYRKA_KEY_LENGTH);
	PRECOND(out != NULL);
	PRECOND(out_len == KYRKA_KEY_LENGTH);

	if (is_offer)
		label = KDF_KEY_OFFER_LABEL;
	else
		label = KDF_KEY_TRAFFIC_LABEL;

	nyfe_zeroize_register(&kdf, sizeof(kdf));

	nyfe_kmac256_init(&kdf, secret, secret_len, label, strlen(label));
	nyfe_kmac256_final(&kdf, out, out_len);

	nyfe_zeroize(&kdf, sizeof(kdf));
}
