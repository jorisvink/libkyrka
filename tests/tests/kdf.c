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

static u_int8_t secret[KYRKA_KEY_LENGTH] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

static void
kdf_base_key_deterministic_test(void)
{
	u_int8_t	a[KYRKA_KEY_LENGTH];
	u_int8_t	b[KYRKA_KEY_LENGTH];

	kyrka_base_key(secret, sizeof(secret), KYRKA_KDF_PURPOSE_PEER_OFFER,
	    a, sizeof(a), 0, 0);
	kyrka_base_key(secret, sizeof(secret), KYRKA_KDF_PURPOSE_PEER_OFFER,
	    b, sizeof(b), 0, 0);

	VERIFY(memcmp(a, b, sizeof(a)) == 0);
}

static void
kdf_base_key_purpose_differs_test(void)
{
	u_int8_t	a[KYRKA_KEY_LENGTH];
	u_int8_t	b[KYRKA_KEY_LENGTH];

	kyrka_base_key(secret, sizeof(secret),
	    KYRKA_KDF_PURPOSE_PEER_OFFER, a, sizeof(a), 0, 0);
	kyrka_base_key(secret, sizeof(secret),
	    KYRKA_KDF_PURPOSE_CATHEDRAL_OFFER, b, sizeof(b), 0, 0);

	VERIFY(memcmp(a, b, sizeof(a)) != 0);
}

static void
kdf_base_key_flock_order_test(void)
{
	u_int8_t	a[KYRKA_KEY_LENGTH];
	u_int8_t	b[KYRKA_KEY_LENGTH];

	kyrka_base_key(secret, sizeof(secret), KYRKA_KDF_PURPOSE_PEER_OFFER,
	    a, sizeof(a), 100, 200);
	kyrka_base_key(secret, sizeof(secret), KYRKA_KDF_PURPOSE_PEER_OFFER,
	    b, sizeof(b), 200, 100);

	VERIFY(memcmp(a, b, sizeof(a)) == 0);
}

static void
kdf_base_key_flock_changes_output_test(void)
{
	u_int8_t	a[KYRKA_KEY_LENGTH];
	u_int8_t	b[KYRKA_KEY_LENGTH];

	kyrka_base_key(secret, sizeof(secret), KYRKA_KDF_PURPOSE_PEER_OFFER,
	    a, sizeof(a), 0, 0);
	kyrka_base_key(secret, sizeof(secret), KYRKA_KDF_PURPOSE_PEER_OFFER,
	    b, sizeof(b), 1, 2);

	VERIFY(memcmp(a, b, sizeof(a)) != 0);
}

static void
kdf_offer_kdf_test(void)
{
	struct kyrka_key	a, b;
	struct kyrka		*ctx;
	u_int8_t		seed[64];

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	memset(seed, 0x42, sizeof(seed));

	kyrka_offer_kdf(ctx, secret, sizeof(secret), KYRKA_PEER_OFFER_KDF_LABEL,
	    &a, seed, sizeof(seed), 0, 0);
	kyrka_offer_kdf(ctx, secret, sizeof(secret), KYRKA_PEER_OFFER_KDF_LABEL,
	    &b, seed, sizeof(seed), 0, 0);
	VERIFY(memcmp(a.key, b.key, sizeof(a.key)) == 0);

	kyrka_offer_kdf(ctx, secret, sizeof(secret),
	    KYRKA_CATHEDRAL_KDF_LABEL, &b, seed, sizeof(seed), 0, 0);
	VERIFY(memcmp(a.key, b.key, sizeof(a.key)) != 0);

	seed[0] ^= 0xff;
	kyrka_offer_kdf(ctx, secret, sizeof(secret), KYRKA_PEER_OFFER_KDF_LABEL,
	    &b, seed, sizeof(seed), 0, 0);
	VERIFY(memcmp(a.key, b.key, sizeof(a.key)) != 0);
}

static void
kdf_traffic_kdf_requires_valid_remote_test(void)
{
	int			ret;
	struct kyrka		*ctx;
	struct kyrka_kex	kex;
	u_int8_t		okm[KYRKA_KEY_LENGTH];

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	memset(&kex, 0, sizeof(kex));
	kex.purpose = KYRKA_KDF_PURPOSE_KEY_TRAFFIC_RX;

	ret = kyrka_traffic_kdf(ctx, &kex, okm, sizeof(okm));
	VERIFY(ret == -1);
}

static void
kdf_traffic_kdf_test(void)
{
	int			ret;
	struct kyrka		*ctx;
	struct kyrka_kex	kex;
	u_int8_t		a[KYRKA_KEY_LENGTH];
	u_int8_t		b[KYRKA_KEY_LENGTH];
	u_int8_t		pub[KYRKA_X25519_SCALAR_BYTES];
	u_int8_t		priv[KYRKA_X25519_SCALAR_BYTES];

	kyrka_random_init();

	ctx = kyrka_ctx_alloc(NULL, NULL);
	VERIFY(ctx != NULL);

	ret = kyrka_asymmetry_keygen(priv, sizeof(priv), pub, sizeof(pub));
	VERIFY(ret == 0);

	memset(&kex, 0, sizeof(kex));
	kex.purpose = KYRKA_KDF_PURPOSE_KEY_TRAFFIC_TX;
	nyfe_memcpy(kex.private, priv, sizeof(priv));
	nyfe_memcpy(kex.remote, pub, sizeof(pub));

	ret = kyrka_traffic_kdf(ctx, &kex, a, sizeof(a));
	VERIFY(ret == 0);

	ret = kyrka_traffic_kdf(ctx, &kex, b, sizeof(b));
	VERIFY(ret == 0);

	VERIFY(memcmp(a, b, sizeof(a)) == 0);

	kex.purpose = KYRKA_KDF_PURPOSE_KEY_TRAFFIC_RX;
	ret = kyrka_traffic_kdf(ctx, &kex, b, sizeof(b));
	VERIFY(ret == 0);
	VERIFY(memcmp(a, b, sizeof(a)) != 0);
}

void
test_entry(void)
{
	test_framework_register("kdf_base_key_deterministic_test",
	    kdf_base_key_deterministic_test);
	test_framework_register("kdf_base_key_purpose_differs_test",
	    kdf_base_key_purpose_differs_test);
	test_framework_register("kdf_base_key_flock_order_test",
	    kdf_base_key_flock_order_test);
	test_framework_register("kdf_base_key_flock_changes_output_test",
	    kdf_base_key_flock_changes_output_test);
	test_framework_register("kdf_offer_kdf_test", kdf_offer_kdf_test);
	test_framework_register("kdf_traffic_kdf_requires_valid_remote_test",
	    kdf_traffic_kdf_requires_valid_remote_test);
	test_framework_register("kdf_traffic_kdf_test", kdf_traffic_kdf_test);

	test_framework_run();
}
