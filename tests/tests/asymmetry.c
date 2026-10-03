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

static void
asymmetry_init_test(void)
{
	VERIFY(kyrka_asymmetry_init() == 0);
}

static void
asymmetry_keygen_test(void)
{
	int		ret;
	u_int8_t	pub[KYRKA_X25519_SCALAR_BYTES];
	u_int8_t	priv[KYRKA_X25519_SCALAR_BYTES];
	u_int8_t	zero[KYRKA_X25519_SCALAR_BYTES];

	kyrka_random_init();
	memset(zero, 0, sizeof(zero));

	ret = kyrka_asymmetry_keygen(priv, sizeof(priv), pub, sizeof(pub));
	VERIFY(ret == 0);

	VERIFY(memcmp(priv, zero, sizeof(priv)) != 0);
	VERIFY(memcmp(pub, zero, sizeof(pub)) != 0);
}

static void
asymmetry_derive_shared_secret_test(void)
{
	int			ret;
	struct kyrka_kex	kex_a, kex_b;
	u_int8_t		ss_a[KYRKA_X25519_SCALAR_BYTES];
	u_int8_t		ss_b[KYRKA_X25519_SCALAR_BYTES];
	u_int8_t		pub_a[KYRKA_X25519_SCALAR_BYTES];
	u_int8_t		pub_b[KYRKA_X25519_SCALAR_BYTES];
	u_int8_t		priv_a[KYRKA_X25519_SCALAR_BYTES];
	u_int8_t		priv_b[KYRKA_X25519_SCALAR_BYTES];

	kyrka_random_init();

	ret = kyrka_asymmetry_keygen(priv_a, sizeof(priv_a), pub_a,
	    sizeof(pub_a));
	VERIFY(ret == 0);

	ret = kyrka_asymmetry_keygen(priv_b, sizeof(priv_b), pub_b,
	    sizeof(pub_b));
	VERIFY(ret == 0);

	memset(&kex_a, 0, sizeof(kex_a));
	nyfe_memcpy(kex_a.private, priv_a, sizeof(priv_a));
	nyfe_memcpy(kex_a.remote, pub_b, sizeof(pub_b));

	memset(&kex_b, 0, sizeof(kex_b));
	nyfe_memcpy(kex_b.private, priv_b, sizeof(priv_b));
	nyfe_memcpy(kex_b.remote, pub_a, sizeof(pub_a));

	ret = kyrka_asymmetry_derive(&kex_a, ss_a, sizeof(ss_a));
	VERIFY(ret == 0);

	ret = kyrka_asymmetry_derive(&kex_b, ss_b, sizeof(ss_b));
	VERIFY(ret == 0);

	VERIFY(memcmp(ss_a, ss_b, sizeof(ss_a)) == 0);
}

static void
asymmetry_derive_rejects_zero_remote_test(void)
{
	int			ret;
	struct kyrka_kex	kex;
	u_int8_t		out[KYRKA_X25519_SCALAR_BYTES];

	memset(&kex, 0, sizeof(kex));

	ret = kyrka_asymmetry_derive(&kex, out, sizeof(out));
	VERIFY(ret == -1);
}

void
test_entry(void)
{
	test_framework_register("asymmetry_init_test", asymmetry_init_test);
	test_framework_register("asymmetry_keygen_test", asymmetry_keygen_test);
	test_framework_register("asymmetry_derive_shared_secret_test",
	    asymmetry_derive_shared_secret_test);
	test_framework_register("asymmetry_derive_rejects_zero_remote_test",
	    asymmetry_derive_rejects_zero_remote_test);

	test_framework_run();
}
