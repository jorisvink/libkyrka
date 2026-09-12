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
mlkem_roundtrip_test(void)
{
	u_int8_t		zero[KYRKA_KEY_LENGTH];
	struct kyrka_mlkem1024	peer, local;

	kyrka_random_init();
	memset(zero, 0, sizeof(zero));
	memset(&peer, 0, sizeof(peer));
	memset(&local, 0, sizeof(local));

	kyrka_mlkem1024_keypair(&peer);
	VERIFY(memcmp(peer.pk, zero, sizeof(zero)) != 0);

	nyfe_memcpy(local.pk, peer.pk, sizeof(local.pk));

	kyrka_mlkem1024_encapsulate(&local);
	VERIFY(memcmp(local.ss, zero, sizeof(zero)) != 0);

	nyfe_memcpy(peer.ct, local.ct, sizeof(peer.ct));

	kyrka_mlkem1024_decapsulate(&peer);

	VERIFY(memcmp(local.ss, peer.ss, sizeof(local.ss)) == 0);
}

static void
mlkem_wrong_ciphertext_test(void)
{
	struct kyrka_mlkem1024	peer, local, other;

	kyrka_random_init();
	memset(&peer, 0, sizeof(peer));
	memset(&local, 0, sizeof(local));
	memset(&other, 0, sizeof(other));

	kyrka_mlkem1024_keypair(&peer);
	nyfe_memcpy(local.pk, peer.pk, sizeof(local.pk));
	kyrka_mlkem1024_encapsulate(&local);

	kyrka_mlkem1024_keypair(&other);
	nyfe_memcpy(local.pk, other.pk, sizeof(local.pk));
	kyrka_mlkem1024_encapsulate(&local);

	nyfe_memcpy(peer.ct, local.ct, sizeof(peer.ct));
	kyrka_mlkem1024_decapsulate(&peer);

	VERIFY(memcmp(local.ss, peer.ss, sizeof(local.ss)) != 0);
}

void
test_entry(void)
{
	test_framework_register("mlkem_roundtrip_test", mlkem_roundtrip_test);
	test_framework_register("mlkem_wrong_ciphertext_test",
	    mlkem_wrong_ciphertext_test);

	test_framework_run();
}
