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

#include "libkyrka-int.h"

/*
 * Derive a symmetrical key from the given secret and the given seed + label.
 */
void
kyrka_cipher_kdf(struct kyrka *ctx, const u_int8_t *secret, size_t secret_len,
    const char *label, struct kyrka_key *okm, void *seed, size_t seed_len)
{
	struct nyfe_kmac256	kdf;
	u_int8_t		len;

	PRECOND(ctx != NULL);
	PRECOND(secret != NULL);
	PRECOND(secret_len == KYRKA_KEY_LENGTH);
	PRECOND(label != NULL);
	PRECOND(okm != NULL);
	PRECOND(seed != NULL);
	PRECOND(seed_len == 64);

	nyfe_zeroize_register(&kdf, sizeof(kdf));

	len = sizeof(okm->key);
	nyfe_kmac256_init(&kdf, secret, secret_len, label, strlen(label));

	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, seed, seed_len);
	nyfe_kmac256_final(&kdf, okm->key, sizeof(okm->key));
	nyfe_zeroize(&kdf, sizeof(kdf));
}
