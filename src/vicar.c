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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libkyrka-int.h"

/* The KDF label used by vicar for key derivation. */
#define VICAR_KDF_LABEL			"VICAR.PASSPHRASE.PBKDF"

/* The length in bytes for how much salt we have per vicar file. */
#define VICAR_SALT_LEN			32

/* The length in bytes of the authentication tag. */
#define VICAR_TAG_LEN			32

/* The length in bytes for how much key material we generate. */
#define VICAR_OKM_LEN			64

/* The length in bytes for how many bytes our padded passphrases are. */
#define VICAR_PASSPHRASE_PADDED_LEN	256

/*
 * A vicar configuration file.
 *
 * This holds the initial configuration for an application or device
 * that has to be provisioned.
 *
 * The initial configuration consists of:
 *	- The flock id
 *	- The kek 
 *	- The kek id (tunnel id)
 *	- The cathedral id
 *	- The cathedral secret
 *	- The initial cathedral ip and port
 */
struct vicar {
	/*
	 * The salt used to derive a unique encryption key for
	 * decrypting the data member.
	 */
	u_int8_t		salt[VICAR_SALT_LEN];

	/*
	 * The encrypted payload, encrypted under Agelas with
	 * the salt as AAD.
	 */
	struct {
		u_int32_t	id;
		u_int32_t	ip;
		u_int64_t	flock;
		u_int16_t	port;
		u_int16_t	tunnel;
		u_int8_t	kek[KYRKA_KEY_LENGTH];
		u_int8_t	secret[KYRKA_KEY_LENGTH];
	} data;

	/* Authentication tag, calculated over salt + data. */
	u_int8_t		tag[VICAR_TAG_LEN];
} __attribute__((packed));

/*
 * Loads the tunnel id, kek, cathedral id and cathedral secret
 * from the given encrypted vicar file into the given cathedral
 * configuration.
 */
int
kyrka_vicar_load(KYRKA *ctx, const char *path, const char *passphrase,
    struct kyrka_cathedral_cfg *cfg)
{
	int			fd;
	struct vicar		conf;
	struct nyfe_agelas	cipher;
	u_int8_t		tag[VICAR_TAG_LEN];
	u_int8_t		okm[VICAR_OKM_LEN];
	u_int8_t		padded[VICAR_PASSPHRASE_PADDED_LEN];

	if (ctx == NULL)
		return (-1);

	if (path == NULL || passphrase == NULL || cfg == NULL) {
		ctx->last_error = KYRKA_ERROR_PARAMETER;
		return (-1);
	}

	if ((fd = kyrka_file_open(ctx, path)) == -1)
		return (-1);

	if (nyfe_file_read(fd, &conf, sizeof(conf)) != sizeof(conf)) {
		ctx->last_error = KYRKA_ERROR_FILE_ERROR;
		(void)close(fd);
		return (-1);
	}

	(void)close(fd);

	nyfe_zeroize_register(okm, sizeof(okm));
	nyfe_zeroize_register(&conf, sizeof(conf));
	nyfe_zeroize_register(padded, sizeof(padded));
	nyfe_zeroize_register(&cipher, sizeof(cipher));

	nyfe_mem_zero(padded, sizeof(padded));
	nyfe_memcpy(padded, passphrase, strlen(passphrase));

	nyfe_passphrase_kdf(padded, sizeof(padded),
	    conf.salt, sizeof(conf.salt), okm, sizeof(okm),
	    VICAR_KDF_LABEL, sizeof(VICAR_KDF_LABEL) - 1);
	nyfe_zeroize(padded, sizeof(padded));

	nyfe_agelas_init(&cipher, okm, sizeof(okm));
	nyfe_zeroize(okm, sizeof(okm));

	nyfe_agelas_aad(&cipher, conf.salt, sizeof(conf.salt));
	nyfe_agelas_decrypt(&cipher, &conf.data, &conf.data, sizeof(conf.data));
	nyfe_agelas_authenticate(&cipher, tag, sizeof(tag));
	nyfe_zeroize(&cipher, sizeof(cipher));

	if (nyfe_mem_cmp(conf.tag, tag, sizeof(tag))) {
		nyfe_zeroize(&conf, sizeof(conf));
		ctx->last_error = KYRKA_ERROR_INTEGRITY;
		return (-1);
	}

	cfg->identity = conf.data.id;
	cfg->tunnel = conf.data.tunnel;
	cfg->flock_src = conf.data.flock;

	if (kyrka_cathedral_secret_load(ctx,
	    conf.data.secret, sizeof(conf.data.secret)) == -1) {
		nyfe_zeroize(&conf, sizeof(conf));
		return (-1);
	}

	if (kyrka_device_kek_load(ctx,
	    conf.data.kek, sizeof(conf.data.kek)) == -1) {
		nyfe_zeroize(&conf, sizeof(conf));
		return (-1);
	}

	nyfe_zeroize(&conf, sizeof(conf));

	return (0);
}
