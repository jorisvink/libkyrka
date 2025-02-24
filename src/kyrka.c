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
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "libkyrka-int.h"

/*
 * Allocate a new KYRKA context that will represent a single sanctum tunnel.
 */
struct kyrka *
kyrka_ctx_alloc(void (*event)(struct kyrka *, union kyrka_event *, void *),
    void *udata)
{
	struct kyrka		*ctx;

	if ((ctx = calloc(1, sizeof(*ctx))) == NULL)
		return (NULL);

	nyfe_zeroize_register(ctx, sizeof(*ctx));

	nyfe_random_init();
	nyfe_random_bytes(&ctx->local_id, sizeof(ctx->local_id));

	nyfe_random_bytes(ctx->cfg.kek, sizeof(ctx->cfg.kek));
	nyfe_random_bytes(ctx->cfg.secret, sizeof(ctx->cfg.secret));
	nyfe_random_bytes(ctx->cathedral.secret, sizeof(ctx->cathedral.secret));

	ctx->udata = udata;
	ctx->event = event;

	return (ctx);
}

/*
 * Load a shared secret inside of the given path into our context.
 */
int
kyrka_secret_load(KYRKA *ctx, const char *path)
{
	if (ctx == NULL)
		return (-1);

	if (path == NULL) {
		ctx->last_error = KYRKA_ERROR_PARAMETER;
		return (-1);
	}

	if (kyrka_key_load_from_path(ctx, path,
	    ctx->cfg.secret, sizeof(ctx->cfg.secret)) == -1)
		return (-1);

	ctx->flags |= KYRKA_FLAG_SECRET_SET;

	return (0);
}

/*
 * Sets the cathedral secret directly by copying in the given secret.
 * Only call this if you did not specify the secret in the kyrka_cathedral_cfg
 * data structure when calling kyrka_cathedral_config().
 */
int
kyrka_cathedral_secret_load(KYRKA *ctx, const void *secret, size_t len)
{
	if (ctx == NULL)
		return (-1);

	if (secret == NULL || len != KYRKA_KEY_LENGTH) {
		ctx->last_error = KYRKA_ERROR_PARAMETER;
		return (-1);
	}

	nyfe_memcpy(ctx->cathedral.secret, secret, len);

	ctx->flags |= KYRKA_FLAG_CATHEDRAL_SECRET;

	return (0);
}

/*
 * Sets the device KEK secret directly by copying in the given secret.
 * Only call this if you did not specify the kek in the kyrka_cathedral_cfg
 * data structure when calling kyrka_cathedral_config().
 */
int
kyrka_device_kek_load(KYRKA *ctx, const void *secret, size_t len)
{
	if (ctx == NULL)
		return (-1);

	if (secret == NULL || len != KYRKA_KEY_LENGTH) {
		ctx->last_error = KYRKA_ERROR_PARAMETER;
		return (-1);
	}

	nyfe_memcpy(ctx->cfg.kek, secret, len);

	ctx->flags |= KYRKA_FLAG_DEVICE_KEK;

	return (0);
}

/*
 * The application thinks the peer timed out, so we just erase any
 * installed TX key and send an event back if we did so.
 */
int
kyrka_peer_timeout(KYRKA *ctx)
{
	union kyrka_event	evt;

	if (ctx == NULL)
		return (-1);

	if (ctx->tx.cipher == NULL)
		return (0);

	kyrka_cipher_cleanup(ctx->tx.cipher);
	ctx->tx.cipher = NULL;

	if (ctx->event != NULL) {
		evt.tx.spi = ctx->tx.spi;
		evt.type = KYRKA_EVENT_TX_ERASED;
		ctx->event(ctx, &evt, ctx->udata);
	}

	return (0);
}

/*
 * Perform an "emergency" erase of all data allocated by all KYRKA contexts.
 * You cannot safely use *ANY* allocated KYRKA context after calling
 * this function. Use this with caution.
 *
 * Ideally you call this from an error handler in your code when you are
 * going to exit or abort due to a panic.
 */
void
kyrka_emergency_erase(void)
{
	nyfe_zeroize_all();
}

/*
 * Zeroize and free the given KYRKA context.
 */
void
kyrka_ctx_free(struct kyrka *ctx)
{
	if (ctx != NULL) {
		nyfe_zeroize(ctx, sizeof(*ctx));
		free(ctx);
	}
}

/*
 * Obtain the last error that occurred in the KYRKA context.
 */
u_int32_t
kyrka_last_error(struct kyrka *ctx)
{
	if (ctx == NULL)
		return (KYRKA_ERROR_NO_CONTEXT);

	return (ctx->last_error);
}

/*
 * Attempt to open the given file for reading.
 */
int
kyrka_file_open(struct kyrka *ctx, const char *path)
{
	struct stat	fst;
	int		fd, saved_errno;

	PRECOND(ctx != NULL);
	PRECOND(path != NULL);

	if ((fd = open(path, O_RDONLY | O_NOFOLLOW)) == -1) {
		ctx->last_error = KYRKA_ERROR_SYSTEM;
		return (-1);
	}

	if (fstat(fd, &fst) == -1) {
		saved_errno = errno;
		(void)close(fd);
		errno = saved_errno;
		ctx->last_error = KYRKA_ERROR_SYSTEM;
		return (-1);
	}

	if (!S_ISREG(fst.st_mode)) {
		saved_errno = errno;
		(void)close(fd);
		errno = saved_errno;
		ctx->last_error = KYRKA_ERROR_FILE_ERROR;
		return (-1);
	}

	return (fd);
}
