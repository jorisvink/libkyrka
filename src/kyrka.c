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
kyrka_ctx_alloc(void (*event)(struct kyrka *, union kyrka_event *))
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

	ctx->event = event;

	return (ctx);
}

/*
 * Load the secret in the given path into our context.
 */
int
kyrka_secret_load(KYRKA *ctx, const char *path)
{
	int		fd;

	if (ctx == NULL)
		return (-1);

	if (path == NULL) {
		ctx->last_error = KYRKA_ERROR_PARAMETER;
		return (-1);
	}

	if ((fd = kyrka_file_open(ctx, path)) == -1)
		return (-1);

	if (nyfe_file_read(fd, ctx->cfg.secret,
	    sizeof(ctx->cfg.secret)) != sizeof(ctx->cfg.secret)) {
		(void)close(fd);
		ctx->last_error = KYRKA_ERROR_INTERNAL;
		return (-1);
	}

	(void)close(fd);

	ctx->flags |= KYRKA_FLAG_SECRET_SET;

	return (0);
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
