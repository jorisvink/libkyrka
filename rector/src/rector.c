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

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libnyfe.h"

struct config {
	u_int32_t	id;
	u_int64_t	flock;
	u_int16_t	tunnel;
	u_int8_t	kek[32];
	u_int8_t	secret[32];
} __attribute__((packed));

void		usage(void) __attribute__((noreturn));
void		fatal(const char *, ...) __attribute__((noreturn));

u_int64_t	rector_strtonum(const char *, int);
void		rector_config_write(const char *, struct config *);
void		rector_read_secret(const char *, u_int8_t *, size_t);

void
usage(void)
{
	printf("rector: [tunnnel] [flock] [device] [kek] [cathedral]\n");
	printf("Will always attempt to write to libkyrka.cfg\n");
	exit(1);
}

void
fatal(const char *fmt, ...)
{
	va_list		args;

	nyfe_zeroize_all();

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	fprintf(stderr, "\n");

	exit(1);
}

int
main(int argc, char *argv[])
{
	struct config		cfg;

	if (argc != 6)
		usage();

	memset(&cfg, 0, sizeof(cfg));

	nyfe_zeroize_register(&cfg, sizeof(cfg));

	cfg.tunnel = rector_strtonum(argv[1], 16);
	cfg.flock = rector_strtonum(argv[2], 16);
	cfg.id = rector_strtonum(argv[3], 16);

	rector_read_secret(argv[4], cfg.kek, sizeof(cfg.kek));
	rector_read_secret(argv[5], cfg.secret, sizeof(cfg.secret));

	rector_config_write("libkyrka.cfg", &cfg);

	nyfe_zeroize(&cfg, sizeof(cfg));

	return (0);
}

u_int64_t
rector_strtonum(const char *nptr, int base)
{
	char		*ep;
	u_int64_t	ret;

	errno = 0;
	ret = strtoull(nptr, &ep, base);
	if (errno != 0 || *ep != '\0')
		fatal("%s feels like an odd base %d number", nptr, base);

	return (ret);
}

void
rector_config_write(const char *path, struct config *cfg)
{
	int		fd, saved_errno;

	fd = nyfe_file_open(path, NYFE_FILE_CREATE);
	nyfe_file_write(fd, cfg, sizeof(*cfg));

	if (close(fd) == -1) {
		saved_errno = errno;
		(void)unlink(path);
		fatal("failed to write %s: %d", saved_errno);
	}
}

void
rector_read_secret(const char *path, u_int8_t *secret, size_t len)
{
	int		fd;
	size_t		ret;

	if (len != 32)
		fatal("invalid length of %zu given", len);

	fd = nyfe_file_open(path, NYFE_FILE_READ);

	if ((ret = nyfe_file_read(fd, secret, len)) != len)
		fatal("failed to read secret (%zu/%zu)", ret, len);

	(void)close(fd);
}
