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

#ifndef __H_KYRKA_INRI_API
#define __H_KYRKA_INRI_API

#include <netinet/in.h>

#define KYRKA_INRI_FLAG_P2P_DISABLED	(1 << 0)
#define KYRKA_INRI_FLAG_CONFIGURED	(1 << 1)

/*
 * The kyrka inri api context.
 */
struct kyrka_inri {
	struct kyrka			*ctx;
	void				*udata;

	u_int32_t			flags;
	time_t				notify;
	u_int16_t			interval;

	int				fd;
	int				online;

	struct sockaddr_in		peer;
	struct sockaddr_in		cathedral;

	struct kyrka_cathedral_cfg	config;

	void	(*state)(struct kyrka_inri *, int);
	void	(*log)(struct kyrka_inri *, const char *, ...);
	void	(*heaven)(struct kyrka_inri *, const void *, size_t);
};

#endif
