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

/*
 * This example demonstrates the use of the KYRKA_INRI API.
 *
 * This API makes assumptions on the transport (the assumption being
 * you are connecting over ipv4) and provides a quicker way of getting
 * started as you do not have to re-implement the sending / receiving.
 *
 * The API takes care of this for you.
 *
 * If you wish to test this example, make sure you have the required
 * files available for setting up a tunnel using a cathedral.
 *
 * $ gcc -Werror -D_GNU_SOURCE=1 -Wall -std=c99 -pedantic inri.c -o inri \
 *	-I ../host-build/include -L../host-build/lib -lkyrka -lsodium
 */

#include <sys/types.h>

#include <libkyrka/libkyrka.h>

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void		cb_tunnel_state(KYRKA_INRI *, int);
static void		cb_log(KYRKA_INRI *, const char *, ...);
static void		cb_cleartext(KYRKA_INRI *, const void *, size_t);

static unsigned long	number_convert(const char *, unsigned long, int);

/*
 * The example state that is passed around to all callbacks.
 */
struct state {
	int		online;
};

int
main(int argc, char *argv[])
{
	KYRKA_INRI		*ctx;
	struct state		state;
	u_int64_t		flock;
	u_int32_t		identity;
	u_int16_t		tunnel, port;

	if (argc != 9) {
		printf("Usage: inri [cathedral ip] [cathedral port] ");
		printf("[tunnel] [cs-id]\n");
		printf("            [flock] [path-to-kek] [path-to-cosk] ");
		printf("[path-to-cs]\n");
		exit(1);
	}

	port = number_convert(argv[2], USHRT_MAX, 10);
	tunnel = number_convert(argv[3], USHRT_MAX, 16);
	identity = number_convert(argv[4], UINT_MAX, 16);
	flock = number_convert(argv[5], ULLONG_MAX, 16);

	memset(&state, 0, sizeof(state));

	/*
	 * We allocate a new KYRKA_INRI context first.
	 *
	 * This context contains an actual KYRKA context that all
	 * work is done upon. You can obtain this context yourself
	 * by calling the kyrka_inri_context() function.
	 */
	if ((ctx = kyrka_inri_alloc()) == NULL)
		errx(1, "kyrka_inri_alloc");

	/*
	 * The KYRKA_INRI_INTERVAL is used to determine how long
	 * the kyrka_inri_wait() function will sleep before returning
	 * KYRKA_ERROR_TIMEOUT.
	 *
	 * It is also used as the cathedral-notify interval, sending
	 * a keep-alive packet to the cathedral every X seconds.
	 */
	kyrka_inri_set(ctx, KYRKA_INRI_INTERVAL, 1);

	/*
	 * Set all callbacks and the userdata for these callbacks.
	 */
	kyrka_inri_set(ctx, KYRKA_INRI_CALLBACK_LOG, cb_log);
	kyrka_inri_set(ctx, KYRKA_INRI_CALLBACK_DATA, cb_cleartext);
	kyrka_inri_set(ctx, KYRKA_INRI_CALLBACK_TUNNEL_STATE, cb_tunnel_state);
	kyrka_inri_set(ctx, KYRKA_INRI_CALLBACK_UDATA, &state);

	/*
	 * Set what cathedral we are talking too and on which port.
	 */
	kyrka_inri_set(ctx, KYRKA_INRI_CATHEDRAL_PORT, port);
	kyrka_inri_set(ctx, KYRKA_INRI_CATHEDRAL_IP, argv[1]);

	/*
	 * Set our client KEK so we can unwrap Ambries.
	 */
	kyrka_inri_set(ctx, KYRKA_INRI_DEVICE_KEK, argv[6]);

	/*
	 * Set our tunnel we will establish (our kek -> peer kek)
	 */
	kyrka_inri_set(ctx, KYRKA_INRI_CATHEDRAL_TUNNEL, tunnel);

	/*
	 * Set our client cathedral identity so the cathedral knows
	 * how to authenticate our packets.
	 */
	kyrka_inri_set(ctx, KYRKA_INRI_CATHEDRAL_IDENTITY, identity);

	/*
	 * Set our client cathedral secret to provide traffic protection
	 * for the cathedral packets we send.
	 */
	kyrka_inri_set(ctx, KYRKA_INRI_CATHEDRAL_SECRET, argv[8]);

	/*
	 * Set our client cathedral offer signing key to provide
	 * authenticity for the cathedral packets we send.
	 */
	kyrka_inri_set(ctx, KYRKA_INRI_DEVICE_COSK, argv[7]);

	/*
	 * Set our source flock and destination flock (same in this case).
	 */
	kyrka_inri_set(ctx, KYRKA_INRI_CATHEDRAL_FLOCK_SRC, flock);
	kyrka_inri_set(ctx, KYRKA_INRI_CATHEDRAL_FLOCK_DST, flock);

	/* Apply our configuration. */
	if (kyrka_inri_apply(ctx) == -1)
		errx(1, "config: %u", kyrka_inri_error(ctx));

	/*
	 * One can obtain the underlying socket in case one wants to
	 * use their own event loop in combination with KYRKA_INRI.
	 */
	printf("fd: %d\n", kyrka_inri_fd(ctx));

	/*
	 * We wait for things to happen and then run the context.
	 */
	for (;;) {
		if (kyrka_inri_wait(ctx) == -1) {
			if (kyrka_inri_error(ctx) != KYRKA_ERROR_TIMEOUT)
				errx(1, "wait: %u", kyrka_inri_error(ctx));
		}

		if (kyrka_inri_run(ctx) == -1)
			errx(1, "run: %u", kyrka_inri_error(ctx));
	}

	return (0);
}

/*
 * The KYRKA_INRI_CALLBACK_DATA callback, which is called by the API
 * when cleartext data was made available to the user.
 */
static void
cb_cleartext(KYRKA_INRI *inri, const void *data, size_t len)
{
	size_t		idx;
	const u_int8_t	*ptr;

	printf("%zu bytes of plaintext arrived\n", len);

	ptr = data;

	for (idx = 0; idx < len; idx++)
		printf("%02x", ptr[idx]);

	printf("\n");
}

/*
 * The KYRKA_INRI_CALLBACK_LOG callback, which is called by the API
 * when it attempts to log certain important information.
 *
 * If not set, no logs are made available any other way.
 */
static void
cb_log(KYRKA_INRI *inri, const char *fmt, ...)
{
	va_list		args;

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);

	printf("\n");
}

/*
 * The KYRKA_INRI_CALLBACK_TUNNEL_STATE callback, which is called by the
 * API when the tunnel state changes.
 *
 * Right now the only state reported is if the tunnel is online or not.
 */
static void
cb_tunnel_state(KYRKA_INRI *inri, int online)
{
	struct state	*state;
	u_int8_t	data[32];

	/* Obtain pointer to the KYRKA_INRI_CALLBACK_UDATA userdata. */
	state = kyrka_inri_udata(inri);

	if (online) {
		state->online = 1;
		printf("tunnel is now online\n");

		/* Send some data into the tunnel to our peer. */
		memset(data, 'A', sizeof(data));
		if (kyrka_inri_send(inri, data, sizeof(data)) == -1)
			errx(1, "kyrka_inri_send: %d", kyrka_inri_error(inri));
	}
}

/*
 * Helper function to convert a C string into an unsigned long.
 */
static unsigned long
number_convert(const char *str, unsigned long max, int base)
{
	unsigned long	val;
	char		*ep;

	errno = 0;
	val = strtoull(str, &ep, base);
	if (errno != 0 || *ep != '\0')
		errx(1, "'%s' is an invalid number", str);

	if (val > max)
		errx(1, "'%s' too large", str);

	return (val);
}
