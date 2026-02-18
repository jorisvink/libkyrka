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
#include <sys/socket.h>

#include <arpa/inet.h>

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "libkyrka-int.h"
#include "libkyrka-inri.h"

static void	inri_context_event(KYRKA *, union kyrka_event *, void *);
static void	inri_heaven_ifc(const void *, size_t, u_int64_t, void *);
static void	inri_purgatory_ifc(const void *, size_t, u_int64_t, void *);
static void	inri_cathedral_send(const void *, size_t, u_int64_t, void *);

static int	inri_opt_interval(struct kyrka_inri *, va_list);
static int	inri_opt_p2p_disable(struct kyrka_inri *, va_list);

static int	inri_opt_callback_log(struct kyrka_inri *, va_list);
static int	inri_opt_callback_data(struct kyrka_inri *, va_list);
static int	inri_opt_callback_state(struct kyrka_inri *, va_list);
static int	inri_opt_callback_udata(struct kyrka_inri *, va_list);

static int	inri_opt_cathedral_ip(struct kyrka_inri *, va_list);
static int	inri_opt_cathedral_port(struct kyrka_inri *, va_list);
static int	inri_opt_cathedral_secret(struct kyrka_inri *, va_list);
static int	inri_opt_cathedral_tunnel(struct kyrka_inri *, va_list);
static int	inri_opt_cathedral_identity(struct kyrka_inri *, va_list);
static int	inri_opt_cathedral_flock_src(struct kyrka_inri *, va_list);
static int	inri_opt_cathedral_flock_dst(struct kyrka_inri *, va_list);

static int	inri_opt_device_kek(struct kyrka_inri *, va_list);
static int	inri_opt_device_cosk(struct kyrka_inri *, va_list);

/*
 * All options that are settable via kyrka_inri_set().
 */
static const struct {
	u_int64_t	opt;
	int		(*cb)(struct kyrka_inri *, va_list);
} opts[] = {
	{ KYRKA_INRI_CALLBACK_LOG,		inri_opt_callback_log },
	{ KYRKA_INRI_CALLBACK_DATA,		inri_opt_callback_data },
	{ KYRKA_INRI_CALLBACK_TUNNEL_STATE,	inri_opt_callback_state },
	{ KYRKA_INRI_CALLBACK_UDATA,		inri_opt_callback_udata },

	{ KYRKA_INRI_INTERVAL,			inri_opt_interval },
	{ KYRKA_INRI_P2P_DISABLE,		inri_opt_p2p_disable },

	{ KYRKA_INRI_CATHEDRAL_IP,		inri_opt_cathedral_ip },
	{ KYRKA_INRI_CATHEDRAL_PORT,		inri_opt_cathedral_port },
	{ KYRKA_INRI_CATHEDRAL_TUNNEL,		inri_opt_cathedral_tunnel },
	{ KYRKA_INRI_CATHEDRAL_SECRET,		inri_opt_cathedral_secret },
	{ KYRKA_INRI_CATHEDRAL_IDENTITY,	inri_opt_cathedral_identity },
	{ KYRKA_INRI_CATHEDRAL_FLOCK_SRC,	inri_opt_cathedral_flock_src },
	{ KYRKA_INRI_CATHEDRAL_FLOCK_DST,	inri_opt_cathedral_flock_dst },

	{ KYRKA_INRI_DEVICE_KEK,		inri_opt_device_kek },
	{ KYRKA_INRI_DEVICE_COSK,		inri_opt_device_cosk },

	{ 0, NULL }
};

/*
 * Allocate a new KYRKA_INRI context and return it to the caller.
 */
struct kyrka_inri *
kyrka_inri_alloc(void)
{
	struct kyrka_inri	*inri;

	if ((inri = calloc(1, sizeof(*inri))) == NULL)
		return (NULL);

	inri->fd = -1;
	inri->interval = 1;

	inri->cathedral.sin_family = AF_INET;
#if !defined(__linux__)
	inri->cathedral.sin_len = sizeof(inri->cathedral);
#endif

	if ((inri->fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		kyrka_inri_free(inri);
		return (NULL);
	}

	if ((inri->ctx = kyrka_ctx_alloc(inri_context_event, inri)) == NULL) {
		kyrka_inri_free(inri);
		return (NULL);
	}

	if (kyrka_heaven_ifc(inri->ctx, inri_heaven_ifc, inri) == -1 ||
	    kyrka_purgatory_ifc(inri->ctx, inri_purgatory_ifc, inri) == -1) {
		kyrka_inri_free(inri);
		return (NULL);
	}

	return (inri);
}

/*
 * Free any resources tied to the given KYRKA_INRI context.
 */
void
kyrka_inri_free(struct kyrka_inri *inri)
{
	if (inri == NULL)
		return;

	if (inri->fd != -1)
		(void)close(inri->fd);

	kyrka_ctx_free(inri->ctx);
	free(inri);
}

/*
 * Return the last error on the underlying KYRKA context, wrapper provided
 * so that a caller does not have to call kyrka_inri_context() first before
 * being able to obtain the error code.
 */
u_int32_t
kyrka_inri_error(struct kyrka_inri *inri)
{
	if (inri == NULL)
		return (KYRKA_ERROR_NO_CONTEXT);

	return (kyrka_last_error(inri->ctx));
}

/*
 * Return the underlying KYRKA context to the caller.
 */
struct kyrka *
kyrka_inri_context(struct kyrka_inri *inri)
{
	if (inri == NULL)
		return (NULL);

	return (inri->ctx);
}

/*
 * Return the underlying socket to the caller such that they may integrate
 * it into their own event loop instead of using ours.
 */
int
kyrka_inri_fd(struct kyrka_inri *inri)
{
	if (inri == NULL)
		return (-1);

	return (inri->fd);
}

/*
 * Wait for i/o on the underlying socket, up to the given interval amount
 * of seconds specified by KYRKA_INRI_INTERVAL.
 */
int
kyrka_inri_wait(struct kyrka_inri *inri)
{
	struct pollfd		pfd;
	int			ret, timeo;

	if (inri == NULL)
		return (-1);

	if (!(inri->flags & KYRKA_INRI_FLAG_CONFIGURED)) {
		inri->ctx->last_error = KYRKA_ERROR_NO_CONFIG;
		return (-1);
	}

	pfd.fd = inri->fd;
	pfd.events = POLLIN;

	if (inri->interval == 0)
		timeo = -1;
	else
		timeo = inri->interval * 1000;

	for (;;) {
		if ((ret = poll(&pfd, 1, timeo)) == -1) {
			if (errno == EINTR)
				continue;

			inri->ctx->last_error = KYRKA_ERROR_SYSTEM;
			return (-1);
		}

		if (ret == 0) {
			inri->ctx->last_error = KYRKA_ERROR_TIMEOUT;
			break;
		}

		if (pfd.revents & POLLIN)
			return (0);
	}

	return (-1);
}

/*
 * Run our KYRKA_INRI context, sending periodic requests to the
 * cathedral (based on KYRKA_INRI_INTERVAL) and handling incoming
 * packets.
 */
int
kyrka_inri_run(struct kyrka_inri *inri)
{
	struct timespec		ts;
	ssize_t			ret;
	u_int8_t		pkt[1500];

	if (inri == NULL)
		return (-1);

	if (!(inri->flags & KYRKA_INRI_FLAG_CONFIGURED)) {
		inri->ctx->last_error = KYRKA_ERROR_NO_CONFIG;
		return (-1);
	}

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);

	if (ts.tv_sec >= inri->notify) {
		inri->notify = ts.tv_sec + inri->interval;

		if (kyrka_cathedral_notify(inri->ctx) == -1)
			return (-1);

		if (!(inri->flags & KYRKA_INRI_FLAG_P2P_DISABLED)) {
			if (kyrka_cathedral_nat_detection(inri->ctx) == -1)
				return (-1);
		}
	}

	if (kyrka_key_manage(inri->ctx) == -1 &&
	    kyrka_last_error(inri->ctx) != KYRKA_ERROR_NO_SECRET)
		return (-1);

	for (;;) {
		if ((ret = recv(inri->fd,
		    pkt, sizeof(pkt), MSG_DONTWAIT)) == -1) {
			if (errno == EINTR)
				continue;
			break;
		}

		if (ret == 0)
			continue;

		if (kyrka_purgatory_input(inri->ctx, pkt, ret) == -1)
			return (-1);
	}

	return (0);
}

/*
 * Set the given option in the KYRKA_INRI context.
 */
int
kyrka_inri_set(struct kyrka_inri *inri, u_int64_t opt, ...)
{
	va_list		args;
	int		i, ret;

	if (inri == NULL)
		return (-1);

	for (i = 0; opts[i].opt != 0; i++) {
		if (opts[i].opt == opt)
			break;
	}

	if (opts[i].opt == 0) {
		inri->ctx->last_error = KYRKA_ERROR_PARAMETER;
		return (-1);
	}

	va_start(args, opt);
	ret = opts[i].cb(inri, args);
	va_end(args);

	if (ret == -1)
		inri->ctx->last_error = KYRKA_ERROR_PARAMETER;

	return (ret);
}

/*
 * Apply the previous configured settings to the cathedral configuration
 * for our KYRKA context so they become active.
 */
int
kyrka_inri_apply(struct kyrka_inri *inri)
{
	if (inri == NULL)
		return (-1);

	inri->config.udata = inri;
	inri->config.send = inri_cathedral_send;

	memcpy(&inri->peer, &inri->cathedral, sizeof(inri->cathedral));

	if (kyrka_cathedral_config(inri->ctx, &inri->config) == -1)
		return (-1);

	inri->flags |= KYRKA_INRI_FLAG_CONFIGURED;

	return (0);
}

/*
 * Send data into our tunnel, this data is encrypted and pushed to
 * our peer.
 */
int
kyrka_inri_send(struct kyrka_inri *inri, const void *data, size_t len)
{
	if (inri == NULL)
		return (-1);

	if (!(inri->flags & KYRKA_INRI_FLAG_CONFIGURED)) {
		inri->ctx->last_error = KYRKA_ERROR_NO_CONFIG;
		return (-1);
	}

	/* XXX 1400 */
	if (data == NULL || len == 0 || len > 1400) {
		inri->ctx->last_error = KYRKA_ERROR_PARAMETER;
		return (-1);
	}

	return (kyrka_heaven_input(inri->ctx, data, len));
}

/*
 * Return the udata attached to the given KYRKA_INRI context.
 */
void *
kyrka_inri_udata(struct kyrka_inri *inri)
{
	if (inri == NULL)
		return (NULL);

	return (inri->udata);
}

/*
 * Internal callback for KYRKA events, we push some of these as log
 * messages to the higher layer. Some of the events we act upon internally
 * only without concerning the user.
 */
static void
inri_context_event(struct kyrka *ctx, union kyrka_event *evt, void *udata)
{
	struct kyrka_inri	*inri;

	PRECOND(ctx != NULL);
	PRECOND(evt != NULL);
	PRECOND(udata != NULL);

	inri = udata;

	switch (evt->type) {
	case KYRKA_EVENT_AMBRY_RECEIVED:
		if (inri->log != NULL) {
			inri->log(inri, "ambry 0x%08x received",
			    evt->ambry.generation);
		}
		break;
	case KYRKA_EVENT_KEYS_INFO:
		if (inri->log != NULL) {
			inri->log(inri, "tx=%08x rx=%08x",
			    evt->keys.tx_spi, evt->keys.rx_spi);
		}

		if (inri->online == 0 && inri->state != NULL &&
		    evt->keys.tx_spi != 0 && evt->keys.rx_spi != 0) {
			inri->online = 1;
			inri->state(inri, 1);
		}
		break;
	case KYRKA_EVENT_EXCHANGE_INFO:
		if (inri->log != NULL)
			inri->log(inri, "exchange: %s", evt->exchange.reason);
		break;
	case KYRKA_EVENT_LOGMSG:
		if (inri->log != NULL)
			inri->log(inri, "log: %s", evt->logmsg.log);
		break;
	case KYRKA_EVENT_PEER_DISCOVERY:
		break;
	default:
		if (inri->log != NULL)
			inri->log(inri, "event %02x", evt->type);
		break;
	}
}

/*
 * Internal callback for when cleartext data is available, we call the
 * KYRKA_INRI_CALLBACK_DATA handler with this data so the user can
 * obtain it.
 */
static void
inri_heaven_ifc(const void *data, size_t len, u_int64_t seq, void *udata)
{
	struct kyrka_inri	*inri;

	PRECOND(data != NULL);
	PRECOND(len > 0);
	PRECOND(udata != NULL);

	inri = udata;

	inri->heaven(inri, data, len);
}

/*
 * Internal callback for when KYRKA wants to send encrypted data to our peer.
 * We simply send it to our current peer address.
 */
static void
inri_purgatory_ifc(const void *data, size_t len, u_int64_t seq, void *udata)
{
	struct kyrka_inri	*inri;

	PRECOND(data != NULL);
	PRECOND(len > 0);
	PRECOND(udata != NULL);

	inri = udata;

	if (sendto(inri->fd, data, len, 0,
	    (const struct sockaddr *)&inri->peer, sizeof(inri->peer)) == -1) {
		kyrka_logmsg(inri->ctx,
		    "sendto peer: %s", strerror(errno));
	}
}

/*
 * Internal callback for when KYRKA wants to send encrypted data to our peer.
 * We simply send it to our current cathedral address.
 */
static void
inri_cathedral_send(const void *data, size_t len, u_int64_t seq, void *udata)
{
	struct kyrka_inri	*inri;

	PRECOND(data != NULL);
	PRECOND(len > 0);
	PRECOND(udata != NULL);

	inri = udata;

	if (sendto(inri->fd, data, len, 0,
	    (const struct sockaddr *)&inri->cathedral,
	    sizeof(inri->cathedral)) == -1) {
		kyrka_logmsg(inri->ctx,
		    "sendto cathedral: %s", strerror(errno));
	}
}

/* Internal KYRKA_INRI_CALLBACK_LOG handler. */
static int
inri_opt_callback_log(struct kyrka_inri *inri, va_list args)
{
	PRECOND(inri != NULL);

	*(void **)&inri->log = va_arg(args, void *);

	return (0);
}

/* Internal KYRKA_INRI_CALLBACK_DATA handler. */
static int
inri_opt_callback_data(struct kyrka_inri *inri, va_list args)
{
	PRECOND(inri != NULL);

	*(void **)&inri->heaven = va_arg(args, void *);

	return (0);
}

/* Internal KYRKA_INRI_CALLBACK_TUNNEL_STATE handler. */
static int
inri_opt_callback_state(struct kyrka_inri *inri, va_list args)
{
	PRECOND(inri != NULL);

	*(void **)&inri->state = va_arg(args, void *);

	return (0);
}

/* Internal KYRKA_INRI_CALLBACK_UDATA handler. */
static int
inri_opt_callback_udata(struct kyrka_inri *inri, va_list args)
{
	PRECOND(inri != NULL);

	inri->udata = va_arg(args, void *);

	return (0);
}

/* Internal KYRKA_INRI_INTERVAL handler. */
static int
inri_opt_interval(struct kyrka_inri *inri, va_list args)
{
	int	interval;

	PRECOND(inri != NULL);

	interval = va_arg(args, int);
	if (interval < 0 || interval > USHRT_MAX)
		return (-1);

	inri->interval = interval;

	return (0);
}

/* Internal KYRKA_INRI_P2P_DISABLE handler. */
static int
inri_opt_p2p_disable(struct kyrka_inri *inri, va_list args)
{
	int		opt;

	PRECOND(inri != NULL);

	opt = va_arg(args, int);

	if (opt == 1) {
		inri->flags |= KYRKA_INRI_FLAG_P2P_DISABLED;
	} else if (opt == 0) {
		inri->flags &= ~KYRKA_INRI_FLAG_P2P_DISABLED;
	} else {
		return (-1);
	}

	return (0);
}

/* Internal KYRKA_INRI_CATHEDRAL_IP handler. */
static int
inri_opt_cathedral_ip(struct kyrka_inri *inri, va_list args)
{
	const char	*ip;

	PRECOND(inri != NULL);

	ip = va_arg(args, const char *);

	if (inet_pton(AF_INET, ip, &inri->cathedral.sin_addr) == -1)
		return (-1);

	return (0);
}

/* Internal KYRKA_INRI_CATHEDRAL_PORT handler. */
static int
inri_opt_cathedral_port(struct kyrka_inri *inri, va_list args)
{
	int		port;

	PRECOND(inri != NULL);

	port = va_arg(args, int);

	if (port < 0 || port > USHRT_MAX)
		return (-1);

	inri->cathedral.sin_port = htons(port);

	return (0);
}

/* Internal KYRKA_INRI_CATHEDRAL_TUNNEL handler. */
static int
inri_opt_cathedral_tunnel(struct kyrka_inri *inri, va_list args)
{
	int		tunnel;

	PRECOND(inri != NULL);

	tunnel = va_arg(args, int);

	if (tunnel < 0 || tunnel > USHRT_MAX)
		return (-1);

	inri->config.tunnel = tunnel;

	return (0);
}

/* Internal KYRKA_INRI_CATHEDRAL_SECRET handler. */
static int
inri_opt_cathedral_secret(struct kyrka_inri *inri, va_list args)
{
	PRECOND(inri != NULL);

	inri->config.secret = va_arg(args, const char *);

	return (0);
}

/* Internal KYRKA_INRI_CATHEDRAL_IDENTITY handler. */
static int
inri_opt_cathedral_identity(struct kyrka_inri *inri, va_list args)
{
	PRECOND(inri != NULL);

	inri->config.identity = va_arg(args, u_int32_t);

	return (0);
}

/* Internal KYRKA_INRI_CATHEDRAL_FLOCK_SRC handler. */
static int
inri_opt_cathedral_flock_src(struct kyrka_inri *inri, va_list args)
{
	PRECOND(inri != NULL);

	inri->config.flock_src = va_arg(args, u_int64_t);

	return (0);
}

/* Internal KYRKA_INRI_CATHEDRAL_FLOCK_DST handler. */
static int
inri_opt_cathedral_flock_dst(struct kyrka_inri *inri, va_list args)
{
	PRECOND(inri != NULL);

	inri->config.flock_dst = va_arg(args, u_int64_t);

	return (0);
}

/* Internal KYRKA_INRI_DEVICE_KEK handler. */
static int
inri_opt_device_kek(struct kyrka_inri *inri, va_list args)
{
	PRECOND(inri != NULL);

	inri->config.kek = va_arg(args, const char *);

	return (0);
}

/* Internal KYRKA_INRI_DEVICE_COSK handler. */
static int
inri_opt_device_cosk(struct kyrka_inri *inri, va_list args)
{
	PRECOND(inri != NULL);

	inri->config.cosk = va_arg(args, const char *);

	return (0);
}
