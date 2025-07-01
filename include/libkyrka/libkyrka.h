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

#ifndef __H_LIBKYRKA_H
#define __H_LIBKYRKA_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <sys/types.h>

#if defined(PLATFORM_WINDOWS)
#include "portable_win.h"
#endif

/* The magic for cathedral messages (KATEDRAL). */
#define KYRKA_CATHEDRAL_MAGIC		0x4b4154454452414c

/* The magic for NAT detection messages (CIBORIUM). */
#define KYRKA_CATHEDRAL_NAT_MAGIC	0x4349424f5249554d

/* The magic for cathedral liturgy messages (LITURGY) */
#define KYRKA_CATHEDRAL_LITURGY_MAGIC	0x004C495455524759

/* The amount of peers per flock. */
#define KYRKA_PEERS_PER_FLOCK		255

/* The maximum number of federated cathedrals we can have. */
#define KYRKA_CATHEDRALS_MAX		32

/*
 * Library error codes.
 */
#define KYRKA_ERROR_NONE		0
#define KYRKA_ERROR_SYSTEM		1
#define KYRKA_ERROR_PARAMETER		2
#define KYRKA_ERROR_NO_CONTEXT		3
#define KYRKA_ERROR_NO_CALLBACK		4
#define KYRKA_ERROR_FILE_ERROR		5
#define KYRKA_ERROR_INTERNAL		6
#define KYRKA_ERROR_INTEGRITY		7
#define KYRKA_ERROR_NO_TX_KEY		8
#define KYRKA_ERROR_NO_RX_KEY		9
#define KYRKA_ERROR_NO_KEK		10
#define KYRKA_ERROR_NO_SECRET		11
#define KYRKA_ERROR_NO_CONFIG		12
#define KYRKA_ERROR_CATHEDRAL_CONFIG	13
#define KYRKA_ERROR_PACKET_ERROR	14

/*
 * Events that can occur and can be seen if an event callback was
 * given to kyrka_ctx_alloc().
 */
#define KYRKA_EVENT_KEYS_INFO			1
#define KYRKA_EVENT_KEYS_ERASED			2
#define KYRKA_EVENT_EXCHANGE_INFO		3
#define KYRKA_EVENT_PEER_DISCOVERY		4
#define KYRKA_EVENT_AMBRY_RECEIVED		5
#define KYRKA_EVENT_LITURGY_RECEIVED		6
#define KYRKA_EVENT_REMEMBRANCE_RECEIVED	7
#define KYRKA_EVENT_ENCAP_INFO			8

struct kyrka_event_encap_info {
	u_int32_t			type;
	u_int32_t			spi;
};

struct kyrka_event_keys_info {
	u_int32_t			type;
	u_int32_t			tx_spi;
	u_int32_t			rx_spi;
	u_int64_t			peer_id;
};

struct kyrka_event_exchange_info {
	u_int32_t			type;
	const char			*reason;
};

struct kyrka_event_peer {
	u_int32_t			type;
	u_int32_t			ip;
	u_int16_t			port;
};

struct kyrka_event_ambry {
	u_int32_t			type;
	u_int32_t			generation;
};

struct kyrka_event_liturgy {
	u_int32_t			type;
	u_int8_t			peers[KYRKA_PEERS_PER_FLOCK];
};

struct kyrka_event_remembrance {
	u_int32_t			type;
	u_int32_t			ips[KYRKA_CATHEDRALS_MAX];
	u_int32_t			ports[KYRKA_CATHEDRALS_MAX];
};

union kyrka_event {
	u_int32_t				type;
	struct kyrka_event_keys_info		keys;
	struct kyrka_event_encap_info		encap;
	struct kyrka_event_peer			peer;
	struct kyrka_event_ambry		ambry;
	struct kyrka_event_liturgy		liturgy;
	struct kyrka_event_exchange_info	exchange;
	struct kyrka_event_remembrance		remembrance;
};

/*
 * Data structure used to configure a cathedral.
 */
struct kyrka_cathedral_cfg {
	void		*udata;

	const char	*kek;
	const char	*secret;

	u_int64_t	flock_src;
	u_int64_t	flock_dst;

	u_int16_t	group;
	u_int16_t	tunnel;
	u_int32_t	identity;

	int		hidden;
	int		remembrance;

	void		(*send)(const void *, size_t, u_int64_t, void *);
};

/* A KYRKA context as an opaque. */
typedef struct kyrka			KYRKA;

/*
 * The public API.
 */

const char	*kyrka_version(void);
u_int32_t	kyrka_last_error(KYRKA *);

void	kyrka_ctx_free(KYRKA *);
int	kyrka_peer_timeout(KYRKA *);
void	kyrka_emergency_erase(void);
KYRKA	*kyrka_ctx_alloc(void (*event)(KYRKA *, union kyrka_event *, void *),
	    void *);

int	kyrka_key_manage(KYRKA *);
int	kyrka_secret_load_path(KYRKA *, const char *);
int	kyrka_secret_load(KYRKA *, const void *, size_t);
int	kyrka_encap_key_load(KYRKA *, const void *, size_t);
int	kyrka_device_kek_load(KYRKA *, const void *, size_t);
int	kyrka_cathedral_secret_load(KYRKA *, const void *, size_t);

int	kyrka_heaven_ifc(KYRKA *,
	    void (*cb)(const void *, size_t, u_int64_t, void *), void *);
int	kyrka_heaven_input(KYRKA *, const void *, size_t);

int	kyrka_purgatory_ifc(KYRKA *,
	    void (*cb)(const void *, size_t, u_int64_t, void *), void *);
int	kyrka_purgatory_input(KYRKA *, const void *, size_t);

int	kyrka_cathedral_notify(KYRKA *);
int	kyrka_cathedral_nat_detection(KYRKA *);
int	kyrka_cathedral_liturgy(KYRKA *, u_int8_t *, size_t);
int	kyrka_cathedral_config(KYRKA *, struct kyrka_cathedral_cfg *);

#if defined(__cplusplus)
}
#endif

#endif
