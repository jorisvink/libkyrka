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

/* The magic for cathedral messages (KATEDRAL). */
#define KYRKA_CATHEDRAL_MAGIC		0x4b4154454452414c

/* The magic for NAT detection messages (CIBORIUM). */
#define KYRKA_CATHEDRAL_NAT_MAGIC	0x4349424f5249554d

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

/*
 * Events that can occur and can be seen if an event callback was
 * given to kyrka_ctx_alloc().
 */
#define KYRKA_EVENT_TX_ACTIVE		1
#define KYRKA_EVENT_RX_ACTIVE		2
#define KYRKA_EVENT_TX_EXPIRED		3
#define KYRKA_EVENT_PEER_UPDATE		4
#define KYRKA_EVENT_TX_ERASED		5
#define KYRKA_EVENT_AMBRY_RECEIVED	6

struct kyrka_event_spi_active {
	u_int32_t			type;
	u_int32_t			spi;
	u_int64_t			id;
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

union kyrka_event {
	u_int32_t			type;
	struct kyrka_event_spi_active	tx;
	struct kyrka_event_spi_active	rx;
	struct kyrka_event_peer		peer;
	struct kyrka_event_ambry	ambry;
};

/*
 * Data structure used to configure a cathedral.
 */
struct kyrka_cathedral_cfg {
	void		*udata;

	const char	*kek;
	const char	*secret;

	u_int64_t	flock;
	u_int16_t	tunnel;
	u_int32_t	identity;

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

int	kyrka_key_offer(KYRKA *);
int	kyrka_key_generate(KYRKA *);
int	kyrka_secret_load(KYRKA *, const char *);
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
int	kyrka_cathedral_config(KYRKA *, struct kyrka_cathedral_cfg *);

#if defined(__cplusplus)
}
#endif

#endif
