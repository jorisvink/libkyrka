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

#ifndef __H_LIBKYRKA_INTERNAL_H
#define __H_LIBKYRKA_INTERNAL_H

#include <sys/queue.h>

#if defined(__ANDROID__)
#include <sys/endian.h>
#endif

#include <stdlib.h>

/* Portability for apple devices. */
#if defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define htobe16(x)		OSSwapHostToBigInt16(x)
#define htobe32(x)		OSSwapHostToBigInt32(x)
#define htobe64(x)		OSSwapHostToBigInt64(x)
#define be16toh(x)		OSSwapBigToHostInt16(x)
#define be32toh(x)		OSSwapBigToHostInt32(x)
#define be64toh(x)		OSSwapBigToHostInt64(x)
#endif

/*
 * Internal macros for enforcing some things.
 */
#define PRECOND(x)							\
	do {								\
		if (!(x)) {						\
			printf("precondition failed in libkyrka: "	\
			    "%s:%s:%d\n", __FILE__, __func__,		\
			    __LINE__);					\
			kyrka_emergency_erase();			\
			abort();					\
		}							\
	} while (0)

/* Length of our symmetrical keys, in bytes. */
#define KYRKA_KEY_LENGTH		32

/* Length for an encapsulation key in hex. */
#define KYRKA_ENCAP_HEX_LEN		(KYRKA_KEY_LENGTH * 2)

/* ESP next_proto value for a heartbeat. */
#define KYRKA_PACKET_HEARTBEAT		0xfc

/* The number of seconds between heartbeats. */
#define KYRKA_HEARTBEAT_INTERVAL	15

/* Maximum number of packets that can be sent under an SA. */
#define KYRKA_SA_PACKET_SOFT		(1ULL << 33)
#define KYRKA_SA_PACKET_HARD		(1ULL << 34)

/* Maximum number of seconds an SA can be alive. */
#define KYRKA_SA_LIFETIME_SOFT		3500
#define KYRKA_SA_LIFETIME_HARD		3600

/* The half-time window in which offers are valid. */
#define KYRKA_OFFER_VALID		5

/* The magic for a key offer packet (SACRAMNT). */
#define KYRKA_KEY_OFFER_MAGIC		0x53414352414D4E54

/* The length of the seed in a key offer packet. */
#define KYRKA_KEY_OFFER_SALT_LEN	64

/* The KDF label for the cathedral. */
#define KYRKA_CATHEDRAL_KDF_LABEL	"SANCTUM.CATHEDRAL.KDF"

/* The KDF label for traffic encapsulation. */
#define KYRKA_ENCAP_LABEL		"SANCTUM.ENCAP.KDF"

/* The label for KMAC256 for ambry. */
#define KYRKA_AMBRY_KDF			"SANCTUM.AMBRY.KDF"

/* Length of a seed using for deriving Ambry wrapping keys. */
#define KYRKA_AMBRY_SEED_LEN		64

/* Length of a KEK used for an Ambry. */
#define KYRKA_AMBRY_KEK_LEN		32

/* Length of the key carried in an Ambry. */
#define KYRKA_AMBRY_KEY_LEN		32

/* Length of OKM to generate. */
#define KYRKA_AMBRY_OKM_LEN		64

/* Length of an authentication tag for an Ambry. */
#define KYRKA_AMBRY_TAG_LEN		32

/* Anti-replay window size. */
#define KYRKA_ARWIN_SIZE		64

/* The amount of peers per flock. */
#define KYRKA_PEERS_PER_FLOCK		255

/*
 * The ambry header, just 4 bytes that denotes the generation.
 */
struct kyrka_ambry_head {
	u_int32_t	generation;
	u_int8_t	reserved[12];
} __attribute__((packed));

/* 
 * An ambry entry, consisting of the tunnel ID, the seed used for wrapping,
 * the wrapped key and the authentication tag.
 */
struct kyrka_ambry_entry {
	u_int16_t	tunnel;
	u_int8_t	seed[KYRKA_AMBRY_SEED_LEN];
	u_int8_t	key[KYRKA_AMBRY_KEY_LEN];
	u_int8_t	tag[KYRKA_AMBRY_TAG_LEN];
} __attribute__((packed));

/*
 * An encrypted packet its head, includes the ESP header *and* the
 * 64-bit packet number used as part of the nonce later.
 */
struct kyrka_ipsec_hdr {
	struct {
		u_int32_t		spi;
		u_int32_t		seq;
	} esp;
	u_int64_t		pn;
} __attribute__((packed));

/* ESP trailer, added to the plaintext before encrypted. */
struct kyrka_ipsec_tail {
	u_int8_t		pad;
	u_int8_t		next;
} __attribute__((packed));

/*
 * The encapsulation header consisting of a normal ESP header
 * in combination with a 16 byte seed. The entire header is
 * used for mask generation when encapsulating an outgoing packet.
 * The mask is used to hide the inner ESP header and 64-bit pn.
 */
struct kyrka_encap_hdr {
	struct kyrka_ipsec_hdr		ipsec;
	u_int8_t			seed[16];
} __attribute__((packed));

/*
 * The length of the mask we XOR onto the packet if encapsulation is enabled.
 * The 20 bytes stems from the kyrka_offer_hdr having 4 bytes more than
 * a normal ESP header + packet number. So this is essentially
 * sizeof(struct kyrka_offer_hdr) - KYRKA_KEY_OFFER_SALT_LEN.
 */
#define KYRKA_ENCAP_MASK_LEN		\
    (sizeof(struct kyrka_offer_hdr) - KYRKA_KEY_OFFER_SALT_LEN)

/* Preseed is used for when outer encapsulation is enabled. */
#define KYRKA_PACKET_ENCAP_LEN		sizeof(struct kyrka_encap_hdr)

/* The header starts after our potential encapsulation. */
#define KYRKA_PACKET_HEAD_OFFSET	KYRKA_PACKET_ENCAP_LEN

/* The data starts after the header. */
#define KYRKA_PACKET_DATA_OFFSET	\
    (KYRKA_PACKET_HEAD_OFFSET + sizeof(struct kyrka_ipsec_hdr))

/* The maximum length of the user data we carry per packet. */
#define KYRKA_PACKET_DATA_LEN		1500

/*
 * The total space available in a packet buffer, we're lazy and just
 * made it large enough to hold the head room, packet data and
 * any tail that is going to be added to it.
 */
#define KYRKA_PACKET_MAX_LEN		(KYRKA_PACKET_DATA_LEN + 64)

/*
 * A security association and space to operate on packets.
 */
struct kyrka_sa {
	time_t		age;
	u_int32_t	spi;
	u_int32_t	salt;
	u_int64_t	seqnr;
	u_int64_t	bitmap;
	u_int64_t	lastpkt;
	void		*cipher;
};

/*
 * A packet.
 */
struct kyrka_packet {
	size_t		length;
	u_int8_t	data[KYRKA_PACKET_MAX_LEN];
};

/*
 * A virtual interface.
 */
struct kyrka_ifc {
	void		*udata;
	void		(*send)(const void *, size_t, u_int64_t, void *);
};

/*
 * Packets used when doing key offering or cathedral forward registration.
 *
 * Note that the internal seed and tag in kyrka_offer_data is only
 * populated when the cathedral sends an ambry.
 *
 * An offer can either be:
 *	1) A key offering (between peers)
 *	2) An ambry offering (from cathedral to us)
 *	3) An info offering (from us to cathedral, or cathedral to us)
 */

#define KYRKA_OFFER_TYPE_KEY		1
#define KYRKA_OFFER_TYPE_AMBRY		2
#define KYRKA_OFFER_TYPE_INFO		3
#define KYRKA_OFFER_TYPE_LITURGY	4

struct kyrka_offer_hdr {
	u_int64_t		magic;
	u_int64_t		flock;
	u_int32_t		spi;
	u_int8_t		seed[KYRKA_KEY_OFFER_SALT_LEN];
} __attribute__((packed));

struct kyrka_key_offer {
	u_int64_t		id;
	u_int32_t		salt;
	u_int8_t		key[KYRKA_KEY_LENGTH];
} __attribute__((packed));

struct kyrka_ambry_offer {
	u_int16_t		tunnel;
	u_int32_t		generation;
	u_int8_t		seed[KYRKA_AMBRY_SEED_LEN];
	u_int8_t		key[KYRKA_AMBRY_KEY_LEN];
	u_int8_t		tag[KYRKA_AMBRY_TAG_LEN];
} __attribute__((packed));

struct kyrka_info_offer {
	u_int32_t		id;

	u_int32_t		peer_ip;
	u_int16_t		peer_port;

	u_int32_t		local_ip;
	u_int16_t		local_port;

	u_int16_t		tunnel;
	u_int32_t		ambry_generation;
} __attribute__((packed));

struct kyrka_liturgy_offer {
	u_int8_t		id;
	u_int8_t		peers[KYRKA_PEERS_PER_FLOCK];
} __attribute__((packed));

struct kyrka_offer_data {
	u_int8_t		type;
	u_int64_t		timestamp;

	union {
		struct kyrka_key_offer		key;
		struct kyrka_info_offer		info;
		struct kyrka_ambry_offer	ambry;
		struct kyrka_liturgy_offer	liturgy;
	} offer;
} __attribute__((packed));

struct kyrka_offer {
	struct kyrka_offer_hdr		hdr;
	struct kyrka_offer_data		data;
	u_int8_t			tag[32];
} __attribute__((packed));

/* If a secret has been loaded into the context. */
#define KYRKA_FLAG_SECRET_SET		(1 << 0)

/* If the cathedral settings were configured. */
#define KYRKA_FLAG_CATHEDRAL_CONFIG	(1 << 1)

/* If a cathedral secret was loaded into the context. */
#define KYRKA_FLAG_CATHEDRAL_SECRET	(1 << 2)

/* If a device KEK was loaded into the context. */
#define KYRKA_FLAG_DEVICE_KEK		(1 << 3)

/* XXX */
union kyrka_event;

/*
 * The holy church, where data is blessed and safeguarded.
 */
struct kyrka {
	/* Event callback. */
	void		*udata;
	void		(*event)(struct kyrka *, union kyrka_event *, void *);

	/* Randomly generated local 64-bit id. */
	u_int64_t			local_id;

	/* Our peer its local_id. */
	u_int64_t			peer_id;

	/* Last received offer spi. */
	u_int32_t			last_spi;

	/* Last error that occurred in the context. */
	u_int32_t			last_error;

	/* Flags */
	u_int32_t			flags;

	/* SA for RX and TX. */
	struct kyrka_sa			tx;
	struct kyrka_sa			rx;

	/* The interfaces for heaven, purgatory and cathedral. */
	struct kyrka_ifc		heaven;
	struct kyrka_ifc		purgatory;

	/* Current outgoing key offer. */
	struct {
		u_int32_t		spi;
		u_int32_t		salt;
		u_int8_t		key[KYRKA_KEY_LENGTH];
	} offer;

	/* Configurable stuff. */
	struct {
		u_int16_t		spi;
		u_int8_t		kek[KYRKA_KEY_LENGTH];
		u_int8_t		secret[KYRKA_KEY_LENGTH];
	} cfg;

	/* Cathedral config. */
	struct {
		struct kyrka_ifc	ifc;
		u_int64_t		flock;
		u_int32_t		ambry;
		u_int32_t		identity;
		u_int8_t		secret[KYRKA_KEY_LENGTH];
	} cathedral;
};

#include "libkyrka.h"
#include "libnyfe.h"

/* The build date and revision. */
extern const char	*kyrka_build_rev;
extern const char	*kyrka_build_date;

/* cipher interfaces. */
size_t	kyrka_cipher_overhead(void);
void	kyrka_cipher_cleanup(void *);
void	*kyrka_cipher_setup(struct kyrka *, const u_int8_t *, size_t);
int	kyrka_cipher_encrypt(struct kyrka *, void *, const void *,
	    size_t, const void *, size_t, struct kyrka_packet *);
int	kyrka_cipher_decrypt(struct kyrka *, void *, const void *,
	    size_t, const void *, size_t, struct kyrka_packet *);

/* src/cathedral.c */
void	kyrka_cathedral_decrypt(struct kyrka *, const void *, size_t);

/* src/kdf.c */
int	kyrka_cipher_kdf(struct kyrka *, const u_int8_t *, size_t,
	    const char *, struct nyfe_agelas *, void *, size_t);

/* src/key.c */
void	kyrka_key_unwrap(struct kyrka *, const void *, size_t);
int	kyrka_key_load_from_path(struct kyrka *,
	    const char *, u_int8_t *, size_t);

/* src/kyrka.c */
int	kyrka_file_open(struct kyrka *, const char *);

/* src/offer.c */
struct kyrka_offer	*kyrka_offer_init(struct kyrka_packet *,
			    u_int32_t, u_int64_t, u_int8_t);

/* src/packet.c */
void	*kyrka_packet_start(struct kyrka_packet *);
void	*kyrka_packet_head(struct kyrka_packet *);
void	*kyrka_packet_data(struct kyrka_packet *);
void	*kyrka_packet_tail(struct kyrka_packet *);
int	kyrka_packet_crypto_checklen(struct kyrka_packet *);

void	kyrka_offer_tfc(struct kyrka_packet *);
void	kyrka_offer_encrypt(struct nyfe_agelas *, struct kyrka_offer *);
int	kyrka_offer_decrypt(struct nyfe_agelas *, struct kyrka_offer *, int);

#endif
