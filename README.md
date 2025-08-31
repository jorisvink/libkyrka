# Kyrka

libkyrka implements the <a href="https://sanctorum.se/sanctum">sanctum</a>
protocol in library form allowing you to establish sanctum tunnels directly
from your application without the need for the actual daemon.

Note that while the sanctum daemon is built upon proper privilege separation,
the library will not provide this to you unless you do it yourself somehow.

Because it implements the sanctum protocol it can talk to sanctum daemons
and even make use of existing sanctum infrastructure (such as cathedrals
for discovery and relay or key distribution).

Note that libkyrka is not thread-safe and you may not run different
KYRKA contexts in different threads. It was designed to be run on an
event loop using single-threaded i/o multiplexing.

# Building

```
$ make
# make install
```

You can select what cipher sanctum will use by specifying a CIPHER environment
variable at compile time with one of the following:

- libsodium-aes-gcm (AES256-GCM via libsodium) **[default]**
- mbedtls-aes-gcm (AES256-GCM via mbedtls 3.x its mbedcrypto lib)

# Usage

The API provides you with only the minimum required functions to
create a sanctum-based tunnel, it does *not* include network
functionality or similar. You bring your own. (yes, you could run
this over serial or USB if you wanted too do so).

First, create a new KYRKA context:

```c
KYRKA	*ctx;

if ((ctx = kyrka_ctx_alloc(NULL)) == NULL)
	errx(1, "failed to create KYRKA context");
```

Load a shared secret, or configure a cathedral.

```c
u_int8_t secret[32] = { ... };

if (kyrka_secret_load(ctx, secret, sizeof(secret)) == -1)
	errx(1, "kyrka_secret_load: %d", kyrka_last_error(ctx));

/* or */

if (kyrka_secret_load_path(ctx, "/tmp/secret") == -1)
	errx(1, "kyrka_secret_load_path: %d", kyrka_last_error(ctx));
```

```c
void
cathedral_send_packet(const void *data, size_t len, u_int64_t msg, void *udata)
{
	/*
	 * Send the data to somewhere, msg gives you if its a normal
	 * cathedral notify (KYRKA_CATHEDRAL_MAGIC) or if it is a
	 * NAT detection (KYRKA_CATHEDRAL_NAT_MAGIC).
	 */
}

...

struct kyrka_cathedral_cfg	cfg;

/*
 * Note that you can set kek and secret to NULL and load them explicitly
 * via kyrka_cathedral_secret_load() or kyrka_device_kek_load() if you
 * wish to load them from memory.
 */
cfg.udata = NULL;
cfg.tunnel = 0x0102;
cfg.identity = 0xbadf00d;
cfg.kek = "/tmp/device-kek";
cfg.send = cathedral_send_packet;
cfg.flock_src = 0xdeadbeefcafebabe;
cfg.secret = "/tmp/cathedral.secret";

if (kyrka_cathedral_config(ctx, &cfg) == -1)
	errx(1, "kyrka_cathedral_config: %d", kyrka_last_error(ctx));
```

You can also load encrypted vicar configurations in combination with
a cathedral config:

```c

/*
 * The loaded vicar config will set kek, cathedral id, secret, tunnel id
 * and flock inside of the supplied kyrka_cathedral_cfg struct.
 *
 * Meaning you do not need to set cfg.kek, cfg.secret, cfg.flock_src,
 * cfg.tunnel and cfg.identity.
 */

if (kyrka_vicar_load(ctx, "vicar.cfg", "passphrase", &cfg) == -1)
	errx(1, "kyrka_vicar_load: %d", kyrka_last_error(ctx));
```

Set both the heaven (clear) or purgatory (crypto) callbacks. These are
called by libkyrka when plaintext is available to be sent (on heaven)
or when ciphertext is available to be sent (on purgatory).

```c
void
heaven_send_packet(const void *data, size_t len, u_int64_t seq, void *udata)
{
	/*
	 * Cleartext data is ready to be sent, somewhere. Up to you where
	 * or what that means.
	 *
	 * The packet is sequence number is given in seq.
	 */
}

void
purgatory_send_packet(const void *data, size_t len, u_int64_t seq, void *udata)
{
	/*
	 * Ciphertext data is ready to be sent, somewhere. Up to you where
	 * or what that means.
	 *
	 * The packet is sequence number is given in seq.
	 */
}

...

if (kyrka_heaven_ifc(ctx, heaven_send_packet, NULL) == -1)
	errx(1, "kyrka_heaven_ifc: %d", kyrka_last_error(ctx));

if (kyrka_purgatory_ifc(ctx, purgatory_send_packet, NULL) == -1)
	errx(1, "kyrka_purgatory_ifc: %d", kyrka_last_error(ctx));
```

Your program is responsible for sending/receiving data and feeding
it to the correct function for encryption (kyrka_heaven_input()) or
decryption (kyrka_purgatory_input()).

```c
/* Send hello to our peer. */
if (kyrka_heaven_input(ctx, "hello", 5) == -1)
	errx(1, "kyrka_heaven_input: %d", kyrka_last_error(ctx));

/* Submit a received encrypted packet for decryption. */
if (kyrka_purgatory_input(ctx, pkt, pktlen) == -1)
	errx(1, "kyrka_purgatory_input: %d", kyrka_last_error(ctx));
```

Your program MUST call kyrka_key_manage() every event tick as this will
take care of the keying for you entirely.

When using a cathedral libkyrka can automatically rollover secrets
using the ambry distributions from the cathedral.

## Caveats

Some of the underlying libs that libkyrka uses will call a
fatal function in case of things that should never happen, happen.

I am aware this isn't ideal.

You can hook this using kyrka_fatal_callback() and passing
a function pointer to a function that is to be called when
this happens. This gives you the possibility to log the
error and cleanup your application resources.
