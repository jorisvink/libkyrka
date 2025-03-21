# Kyrka

libkyrka implements the <a href="https://sanctorum.se/sanctum">sanctum</a>
protocol in library form allowing you to establish sanctum tunnels directly
from your application without the need for the actual daemon.

If you don't know what sanctum is, this isn't for you.

Note that while the sanctum daemon is built upon proper privilege separation,
the library will not provide this to you unless you do it yourself somehow.

Because it implements the sanctum protocol it can talk to sanctum daemons
and even make use of existing sanctum infrastructure (such as cathedrals
for discovery and relay or key distribution).

# Building

You will need libsodium as its used for the traffic encryption.

```
$ make
# make install
```

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
if (kyrka_secret_load(ctx, "/tmp/super.secret") == -1)
	errx(1, "kyrka_secret_load: %d", kyrka_last_error(ctx));
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

cfg.udata = NULL;
cfg.tunnel = 0x0102;
cfg.identity = 0xbadf00d;
cfg.kek = "/tmp/device-kek";
cfg.flock = 0xdeadbeefcafebabe;
cfg.send = cathedral_send_packet;
cfg.secret = "/tmp/cathedral.secret";

if (kyrka_cathedral_config(ctx, &cfg) == -1)
	errx(1, "kyrka_cathedral_config: %d", kyrka_last_error(ctx));
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
	 * Ciphertgext data is ready to be sent, somewhere. Up to you where
	 * or what that means.
	 *
	 * The packet is sequence number is given in seq.
	 */
}

...

if (kyrka_heaven_ifc(state.tunnel, heaven_send_packet, NULL) == -1)
	errx(1, "kyrka_heaven_ifc: %d", kyrka_last_error(ctx));

if (kyrka_purgatory_ifc(state.tunnel, purgatory_send_packet, NULL) == -1)
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

Your program is responsible for generating new keys via kyrka_key_generate()
and offering these to your peer via kyrka_key_offer().

```c
/* Generate fresh RX key every 3600 seconds. */
if ((now - last_key) >= 3600) {
	last_key = now;
	if (kyrka_key_generate(ctx) == -1)
		errx(1, "kyrka_key_generate: %d", kyrka_last_error(ctx));
}

...

/* Send our active key in wrapped form to our peer. */
if ((now - last_send) >= 10) {
	last_send = now;
	if (kyrka_key_offer(ctx) == -1)
		errx(1, "kyrka_key_offer: %d", kyrka_last_error(ctx));
}
```

You can choose yourself how often you want to rotate keys and offer
them to your peer.

When using a cathedral libkyrka can automatically rollover secrets
using the ambry distributions from the cathedral.

## Caveats

Due to its use of libnyfe underneath you will need to implement
a fatal() function in your code. I never got around to making
libnyfe a proper lib, maybe one day.

```c
void fatal(const char *fmt, ...);
```

This fatal() function must call nyfe_zeroize_all() followed by an exit().
