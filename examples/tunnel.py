#
# Copyright (c) 2025 Joris Vink <joris@sanctorum.se>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#/

# A simple tunnel example using the python mod for libkyrka.
# The api is essentially the C api.
#
# $ make python-mod
# $ cd examples
# $ dd if=/dev/urandom.c bs=32 count=1 of=secret.key
# $ PYTHONPATH=../obj/python python3 tunnel.py 127.0.0.1:1234 127.0.0.1:4321
# .. on another terminal ..
# $ PYTHONPATH=../obj/python python3 tunnel.py 127.0.0.1:4321 127.0.0.1:1234
#/

import os
import sys
import time
import socket
import libkyrka
import selectors

if len(sys.argv) != 3:
    print("Usage: tunnel [lip:lport] [rip:rport]");
    quit()

tmp = sys.argv[1].split(":")
local_addr = (tmp[0], int(tmp[1]))

tmp = sys.argv[2].split(":")
remote_addr = (tmp[0], int(tmp[1]))

print(f"{local_addr}")

established = False

fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
fd.bind(local_addr)
fd.setblocking(False)

def packet_recv(ctx, conn):
    data = conn.recv(1500)

    try:
        ctx.purgatory_input(data)
    except Exception as e:
        print(f"purgatory_input: {e}")

def event(ctx, event, info, udata):
    global established

    print(f"event: {event} {info}")

    try:
        if event == libkyrka.KYRKA_EVENT_KEYS_INFO:
            if info["tx"] != 0 and info["rx"] != 0:
                established = True
                print("tunnel established")
    except Exception as e:
        print(f"event callback: {e}")

def heaven_recv(ctx, data, sequence, udata):
    print(f"heaven_recv: {len(data)} <{data}> {sequence}")

def purgatory_send(ctx, data, sequence, udata):
    try:
        fd.sendto(data, remote_addr)
    except Exception as e:
        print(f"failed to send purgatory data: {e}")

ctx = libkyrka.alloc()

ctx.event_callback(event, None)
ctx.heaven_callback(heaven_recv, None)
ctx.purgatory_callback(purgatory_send, None)

try:
    with open("secret.key", "rb") as f:
        ctx.secret_load(f.read())
except Exception as e:
    print(f"error loading secret.key: {e}")
    quit()    

sel = selectors.DefaultSelector()
sel.register(fd, selectors.EVENT_READ, packet_recv)

last = 0

while True:
    events = sel.select(1)
    for key, mask in events:
        callback = key.data
        callback(ctx, key.fileobj)

    try:
        ctx.key_manage()
    except Exception as e:
        print(f"key manage {e}")

    now = time.time()

    if established and now - last >= 5:
        last = now

        try:
            ctx.heaven_input(b"Blessed sanctum, save us")
        except Exception as e:
            print(f"heaven input {e}")
