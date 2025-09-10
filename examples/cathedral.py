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

# A simple tunnel example that uses a cathedral.
#
# $ make python-mod
# $ cd examples
# $ PYTHONPATH=../obj/python python3 cathedral.py [args]
#
# Where args starts with a directory in which the following files are placed:
#    kek-0x<id>
#    id-<cs>
#
# followed by the flock id, kek <id>, the <cs> id, the tunnel
# you wish to establish and finally the cathedral ip and port.
#
# For example if you want to establish the tunnel 0102 in the flock abcdef
# with cs-id deadbeef to cathedral 1.2.3.4 port 4500:
#
# $ PYTHONPATH=../obj/python python3 cathedral.py dir abcdef 01 \
#   deadbeef 0x0102 1.2.3.4 4500
#/
import os
import sys
import time
import socket
import libkyrka
import selectors

if len(sys.argv) != 8:
    print("Usage: tunnel.py [dir] [flock] [kek] [cs] [tunnel] [ip] [port]")
    quit()

cfgdir = sys.argv[1]
flock = sys.argv[2]
kek = sys.argv[3]
cs = sys.argv[4]
tunnel = sys.argv[5]
ip = sys.argv[6]
port = int(sys.argv[7])

established = False

fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
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
        fd.sendto(data, (ip, port))
    except Exception as e:
        print(f"failed to send purgatory data: {e}")

def cathedral_send(ctx, data, magic, udata):
    try:
        if magic == libkyrka.KYRKA_CATHEDRAL_NAT_MAGIC:
            sp = port + 1
        else:
            sp = port

        fd.sendto(data, (ip, sp))
    except Exception as e:
        print(f"failed to send to cathedral: {e}")

ctx = libkyrka.alloc()

ctx.event_callback(event, None)
ctx.heaven_callback(heaven_recv, None)
ctx.purgatory_callback(purgatory_send, None)

ctx.cathedral_configure(
    udata=None,
    send=cathedral_send,
    kek=f"{cfgdir}/kek-0x{kek}",
    secret=f"{cfgdir}/id-{cs}",
    flock_src=int(flock, 16),
    flock_dst=int(flock, 16),
    group=0,
    tunnel=int(tunnel, 16),
    identity=int(cs, 16),
    hidden=False,
    remembrance=False
)

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

    try:
        ctx.cathedral_notify()
    except Exception as e:
        print(f"cathedral notify {e}")

    now = time.time()

    if established and now - last >= 5:
        last = now

        try:
            ctx.heaven_input(b"Blessed sanctum, save us")
        except Exception as e:
            print(f"heaven input {e}")
