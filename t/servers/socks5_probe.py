#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Raw SOCKS5 client for asserting on the protocol itself, where curl only tells
# us "it failed". Performs the greeting (optionally RFC 1929 auth), sends one
# request, and prints exactly what came back:
#
#   REP=0xNN   the reply code from a well-formed reply
#   CLOSED     the proxy hung up without replying
#   SHORT=n    a truncated reply of n bytes
#   METHOD=NN  the greeting was answered with an unacceptable method (no request sent)
#
# Usage: socks5_probe.py [--host H] [--cmd N] [--atyp ipv4|ipv6|domain]
#                        [--dst D] [--user U] [--pass P] [--split] port dst_port
#
# --split writes the greeting one byte at a time, pausing between them, so it
# lands in separate TCP segments. A proxy must wait for the rest rather than
# decide the protocol on a partial greeting.
#
# --cmd defaults to 1 (CONNECT); pass 2 for BIND or 3 for UDP ASSOCIATE to
# check the "command not supported" path.
import socket, struct, sys, time

argv = sys.argv[1:]


def take_opt(name, default=None):
    if name in argv:
        i = argv.index(name)
        val = argv[i + 1]
        del argv[i:i + 2]
        return val
    return default


host = take_opt('--host', '127.0.0.1')
cmd = int(take_opt('--cmd', '1'))
atyp = take_opt('--atyp', 'ipv4')
dst = take_opt('--dst', '127.0.0.1')
user = take_opt('--user')
password = take_opt('--pass')
split = '--split' in argv
if split:
    argv.remove('--split')

port = int(argv[0])
dport = int(argv[1])

fam = socket.AF_INET6 if ':' in host else socket.AF_INET
s = socket.socket(fam, socket.SOCK_STREAM)
s.settimeout(10)
s.connect((host, port))

greeting = b'\x05\x02\x00\x02' if user is not None else b'\x05\x01\x00'
if split:
    for b in greeting:
        s.sendall(bytes([b]))
        time.sleep(0.05)
else:
    s.sendall(greeting)
sel = s.recv(2)
if len(sel) < 2:
    print('CLOSED')
    sys.exit(0)
if sel[1] == 0xff:
    print('METHOD=%02x' % sel[1])
    sys.exit(0)
if sel[1] == 0x02:
    u8 = user.encode()
    p8 = (password or '').encode()
    s.sendall(b'\x01' + bytes([len(u8)]) + u8 + bytes([len(p8)]) + p8)
    st = s.recv(2)
    if len(st) < 2 or st[1] != 0:
        print('AUTHFAIL')
        sys.exit(0)

if atyp == 'domain':
    d = dst.encode()
    addr = b'\x03' + bytes([len(d)]) + d
elif atyp == 'ipv6':
    addr = b'\x04' + socket.inet_pton(socket.AF_INET6, dst)
else:
    addr = b'\x01' + socket.inet_aton(dst)

s.sendall(bytes([0x05, cmd, 0x00]) + addr + struct.pack('!H', dport))

rep = s.recv(10)
if not rep:
    print('CLOSED')
elif len(rep) < 2:
    print('SHORT=%d' % len(rep))
else:
    print('REP=0x%02x' % rep[1])
