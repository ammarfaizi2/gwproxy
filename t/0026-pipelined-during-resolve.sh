#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A client that speaks before its request has been answered.
#
# Between parsing a request for a domain name and having a target socket, the
# pair sits in a resolving/connecting state -- and the client stays armed for
# input, because arming the resolver only adds the resolver's own descriptor.
# So bytes pipelined behind the request are delivered to the protocol state
# machine at a point where it has nothing to parse.
#
# That used to be treated as an impossible state and abort the process:
#
#   Assertion `0 && "Invalid SOCKS5 connection state"' failed.
#
# Any client could do it, before authentication, and it took every worker and
# every live connection with it. It is a race -- the window is only as long as
# the lookup -- so this hammers it rather than trying once; a single attempt
# usually resolves before the second write lands and proves nothing.
#
# The name must be one that takes a moment and fails: the point is the window,
# not the connection. Each iteration uses a distinct name so a negative DNS
# cache cannot shorten it to nothing.
#
# Asserted for SOCKS5 and for HTTP CONNECT, on every event loop, and the proxy
# has to be serving afterwards rather than merely alive.

. "$(dirname "$0")/lib.sh"
require curl
require python3

DOC="$WORK/doc"
mkdir -p "$DOC"
make_payload "$DOC/index.html" 2048

hp="$(pick_port)"
start_httpd "$hp" "$DOC"

ROUNDS=60

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --target="127.0.0.1:$hp" --as-socks5=1 \
		--as-http=1 --event-loop="$loop" --nr-workers=1

	python3 -c '
import socket, sys
port, rounds = int(sys.argv[1]), int(sys.argv[2])
for i in range(rounds):
    # SOCKS5: greeting, then a domain CONNECT, then talk over the lookup.
    try:
        s = socket.socket(); s.settimeout(3)
        s.connect(("127.0.0.1", port))
        s.sendall(b"\x05\x01\x00"); s.recv(2)
        d = ("r%d-pipelined-during-resolve.example.com" % i).encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(d)]) + d + b"\x01\xbb")
        s.sendall(b"X" * 64)
        s.close()
    except Exception:
        pass
    # HTTP CONNECT: same shape on the other front-end.
    try:
        s = socket.socket(); s.settimeout(3)
        s.connect(("127.0.0.1", port))
        h = "h%d-pipelined-during-resolve.example.com" % i
        s.sendall(("CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n" % (h, h)).encode())
        s.sendall(b"X" * 64)
        s.close()
    except Exception:
        pass
' "$p" "$ROUNDS" 2>/dev/null

	kill -0 "$GWP_PID" 2>/dev/null || \
		fail "[$loop] proxy died on data pipelined behind a request"

	out="$WORK/after.$loop"
	curl -fsS --max-time 10 -x "socks5://127.0.0.1:$p" \
		"http://127.0.0.1:$hp/index.html" -o "$out" || \
		fail "[$loop] proxy stopped serving after the pipelined rounds"
	assert_files_equal "$DOC/index.html" "$out" \
		"[$loop] wrong payload after the pipelined rounds"

	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
done

pass
