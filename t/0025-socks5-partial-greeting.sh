#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Protocol detection must tolerate a first segment too short to decide on.
#
# The client's opening bytes are not guaranteed to arrive in one segment, and
# until VER and NMETHODS are both present the SOCKS5 parser cannot even reject
# a non-SOCKS5 first byte -- so on a one-byte read the protocol is simply not
# known yet and the only correct answer is to wait for more.
#
# Getting that wrong is not a corner case. The parser reports "need more data"
# as -EAGAIN, but the gwp_socks5_handle_data() wrapper folds -EAGAIN into 0 for
# its other caller; taking that 0 as success left the pair in CONN_STATE_PROT
# while claiming the state machine had advanced. epoll's dispatcher asserts on
# that combination, so a single byte from any client aborted the whole process,
# every worker and every live connection with it, before authentication and
# from anyone who could reach the port.
#
# Both halves are asserted separately because they fail differently, and only
# one of them is visible in a release build:
#
#   * survival -- the proxy must still be serving afterwards. This is the half
#     that catches the abort, and it is silent under -DNDEBUG, where the assert
#     is compiled out and the connection is merely dropped;
#   * progress -- a greeting split across segments must still complete a real
#     request end to end. Without this the test would pass trivially on a
#     release build against the very bug it is meant to pin.
#
# The single byte is sent as 0x05 (a truncated SOCKS5 greeting), as 'G' (the
# start of an HTTP request) and as 0xff (neither), because the parser gives up
# before it looks at the value -- so all three take the same path.

. "$(dirname "$0")/lib.sh"
require curl
require python3

DOC="$WORK/doc"
mkdir -p "$DOC"
make_payload "$DOC/index.html" 4096

hp="$(pick_port)"
start_httpd "$hp" "$DOC"

# Send one byte, then close. Returns 0 always: what matters is what the proxy
# does next, not what this connection got back.
poke()
{
	python3 -c '
import socket, sys, time
s = socket.socket()
s.settimeout(5)
s.connect(("127.0.0.1", int(sys.argv[1])))
s.sendall(bytes([int(sys.argv[2], 0)]))
time.sleep(0.1)
s.close()' "$1" "$2" 2>/dev/null
	return 0
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --target="127.0.0.1:$hp" --as-socks5=1 \
		--as-http=1 --event-loop="$loop" --nr-workers=1

	# Survival. A dead proxy is the abort; a live one that stopped
	# listening would be caught by the fetch below just the same.
	for b in 0x05 0x47 0xff; do
		poke "$p" "$b"
		kill -0 "$GWP_PID" 2>/dev/null || \
			fail "[$loop] proxy died on a one-byte first segment ($b)"
	done

	# ...and it is still serving, not merely alive.
	out="$WORK/after.$loop"
	curl -fsS --max-time 10 -x "socks5://127.0.0.1:$p" \
		"http://127.0.0.1:$hp/index.html" -o "$out" || \
		fail "[$loop] proxy stopped serving after the one-byte pokes"
	assert_files_equal "$DOC/index.html" "$out" \
		"[$loop] wrong payload after the one-byte pokes"

	# Progress: a greeting spread over three segments must still connect.
	# On a release build this is the assertion that discriminates -- the
	# assert is gone there, but the connection used to be dropped.
	rep="$($SERVERS_DIR/socks5_probe.py --split "$p" "$hp")"
	[ "$rep" = "REP=0x00" ] || \
		fail "[$loop] split greeting did not succeed (got '${rep:-<none>}')"

	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null

	# With a single front-end enabled there is no other parser to fall back
	# to, so a complete but foreign greeting is rejected outright and the
	# protocol stays undecided. That is ordinary garbage input, not an
	# impossible state: it must close the connection, not the process.
	for mode in "--as-socks5=1 --as-http=0:GET / HTTP/1.1" \
		    "--as-socks5=0 --as-http=1:\x05\x01\x00"; do
		args="${mode%%:*}"
		junk="${mode#*:}"
		p="$(pick_port)"
		# shellcheck disable=SC2086
		gwp_start "127.0.0.1:$p" --target="127.0.0.1:$hp" $args \
			--event-loop="$loop" --nr-workers=1
		printf "$junk\r\n\r\n" | timeout 5 python3 -c '
import socket, sys
s = socket.socket()
s.connect(("127.0.0.1", int(sys.argv[1])))
s.sendall(sys.stdin.buffer.read())
s.close()' "$p" 2>/dev/null
		sleep 0.3
		kill -0 "$GWP_PID" 2>/dev/null || \
			fail "[$loop] proxy died on a foreign greeting ($args)"
		kill "$GWP_PID" 2>/dev/null
		wait "$GWP_PID" 2>/dev/null
	done
done

pass
