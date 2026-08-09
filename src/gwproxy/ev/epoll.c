// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <gwproxy/ev/epoll.h>
#include <gwproxy/common.h>
#include <gwproxy/acl.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <sys/inotify.h>
#ifdef CONFIG_HTTPS
#include <gwproxy/ssl.h>
#endif


static int arm_poll_for_dns_query(struct gwp_wrk *w, struct gwp_conn_pair *gcp);
#ifdef CONFIG_HTTPS
static int tls_flush_hs(struct gwp_conn *c);
#endif

#ifdef CONFIG_NEW_DNS_RESOLVER
#include <gwproxy/dns_resolver.h>
static int register_dns_to_epoll(struct gwp_wrk *w)
{
	struct gwp_wrk_dns *dns = w->dns;
	uint32_t i;

	if (!dns)
		return 0;

	for (i = 0; i < dns->nr; i++) {
		struct gwp_dns_resolver *res = &dns->resolvers[i];
		struct epoll_event ev;
		int r;

		if (res->udp_fd < 0)
			continue;

		/*
		 * The only tagged payload that is not a gwp_conn_pair, so it
		 * needs its own check against the same 48-bit budget.
		 */
		if (unlikely(!EV_PTR_OK(res))) {
			pr_err(&w->ctx->lh,
			       "BUG: DNS resolver %p has bits 48..63 set; the event word cannot carry it",
			       (void *)res);
			return -EOVERFLOW;
		}

		ev.events = EPOLLIN;
		ev.data.u64 = PTR_TO_U64(res) | EV_BIT_RAW_DNS_QUERY;
		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, res->udp_fd, &ev);
		if (r < 0) {
			pr_err(&w->ctx->lh,
			       "Failed to add raw DNS UDP socket to epoll: %s\n",
			       strerror(-r));
			return r;
		}

		pr_dbg(&w->ctx->lh,
			"Worker %u registered raw DNS UDP socket to epoll (fd=%d)",
			w->idx, res->udp_fd);
	}

	return 0;
}

static int send_dns_payload(struct gwp_dns_resolver *res,
			    struct gwp_conn_pair *gcp)
{
	struct gwp_dns_packet *gdp = gcp->gdp;
	const void *b = gdp->buf;
	size_t l = gdp->buf_len;
	ssize_t sr;

	sr = __sys_sendto(res->udp_fd, b, l, MSG_NOSIGNAL, NULL, 0);
	if (unlikely(sr < 0))
		return (int)sr;

	return 0;
}

static int chk_handle_dns_query(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_cfg *cfg = &w->ctx->cfg;

	if (cfg->use_raw_dns) {
		struct gwp_dns_resolver *res = &w->dns->resolvers[0];
		return send_dns_payload(res, gcp);
	}

	return arm_poll_for_dns_query(w, gcp);
}

static int prep_and_send_socks5_rep_connect(struct gwp_wrk *w,
					    struct gwp_conn_pair *gcp,
					    int err);

static int handle_connect(struct gwp_wrk *w, struct gwp_conn_pair *gcp);

static int handle_ev_raw_dns_query(struct gwp_wrk *w)
{
	struct gwp_dns_resolver *res = &w->dns->resolvers[0];
	struct gwp_conn_pair *gcp = NULL;
	struct gwp_ctx *ctx = w->ctx;
	uint8_t buf[UDP_MSG_LIMIT];
	uint16_t len;
	ssize_t ret;
	int r;

	ret = __sys_recv(res->udp_fd, buf, sizeof(buf), 0);
	if (unlikely(ret < 0))
		return (int)ret;

	len = (uint16_t)ret;
	ret = gwp_dns_res_fetch_gcp_by_payload(res, buf, len, &gcp);
	if (unlikely(ret < 0))
		return 0;

	ret = gwp_dns_res_complete_query(res, gcp->gdp, buf, len,
					 &gcp->target_addr);
	if (ret == -EAGAIN)
		return send_dns_payload(res, gcp);

	if (likely(!ret)) {
		pr_dbg(&ctx->lh, "Resolved DNS query for %s to %s (gcp_idx=%u)",
			gcp->gdp->host, ip_to_str(&gcp->target_addr), gcp->idx);
		/*
		 * The raw resolver still yields one address per reply, so
		 * there is nothing to fall back to here yet.
		 */
		gwp_conn_set_single_candidate(gcp, &gcp->target_addr);
		r = handle_connect(w, gcp);
	} else {
		if (gcp->conn_state == CONN_STATE_SOCKS5_DNS_QUERY)
			r = prep_and_send_socks5_rep_connect(w, gcp, (int)ret);
		else
			r = -EIO;
	}
	return r;
}
#else
static int register_dns_to_epoll(struct gwp_wrk __unused *w)
{
	return 0;
}

static int chk_handle_dns_query(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	return arm_poll_for_dns_query(w, gcp);
}

static int handle_ev_raw_dns_query(struct gwp_wrk __unused *w)
{
	return -ENOSYS;
}
#endif

static int connect_next_candidate(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				  int err);
static bool has_inflight_attempt(const struct gwp_conn_pair *gcp);

__cold
int gwp_ctx_init_thread_epoll(struct gwp_wrk *w)
{
	struct epoll_event ev, *events;
	struct gwp_ctx *ctx = w->ctx;
	int ep_fd, ev_fd, r;

	ep_fd = __sys_epoll_create1(EPOLL_CLOEXEC);
	if (ep_fd < 0) {
		r = ep_fd;
		pr_err(&w->ctx->lh, "Failed to create epoll instance: %s\n",
			strerror(-r));
		return r;
	}

	ev_fd = __sys_eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (ev_fd < 0) {
		r = ev_fd;
		pr_err(&w->ctx->lh, "Failed to create eventfd: %s\n", strerror(-r));
		goto out_close_ep_fd;
	}

	w->evsz = 512;
	events = calloc(w->evsz, sizeof(*events));
	if (!events) {
		r = -ENOMEM;
		pr_err(&w->ctx->lh, "Failed to allocate memory for events: %s\n",
			strerror(-r));
		goto out_close_ev_fd;
	}

	w->ev_fd = ev_fd;
	w->ep_fd = ep_fd;
	w->events = events;

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.u64 = EV_BIT_EVENTFD;
	r = __sys_epoll_ctl(ep_fd, EPOLL_CTL_ADD, ev_fd, &ev);
	if (unlikely(r))
		goto out_free_events;

	ev.events = EPOLLIN;
	ev.data.u64 = EV_BIT_ACCEPT;
	r = __sys_epoll_ctl(ep_fd, EPOLL_CTL_ADD, w->tcp_fd, &ev);
	if (unlikely(r))
		goto out_free_events;

	if (w->idx == 0 && (ctx->ino_fd >= 0)) {
		ev.events = EPOLLIN;
		ev.data.u64 = EV_BIT_SOCKS5_AUTH_FILE;
		r = __sys_epoll_ctl(ep_fd, EPOLL_CTL_ADD, ctx->ino_fd, &ev);
		if (unlikely(r))
			goto out_free_events;
	}

	if (w->idx == 0 && (ctx->acl_ino_fd >= 0)) {
		ev.events = EPOLLIN;
		ev.data.u64 = EV_BIT_ACL_FILE;
		r = __sys_epoll_ctl(ep_fd, EPOLL_CTL_ADD, ctx->acl_ino_fd, &ev);
		if (unlikely(r))
			goto out_free_events;
	}

	r = register_dns_to_epoll(w);
	if (r)
		goto out_free_events;

	/* Scratch for the SOCKS5 UDP relay; only reachable when as_socks5. */
	if (ctx->cfg.as_socks5) {
		w->udp_buf = malloc(GWP_UDP_RELAY_BUFSZ);
		if (!w->udp_buf) {
			r = -ENOMEM;
			goto out_free_events;
		}
	}

	pr_dbg(&w->ctx->lh, "Worker %u epoll (ep_fd=%d, ev_fd=%d)", w->idx,
		ep_fd, ev_fd);
	return 0;

out_free_events:
	free(events);
	w->events = NULL;
out_close_ev_fd:
	__sys_close(ev_fd);
out_close_ep_fd:
	__sys_close(ep_fd);
	w->ev_fd = w->ep_fd = -1;
	return r;
}

__cold
void gwp_ctx_free_thread_epoll(struct gwp_wrk *w)
{
	if (w->ev_fd >= 0) {
		__sys_close(w->ev_fd);
		pr_dbg(&w->ctx->lh, "Worker %u eventfd closed (fd=%d)", w->idx,
		       w->ev_fd);
		w->ev_fd = -1;
	}

	if (w->ep_fd >= 0) {
		__sys_close(w->ep_fd);
		pr_dbg(&w->ctx->lh, "Worker %u epoll closed (fd=%d)", w->idx,
		       w->ep_fd);
		w->ep_fd = -1;
	}

	free(w->events);
	w->events = NULL;
	free(w->udp_buf);
	w->udp_buf = NULL;
}

static int rearm_accept(struct gwp_wrk *w, int nr_fd_closed)
{
	struct gwp_ctx *ctx = w->ctx;
	struct epoll_event ev;
	int x, r;

	/*
	 * Each connection pair consists of at least 3 file descriptors:
	 *
	 *   1. TCP socket for the client connection.
	 *   2. TCP socket for the target connection.
	 *   3. Timer file descriptor (if used).
	 *
	 * Before rearming the main TCP socket, wait until we have free
	 * space for at least 3 connection pairs per worker thread.
	 */
	if (nr_fd_closed <= ((3 * ctx->cfg.nr_workers) * 3))
		return 0;

	ev.events = EPOLLIN;
	ev.data.u64 = EV_BIT_ACCEPT;
	r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, w->tcp_fd, &ev);
	if (unlikely(r))
		return r;

	w->accept_is_stopped = false;
	pr_info(&ctx->lh,
		"Rearmed main TCP socket for accepting new connections (tidx=%u, fd=%d)",
		w->idx, w->tcp_fd);

	x = atomic_fetch_sub(&ctx->nr_accept_stopped, 1);
	if (x == 1)
		atomic_store(&ctx->nr_fd_closed, 0);

	return 0;
}

__hot
static int free_conn_pair(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_dns_entry *gde = gcp->gde;
	struct gwp_ctx *ctx = w->ctx;
	int nr_fd_closed = 0;
	int r;

	if (!w->ctx->cfg.use_raw_dns) {
		if (gde) {
			r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_DEL, gde->ev_fd, NULL);
			if (unlikely(r))
				return r;
		}
	}

	if (gcp->client.fd >= 0) {
		nr_fd_closed++;
		w->ev_need_reload = true;
	}

	if (gcp->timer_fd >= 0)
		nr_fd_closed++;
	if (gcp->target.fd >= 0)
		nr_fd_closed++;
	if (gcp->udp_fd >= 0)
		nr_fd_closed++;

	/*
	 * A race that was still running when the pair went away: those sockets
	 * count too, or the accept path under-credits them and stays throttled.
	 */
	{
		uint8_t i;

		for (i = 0; i < GWP_MAX_CONN_CAND; i++)
			if (gcp->attempt_fd[i] >= 0)
				nr_fd_closed++;
		if (gcp->attempt_timer_fd >= 0)
			nr_fd_closed++;
	}

	r = gwp_free_conn_pair(w, gcp);
	if (unlikely(r)) {
		pr_err(&ctx->lh, "Failed to free connection pair: %s", strerror(-r));
		return r;
	}

	if (unlikely(w->accept_is_stopped)) {
		int x;
		/*
		 * If we have closed at least one file descriptor, we can
		 * rearm the main TCP socket with EPOLLIN to accept new
		 * connections.
		 */
		x = atomic_fetch_add(&ctx->nr_fd_closed, nr_fd_closed);
		r = rearm_accept(w, x);
		if (r)
			return r;
	}

	return 0;
}

__hot
static int handle_new_client(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	int target_fd, timer_fd, timeout, r;
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_cfg *cfg = &ctx->cfg;
	struct epoll_event ev;
	uint64_t cl_ev_bit;

	/*
	 * If we are running as a SOCKS5 proxy or an HTTP proxy, the initial
	 * connection does not have a target socket. We will create the target
	 * socket later.
	 */
	if (cfg->as_http || cfg->as_socks5) {
		gcp->is_target_alive = false;
		timeout = cfg->protocol_timeout;
		gcp->conn_state = CONN_STATE_PROT;
#ifdef CONFIG_HTTPS
		/*
		 * With a TLS listener, defer to a per-connection first-byte
		 * probe so plaintext SOCKS5/HTTP clients still work on the same
		 * port (see handle_ev_tls_detect()).
		 */
		if (ctx->ssl_ctx)
			gcp->conn_state = CONN_STATE_TLS_DETECT;
#endif
		cl_ev_bit = EV_BIT_CLIENT_PROT;
		target_fd = -1;
	} else {
		bool *p = &gcp->is_target_alive;
		struct gwp_sockaddr *ca = &gcp->target_addr;

		/*
		 * Plain and transparent forwarding connect at accept time (no
		 * SOCKS5/HTTP handshake, hence no reply): enforce the OUTPUT
		 * chain here and drop the connection if the target is denied.
		 */
		if (!gwp_ctx_acl_target_allowed(ctx, gcp)) {
			pr_info(&ctx->lh, "ACL denied target %s for client %s",
				ip_to_str(&gcp->target_addr),
				ip_to_str(&gcp->client_addr));
			return -EACCES;
		}

		/* With an upstream proxy, connect to the proxy instead. */
		if (ctx->upstream.enabled)
			ca = &ctx->upstream.addr;

		target_fd = gwp_create_sock_target(w, ca, &gcp->acl_sockopt, p,
						   true);
		if (target_fd < 0) {
			pr_err(&ctx->lh, "Failed to create target socket: %s",
				strerror(-target_fd));
			return target_fd;
		}
		timeout = cfg->connect_timeout;
		gcp->conn_state = CONN_STATE_FORWARDING;
		cl_ev_bit = EV_BIT_CLIENT;

		/*
		 * Force the connect-result path so the upstream handshake runs
		 * (see handle_ev_target_conn_result).
		 */
		if (ctx->upstream.enabled)
			gcp->is_target_alive = false;
	}

	if (timeout > 0) {
		timer_fd = gwp_create_timer(-1, timeout, 0);
		if (unlikely(timer_fd < 0)) {
			__sys_close(target_fd);
			return timer_fd;
		}
		gcp->timer_fd = timer_fd;
	} else {
		gcp->timer_fd = -1;
	}

	/*
	 * If epoll_ctl() fails, don't bother closing the target socket
	 * because it will be closed in free_conn_pair() anyway.
	 */
	gcp->target.fd = target_fd;
	gcp->client.ep_mask = EPOLLIN | EPOLLRDHUP;

	if (gcp->target.fd >= 0) {
		gcp->target.ep_mask = EPOLLOUT | EPOLLIN | EPOLLRDHUP;
		ev.events = gcp->target.ep_mask;
		ev.data.u64 = PTR_TO_U64(gcp) | EV_BIT_TARGET;
		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, gcp->target.fd, &ev);
		if (unlikely(r))
			return r;
	} else {
		gcp->target.ep_mask = 0;
	}

	ev.events = gcp->client.ep_mask;
	ev.data.u64 = PTR_TO_U64(gcp) | cl_ev_bit;
	r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, gcp->client.fd, &ev);
	if (unlikely(r))
		return r;

	if (gcp->timer_fd >= 0) {
		ev.events = EPOLLIN;
		ev.data.u64 = PTR_TO_U64(gcp) | EV_BIT_TIMER;
		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, gcp->timer_fd, &ev);
		if (unlikely(r))
			return r;
	}

	if (gcp->target.fd >= 0)
		log_conn_pair_created(w, gcp);

	return 0;
}

static int handle_accept_error(struct gwp_wrk *w, int e)
{
	int r;

	if (likely(e == -EAGAIN || e == -EINTR))
		return e;

	if (likely(e == -EMFILE || e == -ENFILE || e == -ENOMEM)) {
		/*
		 * We have reached the limit of open files. Delete the
		 * main TCP socket from the epoll instance to avoid
		 * getting EPOLLIN in the next epoll_wait() call.
		 *
		 * Set the accept_is_stopped flag to true to let the
		 * worker thread know that it should rearm the main
		 * TCP socket with EPOLLIN again after it has at least
		 * closed a file descriptor.
		 *
		 * See free_conn_pair() for more details.
		 */
		pr_warn(&w->ctx->lh, "Too many open files, stop accepting new connections");
		w->accept_is_stopped = true;
		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_DEL, w->tcp_fd, NULL);
		if (unlikely(r))
			return r;

		atomic_fetch_add(&w->ctx->nr_accept_stopped, 1);
		return -EAGAIN;
	}

	pr_err(&w->ctx->lh, "Failed to accept new connection: %s", strerror(-e));
	return e;
}

__hot
static int __handle_ev_accept(struct gwp_wrk *w)
{
	static const int flags = SOCK_NONBLOCK | SOCK_CLOEXEC;
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_cfg *cfg = &ctx->cfg;
	struct gwp_conn_pair *gcp;
	struct gwp_sockaddr addr;
	socklen_t addr_len;
	int fd, r;

	addr_len = sizeof(addr);
	fd = __sys_accept4(w->tcp_fd, &addr.sa, &addr_len, flags);
	if (fd < 0)
		return handle_accept_error(w, fd);

	gcp = gwp_alloc_conn_pair(w);
	if (unlikely(!gcp)) {
		pr_err(&ctx->lh, "Failed to allocate connection pair on accept");
		__sys_close(fd);
		return handle_accept_error(w, -ENOMEM);
	}

	gcp->client_addr = addr;
	gwp_setup_cli_sock_options(w, fd);
	gcp->client.fd = fd;
	pr_dbg(&ctx->lh, "New connection from %s (fd=%d)",
		ip_to_str(&gcp->client_addr), fd);

	if (!gwp_ctx_acl_client_allowed(ctx, &gcp->client_addr,
					GWP_ACL_PROTO_TCP)) {
		pr_info(&ctx->lh, "ACL denied client %s",
			ip_to_str(&gcp->client_addr));
		free_conn_pair(w, gcp);
		return 0;
	}

	if (cfg->as_transparent) {
		r = gwp_get_orig_dst(fd, &gcp->client_addr, &gcp->target_addr);
		if (r) {
			pr_warn(&ctx->lh, "No original destination for %s: %s (not a redirected connection?)",
				ip_to_str(&gcp->client_addr), strerror(-r));
			free_conn_pair(w, gcp);
			return 0;
		}
		gwp_conn_set_single_candidate(gcp, &gcp->target_addr);
	} else if (!cfg->as_socks5 && !cfg->as_http) {
		gwp_conn_set_single_candidate(gcp, &ctx->target_addr);
	}

	r = handle_new_client(w, gcp);
	if (r) {
		if (r == -EMFILE || r == -ENFILE)
			r = handle_accept_error(w, r);
		goto out_err;
	}

	return 0;

out_err:
	free_conn_pair(w, gcp);
	return r;
}

__hot
static int handle_ev_accept(struct gwp_wrk *w, struct epoll_event *ev)
{
	static const uint32_t nr_loop = 32;
	uint32_t i;
	int r;

	if (unlikely(ev->events & EPOLLERR)) {
		pr_err(&w->ctx->lh, "EPOLLERR on accept event");
		return -EIO;
	}

	for (i = 0; i < nr_loop; i++) {
		r = __handle_ev_accept(w);
		if (r) {
			if (likely(r == -EAGAIN || r == -EINTR)) {
				r = 0;
				break;
			}
			/*
			 * A per-connection failure: already logged, and the
			 * pair (if any) already freed. Returning it kills the
			 * worker, and gwp_ctx_thread_entry() then stops the
			 * whole proxy -- so a single client hitting
			 * ECONNABORTED could take every live connection down
			 * with it. accept(2) says to retry this class, and
			 * io_uring's loop never propagates it either. Keep
			 * draining the backlog instead. Otherwise whether the
			 * error escapes depends only on which of the 32
			 * iterations it landed on.
			 */
			r = 0;
		}
	}

	return r;
}

static int handle_ev_eventfd(struct gwp_wrk *w, struct epoll_event *ev)
{
	eventfd_t val;

	if (unlikely(ev->events & EPOLLERR)) {
		pr_err(&w->ctx->lh, "EPOLLERR on eventfd event");
		return -EIO;
	}

	return eventfd_read(w->ev_fd, &val);
}

static bool adj_epl_out(struct gwp_conn *src, struct gwp_conn *dst)
{
	bool want_out = src->len > 0;

#ifdef CONFIG_HTTPS
	/*
	 * A TLS destination may have ciphertext still queued in its send BIO
	 * (a short socket write, or a handshake/alert record) even when there
	 * is no plaintext to forward, so keep EPOLLOUT armed until it drains.
	 */
	if (dst->tls && gwp_ssl_bio_pending(dst->tls) > 0)
		want_out = true;
#endif

	/* Nothing to write, or the write side is already shut down. */
	if (want_out && !dst->wr_shut) {
		if (!(dst->ep_mask & EPOLLOUT)) {
			dst->ep_mask |= EPOLLOUT;
			return true;
		}
	} else {
		if (dst->ep_mask & EPOLLOUT) {
			dst->ep_mask &= ~EPOLLOUT;
			return true;
		}
	}

	return false;
}

static bool adj_epl_in(struct gwp_conn *src)
{
	uint32_t desired;

	/*
	 * Once this fd's read side is at EOF, stop listening for EPOLLIN and
	 * EPOLLRDHUP on it. While the buffer is full, keep RDHUP but drop IN
	 * so we still learn of a peer close under backpressure.
	 */
	if (src->rd_eof)
		desired = 0;
	else if (src->cap - src->len)
		desired = EPOLLIN | EPOLLRDHUP;
	else
		desired = EPOLLRDHUP;

	if ((src->ep_mask & (EPOLLIN | EPOLLRDHUP)) != desired) {
		src->ep_mask = (src->ep_mask & ~(EPOLLIN | EPOLLRDHUP)) | desired;
		return true;
	}

	return false;
}

__hot
static int adjust_epl_mask(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	bool client_need_ctl = false;
	bool target_need_ctl = false;
	struct epoll_event ev;
	int r;

	client_need_ctl |= adj_epl_out(&gcp->target, &gcp->client);
	target_need_ctl |= adj_epl_out(&gcp->client, &gcp->target);
	client_need_ctl |= adj_epl_in(&gcp->client);
	target_need_ctl |= adj_epl_in(&gcp->target);

	if (client_need_ctl) {
		ev.events = gcp->client.ep_mask;
		ev.data.u64 = PTR_TO_U64(gcp) | EV_BIT_CLIENT;

		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, gcp->client.fd, &ev);
		if (unlikely(r))
			return r;
	}

	if (target_need_ctl) {
		ev.events = gcp->target.ep_mask;
		ev.data.u64 = PTR_TO_U64(gcp) | EV_BIT_TARGET;

		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, gcp->target.fd, &ev);
		if (unlikely(r))
			return r;
	}

	return 0;
}

#ifdef CONFIG_HTTPS
/*
 * TLS receive: pull a chunk of ciphertext from the socket into the read BIO,
 * then decrypt as much as fits into src->buf. Any ciphertext left on the socket
 * (a record we only partially read, or more than one chunk's worth) keeps the
 * level-triggered EPOLLIN live so the rest is read on the next wakeup. Returns
 * the number of plaintext bytes produced, or <0 on error.
 */
static ssize_t do_recv_tls(struct gwp_conn *src)
{
	/*
	 * Ciphertext scratch. Kept on the stack and modestly sized: it must
	 * fit the -Wstack-usage budget, and a static __thread buffer passed to
	 * the inline-asm syscall miscompiles under gcc -O2. A partial TLS
	 * record simply stays queued in the socket and is read on the next
	 * (level-triggered) EPOLLIN, so a small buffer is only a throughput,
	 * not a correctness, matter.
	 */
	unsigned char cbuf[4096];
	size_t space, got;
	ssize_t n;
	int sr;

	space = src->cap - src->len;
	if (unlikely(space == 0))
		return 0;

	n = __sys_recv(src->fd, cbuf, sizeof(cbuf), MSG_NOSIGNAL);
	if (n > 0) {
		if (gwp_ssl_bio_write(src->tls, cbuf, (size_t)n) < 0)
			return -EIO;
	} else if (n == 0) {
		src->rd_eof = true;
	} else if (n != -EAGAIN && n != -EINTR) {
		return n;
	}

	got = 0;
	while (space) {
		size_t out = 0;

		sr = gwp_ssl_read(src->tls, src->buf + src->len, space, &out);
		if (sr == GWP_SSL_OK) {
			if (out == 0) {		/* clean close_notify */
				src->rd_eof = true;
				break;
			}
			src->len += (uint32_t)out;
			got += out;
			space -= out;
			continue;
		}
		if (sr == GWP_SSL_WANT_READ || sr == GWP_SSL_WANT_WRITE)
			break;
		return -EIO;
	}

	return (ssize_t)got;
}

/*
 * TLS send: encrypt as much of src->buf as the engine will take, then flush the
 * resulting ciphertext to dst->fd, consuming only what the socket accepts (a
 * memory BIO cannot push read bytes back). Unflushed ciphertext stays queued in
 * the BIO; adj_epl_out() keeps EPOLLOUT armed on a TLS peer while bytes remain.
 * Returns the number of ciphertext bytes flushed, or <0 on a fatal error.
 */
static ssize_t do_send_tls(struct gwp_conn *src, struct gwp_conn *dst)
{
	size_t sent = 0, plen;
	const void *p;
	ssize_t n;
	int sr;

	while (src->len) {
		size_t consumed = 0;

		sr = gwp_ssl_write(dst->tls, src->buf, src->len, &consumed);
		if (sr == GWP_SSL_OK) {
			gwp_conn_buf_advance(src, consumed);
			if (consumed == 0)
				break;
			continue;
		}
		if (sr == GWP_SSL_WANT_READ || sr == GWP_SSL_WANT_WRITE)
			break;		/* ciphertext must drain first */
		return -EIO;
	}

	while ((p = gwp_ssl_bio_peek(dst->tls, &plen)) != NULL) {
		n = __sys_send(dst->fd, p, plen, MSG_NOSIGNAL);
		if (n > 0) {
			gwp_ssl_bio_consume(dst->tls, (size_t)n);
			sent += (size_t)n;
			if ((size_t)n < plen)
				break;	/* socket full */
		} else if (n == -EAGAIN || n == -EINTR) {
			break;
		} else if (n == 0) {
			return -ECONNRESET;
		} else {
			return n;
		}
	}

	return (ssize_t)sent;
}
#endif /* CONFIG_HTTPS */

__hot
static ssize_t __do_recv(struct gwp_conn *src)
{
	ssize_t ret;
	size_t len;
	char *buf;

#ifdef CONFIG_HTTPS
	if (src->tls)
		return do_recv_tls(src);
#endif

	len = src->cap - src->len;
	if (unlikely(len == 0))
		return 0;

	buf = src->buf + src->len;
	ret = __sys_recv(src->fd, buf, len, MSG_NOSIGNAL);
	if (unlikely(ret < 0)) {
		if (ret != -EAGAIN && ret != -EINTR)
			return ret;
		ret = 0;
	} else if (!ret) {
		/*
		 * Peer closed its write side. Flag EOF instead of erroring so
		 * the caller can flush any buffered data before tearing the
		 * connection down (see forward_progress()).
		 */
		src->rd_eof = true;
		return 0;
	}

	src->len += (size_t)ret;
	assert(src->len <= src->cap);
	return ret;
}

__hot
static ssize_t __do_send(struct gwp_conn *src, struct gwp_conn *dst)
{
	ssize_t ret;

#ifdef CONFIG_HTTPS
	/*
	 * A TLS peer may still have queued ciphertext to flush even when there
	 * is no new plaintext (src->len == 0), so route through do_send_tls()
	 * unconditionally rather than short-circuiting on an empty source.
	 */
	if (dst->tls)
		return do_send_tls(src, dst);
#endif

	if (unlikely(src->len == 0))
		return 0;

	ret = __sys_send(dst->fd, src->buf, src->len, MSG_NOSIGNAL);
	if (unlikely(ret < 0)) {
		if (ret != -EAGAIN && ret != -EINTR)
			return ret;
		ret = 0;
	} else if (!ret) {
		return -ECONNRESET;
	}

	gwp_conn_buf_advance(src, (size_t)ret);
	return ret;
}

__hot
static int do_splice(struct gwp_conn *src, struct gwp_conn *dst, bool do_recv,
		     bool do_send)
{
	ssize_t ret;

	if (do_recv) {
		ret = __do_recv(src);
		if (unlikely(ret < 0))
			return (int)ret;
	}

	if (do_send) {
		ret = __do_send(src, dst);
		if (unlikely(ret < 0))
			return (int)ret;
	}

	return 0;
}

__hot
static int prep_and_send_socks5_rep_connect(struct gwp_wrk *w,
					    struct gwp_conn_pair *gcp,
					    int err)
{
	ssize_t sr;
	int r;

	r = gwp_socks5_prep_connect_reply(w, gcp, err);
	if (gcp->target.len) {
		sr = __do_send(&gcp->target, &gcp->client);
		if (unlikely(sr < 0))
			return (int)sr;
	}

	return r;
}

/*
 * ------------------------------------------------------------------------
 * Upstream SOCKS5 proxy client handshake (epoll).
 *
 * When ctx->upstream.enabled, the "target" socket is connected to an upstream
 * SOCKS5 proxy rather than the real destination. Before forwarding, we perform
 * the SOCKS5 client handshake on that socket:
 *
 *    greeting -> [user/pass auth] -> CONNECT(real dst) -> reply
 *
 * gcp->target is used as the I/O buffer for the proxy connection during the
 * handshake (it is otherwise unused until CONN_STATE_FORWARDING). Client data
 * that arrives meanwhile is buffered by handle_ev_client() because
 * is_target_alive is still false.
 * ------------------------------------------------------------------------
 */

/*
 * Describe the upstream destination for logging. With socks5h:// the real
 * destination is a hostname (target_addr is unset), so show up_dst instead.
 */
/*
 * A handshake with the upstream proxy failed. Inform the downstream client
 * with a SOCKS5 failure reply where applicable, then return @err so the
 * caller tears the connection down.
 */
static int upstream_fail(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			    int err)
{
	if (gcp->prot_type == GWP_PROT_TYPE_SOCKS5) {
		int r = prep_and_send_socks5_rep_connect(w, gcp, ECONNREFUSED);
		if (r)
			return r;
	}

	return err;
}

static int upstream_arm(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			uint32_t mask)
{
	struct epoll_event ev;

	gcp->target.ep_mask = mask;
	ev.events = mask;
	ev.data.u64 = PTR_TO_U64(gcp) | EV_BIT_TARGET;
	return __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, gcp->target.fd, &ev);
}

/* The upstream tunnel is up (reply already spliced); start forwarding. */
static int upstream_finish(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	ssize_t sr;

	if (gcp->timer_fd >= 0) {
		__sys_close(gcp->timer_fd);
		gcp->timer_fd = -1;
	}

	gcp->up_tx = false;
	gcp->is_target_alive = true;
	gcp->conn_state = CONN_STATE_FORWARDING;
	gcp->target.ep_mask = EPOLLOUT | EPOLLIN | EPOLLRDHUP;

	pr_info(&ctx->lh, "Upstream tunnel established (idx=%u, ca=%s, dst=%s)",
		gcp->idx, ip_to_str(&gcp->client_addr),
		gwp_upstream_dst_str(gcp));

	/* Flush downstream reply (+ early data) to the client. */
	if (gcp->target.len) {
		sr = __do_send(&gcp->target, &gcp->client);
		if (unlikely(sr < 0))
			return (int)sr;
	}

	/* Flush any client data buffered during the handshake to the target. */
	if (gcp->client.len) {
		sr = __do_send(&gcp->client, &gcp->target);
		if (unlikely(sr < 0))
			return (int)sr;
	}

	return adjust_epl_mask(w, gcp);
}

/* Begin the upstream-proxy handshake and arm the first request send. */
static int upstream_start(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	int r = gwp_upstream_hs_start(w, gcp);

	if (r == GWP_UPSTREAM_IO_SEND)
		return upstream_arm(w, gcp, EPOLLOUT | EPOLLRDHUP);
	return r;	/* negative errno */
}

__hot
static int handle_ev_upstream(struct gwp_wrk *w,
			      struct gwp_conn_pair *gcp,
			      struct epoll_event *ev)
{
	ssize_t sr;
	bool notify;
	int r;

	/* Transmit phase: flush the pending request to the proxy. */
	if (gcp->up_tx) {
		if (ev->events & EPOLLOUT) {
			sr = __do_send(&gcp->target, &gcp->target);
			if (unlikely(sr < 0))
				return (int)sr;
			if (gcp->target.len == 0)
				gcp->up_tx = false;
		}

		if (gcp->up_tx) {
			if (ev->events & (EPOLLRDHUP | EPOLLHUP))
				return -ECONNRESET;
			return upstream_arm(w, gcp, EPOLLOUT | EPOLLRDHUP);
		}

		/* Fully sent; wait for the reply. */
		return upstream_arm(w, gcp, EPOLLIN | EPOLLRDHUP);
	}

	/* Receive phase: read and parse the reply. */
	if (ev->events & EPOLLIN) {
		sr = __do_recv(&gcp->target);
		if (unlikely(sr < 0))
			return (int)sr;
		if (unlikely(gcp->target.rd_eof))
			return -ECONNRESET;
	}

	r = gwp_upstream_hs_on_reply(w, gcp, &notify);
	switch (r) {
	case GWP_UPSTREAM_IO_SEND:
		return upstream_arm(w, gcp, EPOLLOUT | EPOLLRDHUP);
	case GWP_UPSTREAM_IO_RECV:
		if (ev->events & (EPOLLRDHUP | EPOLLHUP))
			return -ECONNRESET;
		return upstream_arm(w, gcp, EPOLLIN | EPOLLRDHUP);
	case GWP_UPSTREAM_IO_DONE:
		return upstream_finish(w, gcp);
	default:			/* negative errno */
		return notify ? upstream_fail(w, gcp, r) : r;
	}
}

/*
 * An attempt won the race. Adopt its socket as the pair's target, drop every
 * other attempt and the attempt timer, and re-register the fd under the normal
 * target tag so the rest of the loop sees an ordinary connected target.
 */
static int adopt_winning_attempt(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				 uint8_t slot)
{
	struct epoll_event ev;
	int fd = gcp->attempt_fd[slot];
	int closed;

	gcp->attempt_fd[slot] = -1;
	closed = gwp_conn_close_attempts(gcp);
	if (closed) {
		/*
		 * Losing sockets are descriptors returned to the process; the
		 * accept path throttles on that count, so tell it.
		 */
		atomic_fetch_add(&w->ctx->nr_fd_closed, closed);
		w->ev_need_reload = true;
	}

	gcp->target.fd = fd;
	gcp->target.ep_mask = EPOLLOUT | EPOLLIN | EPOLLRDHUP;

	ev.events = gcp->target.ep_mask;
	ev.data.u64 = PTR_TO_U64(gcp) | EV_BIT_TARGET;
	return __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, fd, &ev);
}

__hot
static int handle_ev_target_conn_result(struct gwp_wrk *w,
					struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	int r;
	ssize_t sr;

	/*
	 * Connected to the upstream SOCKS5 proxy. Perform the client handshake
	 * before forwarding; the connect timer is kept to bound it.
	 */
	if (ctx->upstream.enabled)
		return upstream_start(w, gcp);

	if (gcp->timer_fd >= 0) {
		__sys_close(gcp->timer_fd);
		gcp->timer_fd = -1;
	}

	if (gcp->conn_state == CONN_STATE_SOCKS5_CONNECT) {
		r = prep_and_send_socks5_rep_connect(w, gcp, 0);
		if (r)
			return r;
	} else if (gcp->conn_state == CONN_STATE_HTTP_CONNECT) {
		/*
		 * "200 OK" for a CONNECT tunnel, nothing for a forwarding
		 * request -- whose rewritten origin-form request is already
		 * queued in client.buf and flushed to the origin below, with the
		 * origin's response relayed back.
		 */
		r = gwp_http_build_connect_reply(gcp->http_conn, gcp->target.buf,
						 gcp->target.cap);
		if (r < 0)
			return r;
		gcp->target.len = (uint32_t)r;
	}

	gcp->is_target_alive = true;
	gcp->conn_state = CONN_STATE_FORWARDING;

	if (gcp->client.len) {
		sr = __do_send(&gcp->client, &gcp->target);
		if (unlikely(sr < 0))
			return (int)sr;
	}

	return adjust_epl_mask(w, gcp);
}

/*
 * A racing connect attempt reported a result. The first one to succeed wins and
 * its socket becomes the target; a failure just retires that attempt, and only
 * when nothing is left in flight and no candidate remains does the client hear
 * about it.
 */
__hot
static int handle_ev_target_attempt(struct gwp_wrk *w,
				    struct gwp_conn_pair *gcp, uint8_t slot)
{
	struct gwp_ctx *ctx = w->ctx;
	socklen_t l = sizeof(int);
	int r, err = 0, fd;

	if (unlikely(slot >= GWP_MAX_CONN_CAND))
		return -EINVAL;

	fd = gcp->attempt_fd[slot];
	if (unlikely(fd < 0))
		return 0;		/* already retired */

	r = __sys_getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &l);
	if (unlikely(r < 0)) {
		pr_err(&ctx->lh, "getsockopt error: %s", strerror(-r));
		err = -r;
	}

	if (unlikely(err)) {
		pr_dbg(&ctx->lh, "Target attempt failed: %s (fd=%d, idx=%u, ta=%s)",
			strerror(err), fd, gcp->idx,
			ip_to_str(&gcp->target_addr));

		__sys_close(fd);
		gcp->attempt_fd[slot] = -1;
		atomic_fetch_add(&ctx->nr_fd_closed, 1);

		/*
		 * Another attempt may still be racing; only step to a new
		 * candidate once nothing is outstanding, so a slow-but-working
		 * address is not abandoned because a faster one was refused.
		 */
		if (has_inflight_attempt(gcp))
			return 0;

		return connect_next_candidate(w, gcp, -err);
	}

	/*
	 * Restore the address this attempt actually dialled: with a race the
	 * winner is often not the last one started, and target_addr currently
	 * holds whichever candidate was most recently set up. Using the
	 * recorded address also keeps a -j DNAT rewrite intact, which
	 * re-deriving from cand[] would silently undo.
	 */
	gcp->target_addr = gcp->attempt_addr[slot];
	pr_info(&ctx->lh, "Target socket connected (fd=%d, idx=%u, ca=%s, ta=%s)",
		fd, gcp->idx, ip_to_str(&gcp->client_addr),
		ip_to_str(&gcp->target_addr));

	r = adopt_winning_attempt(w, gcp, slot);
	if (unlikely(r))
		return r;

	return handle_ev_target_conn_result(w, gcp);
}

/*
 * After a forwarding splice, propagate half-closes and decide whether the
 * pair is done. Once a direction's source has reached EOF and everything it
 * sent has been flushed to the peer, shut the peer's write side so it sees the
 * FIN. When both directions have been shut, the pair is fully drained and is
 * torn down without dropping any buffered data.
 */
static int forward_progress(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	if (gcp->target.rd_eof && gcp->target.len == 0 && !gcp->client.wr_shut) {
#ifdef CONFIG_HTTPS
		/* Best-effort close_notify before closing the write side. */
		if (gcp->client.tls) {
			gwp_ssl_shutdown(gcp->client.tls);
			tls_flush_hs(&gcp->client);
		}
#endif
		__sys_shutdown(gcp->client.fd, SHUT_WR);
		gcp->client.wr_shut = true;
	}

	if (gcp->client.rd_eof && gcp->client.len == 0 && !gcp->target.wr_shut) {
		__sys_shutdown(gcp->target.fd, SHUT_WR);
		gcp->target.wr_shut = true;
	}

	if (gcp->client.wr_shut && gcp->target.wr_shut)
		return -ECONNRESET;

	return adjust_epl_mask(w, gcp);
}

/*
 * @c's fd hung up (EPOLLHUP) and its read side has already been drained to
 * EOF. No further I/O is possible on it, so mark its write side shut and stop
 * monitoring it (EPOLLHUP is level-triggered and would otherwise wake us in a
 * loop); forward_progress() then finishes the pair once the peer is flushed.
 */
static void handle_ev_hup(struct gwp_wrk *w, struct gwp_conn *c)
{
	c->wr_shut = true;
	if (c->ep_mask) {
		__sys_epoll_ctl(w->ep_fd, EPOLL_CTL_DEL, c->fd, NULL);
		c->ep_mask = 0;
	}
}

__hot
/*
 * The Connection Attempt Delay expired: bring the next candidate into the race
 * alongside the ones already running. Nothing is cancelled here -- an attempt
 * that is merely slow may still win.
 */
static int handle_ev_attempt_timer(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	uint64_t val;

	if (gcp->attempt_timer_fd < 0)
		return 0;

	/* Drain the timerfd or it stays readable and spins the loop. */
	__sys_read(gcp->attempt_timer_fd, &val, sizeof(val));

	if (gcp->next_cand >= gcp->nr_cand) {
		__sys_close(gcp->attempt_timer_fd);
		gcp->attempt_timer_fd = -1;
		return 0;
	}

	/*
	 * -EINPROGRESS is not a failure to report: attempts are still running,
	 * and connect_next_candidate() only speaks to the client once nothing
	 * is left in flight.
	 */
	return connect_next_candidate(w, gcp, -EINPROGRESS);
}

static int handle_ev_target(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			    struct epoll_event *ev)
{
	int r;

	if (unlikely(ev->events & EPOLLERR)) {
		/*
		 * A connect() that failed reports EPOLLERR, so bailing out
		 * here dropped the client without a reply -- a refused target
		 * is the common case. Hand it to the connect-result path,
		 * which reads SO_ERROR and answers with the matching REP.
		 */
		if (!gcp->is_target_alive)
			return handle_ev_target_conn_result(w, gcp);

		pr_err(&w->ctx->lh, "EPOLLERR on target connection event");
		return -ECONNRESET;
	}

	if (!gcp->is_target_alive) {
		int cs = gcp->conn_state;

		if (cs >= CONN_STATE_UPSTREAM_S5_MIN &&
		    cs <= CONN_STATE_UPSTREAM_HTTP_MAX)
			return handle_ev_upstream(w, gcp, ev);

		return handle_ev_target_conn_result(w, gcp);
	}

	assert(gcp->conn_state == CONN_STATE_FORWARDING);

	/*
	 * Drain on EPOLLHUP as well as EPOLLIN: a hung-up socket can still have
	 * unread data in its receive buffer, and EPOLLIN keeps firing (level
	 * triggered) until recv() returns 0 and sets rd_eof.
	 */
	if (ev->events & (EPOLLIN | EPOLLHUP)) {
		r = do_splice(&gcp->target, &gcp->client, true, true);
		if (r)
			return r;
	}

	if (ev->events & EPOLLOUT) {
		r = do_splice(&gcp->client, &gcp->target, true, true);
		if (r)
			return r;
	}

	if ((ev->events & EPOLLHUP) && gcp->target.rd_eof)
		handle_ev_hup(w, &gcp->target);

	return forward_progress(w, gcp);
}

__hot
static int handle_ev_client(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			    struct epoll_event *ev)
{
	int r;

	if (unlikely(ev->events & EPOLLERR)) {
		pr_err(&w->ctx->lh, "EPOLLERR on client connection event");
		return -ECONNRESET;
	}

	if (ev->events & (EPOLLIN | EPOLLHUP)) {
		r = do_splice(&gcp->client, &gcp->target, true, gcp->is_target_alive);
		if (r)
			return r;
	}

	if (ev->events & EPOLLOUT) {
		r = do_splice(&gcp->target, &gcp->client, true, true);
		if (r)
			return r;
	}

	if ((ev->events & EPOLLHUP) && gcp->client.rd_eof)
		handle_ev_hup(w, &gcp->client);

	return forward_progress(w, gcp);
}

__hot
static int handle_ev_timer(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;

	if (gcp->timer_fd < 0)
		return 0;

	pr_warn(&ctx->lh, "Connection timeout! (idx=%u, cfd=%d, tfd=%d, ca=%s, ta=%s)",
		gcp->idx, gcp->client.fd, gcp->target.fd,
		ip_to_str(&gcp->client_addr), ip_to_str(&gcp->target_addr));

	/*
	 * A target socket that never came up: tell the client the origin timed
	 * out (SOCKS5 REP 0x06, HTTP 504) instead of just dropping it. Only
	 * once the target socket exists -- the other user of this timer is the
	 * protocol handshake, where the client has not asked for anything yet
	 * and a CONNECT reply would answer a request that was never made.
	 */
	if ((gcp->target.fd >= 0 || has_inflight_attempt(gcp)) &&
	    !gcp->is_target_alive &&
	    !gwp_conn_fail_reply(w, gcp, -ETIMEDOUT) && gcp->target.len) {
		ssize_t sr = __do_send(&gcp->target, &gcp->client);

		if (unlikely(sr < 0))
			return (int)sr;
	}

	return -ETIMEDOUT;
}

__hot
/*
 * The ACL rejected this target: tell the client (SOCKS5 REP 0x02, or HTTP 403)
 * and return an error so the caller tears the connection down. The reply is
 * sent synchronously here, so it works from both the handshake and the async
 * DNS-completion callers of handle_connect().
 */
static int acl_reject_target(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	int r = gwp_acl_reject_reply(w, gcp);

	if (r != -EACCES)
		return r;

	if (gcp->target.len) {
		ssize_t sr = __do_send(&gcp->target, &gcp->client);

		if (sr < 0)
			return (int)sr;
	}
	return -EACCES;
}

/*
 * Start one connect attempt to gcp->target_addr, which the caller has already
 * selected and had the ACL approve. Registers the new target fd with epoll.
 * Returns 0 once the attempt is in flight (or has already completed), or a
 * negative errno if this attempt could not be started at all -- the caller
 * decides whether another candidate is worth trying.
 */
/* Are any connect attempts of this pair still waiting for a result? */
static bool has_inflight_attempt(const struct gwp_conn_pair *gcp)
{
	uint8_t i;

	for (i = 0; i < GWP_MAX_CONN_CAND; i++) {
		if (gcp->attempt_fd[i] >= 0)
			return true;
	}
	return false;
}

/*
 * Start one connect attempt to gcp->target_addr, which the caller has already
 * selected and had the ACL approve. The socket goes into attempt slot @slot and
 * is registered under its own event tag, so several attempts can be in flight
 * at once and each completion is attributable. Returns 0 once the attempt is
 * running, or a negative errno if it could not be started.
 */
static int start_connect_attempt(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				 uint8_t slot)
{
	struct epoll_event ev;
	bool alive = false;
	int tfd, r;

	if (w->ctx->upstream.enabled) {
		/* Connect to the upstream proxy, not the real destination. */
		tfd = gwp_create_sock_target(w, &w->ctx->upstream.addr,
					     &gcp->acl_sockopt, &alive, true);
	} else {
		tfd = gwp_create_sock_target(w, &gcp->target_addr,
					     &gcp->acl_sockopt, &alive, true);
	}
	if (unlikely(tfd < 0))
		return tfd;

	gcp->attempt_fd[slot] = tfd;
	/* Post-ACL, so a -j DNAT rewrite is what gets recorded. */
	gcp->attempt_addr[slot] = gcp->target_addr;

	/*
	 * Even a connect that completed synchronously is reported through the
	 * event loop, so the winner is picked in exactly one place.
	 */
	ev.events = EPOLLOUT | EPOLLRDHUP;
	ev.data.u64 = PTR_TO_U64(gcp) |
		      (EV_BIT_TARGET_ATTEMPT + ((uint64_t)slot << 48ull));
	r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, tfd, &ev);
	if (unlikely(r)) {
		__sys_close(tfd);
		gcp->attempt_fd[slot] = -1;
		return r;
	}

	return 0;
}

/*
 * Arm the delay after which the next candidate joins the race. Racing is what
 * makes a black-holed address cheap: without it a target that silently drops
 * SYNs costs the whole connect timeout before anything else is tried.
 */
static int arm_attempt_timer(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct epoll_event ev;
	int r, ms;

	if (gcp->next_cand >= gcp->nr_cand)
		return 0;			/* nothing left to start */
	if (w->ctx->cfg.connect_attempt_delay <= 0)
		return 0;			/* racing disabled: fall back only */
	if (w->ctx->upstream.enabled)
		return 0;			/* one proxy, nothing to race */

	ms = w->ctx->cfg.connect_attempt_delay;
	if (gcp->attempt_timer_fd < 0) {
		r = gwp_create_timer(-1, ms / 1000, (ms % 1000) * 1000000);
		if (unlikely(r < 0))
			return r;
		gcp->attempt_timer_fd = r;

		ev.events = EPOLLIN;
		ev.data.u64 = PTR_TO_U64(gcp) | EV_BIT_ATTEMPT_TIMER;
		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD,
				    gcp->attempt_timer_fd, &ev);
		if (unlikely(r))
			return r;
	} else {
		r = gwp_create_timer(gcp->attempt_timer_fd, ms / 1000,
				     (ms % 1000) * 1000000);
		if (unlikely(r < 0))
			return r;
	}

	return 0;
}

/*
 * Start the next candidate address, having already tried (or not yet started)
 * the others. @err is why the previous attempt failed, reported to the client
 * if no candidate is left. Returns 0 once an attempt is in flight, or a
 * negative errno once they are exhausted.
 *
 * A candidate the ACL rejects is skipped rather than being fatal: the rule
 * denied that address, not the name, and another address of the same host may
 * well be permitted. Only when every candidate is denied does the client get
 * the ACL rejection.
 */
static int connect_next_candidate(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				  int err)
{
	bool acl_denied = false;
	int r;

	/*
	 * No candidate list at all: socks5h:// hands the hostname to the
	 * upstream proxy and never resolves it here, so target_addr stays
	 * unset and there is exactly one connect to make -- to the upstream.
	 * Attempt it once, leaving target_addr untouched so the ACL keeps
	 * seeing "no resolved IP" and matches on -m domain as before.
	 */
	if (!gcp->nr_cand) {
		if (gcp->next_cand)
			goto exhausted;

		gcp->next_cand = 1;
		if (!gwp_ctx_acl_target_allowed(w->ctx, gcp))
			return acl_reject_target(w, gcp);

		err = start_connect_attempt(w, gcp, 0);
		if (!err)
			return 0;
		goto exhausted;
	}

	while (gcp->next_cand < gcp->nr_cand) {
		uint8_t slot = gcp->next_cand;

		gcp->target_addr = gcp->cand[gcp->next_cand++];

		if (!gwp_ctx_acl_target_allowed(w->ctx, gcp)) {
			acl_denied = true;
			continue;
		}

		gcp->flags |= GWP_CONN_FLAG_ACL_CAND_OK;
		err = start_connect_attempt(w, gcp, slot);
		if (!err) {
			/*
			 * Racing: do not wait for this attempt to resolve
			 * before queueing the next one.
			 */
			r = arm_attempt_timer(w, gcp);
			if (unlikely(r))
				return r;
			return 0;
		}

		pr_dbg(&w->ctx->lh, "Target %s did not start: %s (idx=%u)",
			ip_to_str(&gcp->target_addr), strerror(-err), gcp->idx);

		/*
		 * Chaining: every attempt dials the same upstream proxy, so
		 * walking the target's addresses would just repeat the same
		 * failure. The candidates still matter for the ACL above and
		 * for the destination named to the upstream.
		 */
		if (w->ctx->upstream.enabled)
			break;
	}

	/*
	 * Nothing new could be started. If earlier attempts are still racing,
	 * one of them may yet succeed -- wait for it rather than failing now.
	 */
	if (has_inflight_attempt(gcp))
		return 0;

	/*
	 * The ACL is the reason this request failed only if it denied every
	 * candidate. Once any address was allowed -- possibly on an earlier
	 * walk, whose attempt has since failed -- the honest answer is that
	 * attempt's error, not a rejection that applies to the addresses we
	 * merely skipped.
	 */
	if (acl_denied && !(gcp->flags & GWP_CONN_FLAG_ACL_CAND_OK))
		return acl_reject_target(w, gcp);

exhausted:
	pr_dbg(&w->ctx->lh, "No target address left to try (idx=%u): %s",
		gcp->idx, strerror(-err));

	if (!gwp_conn_fail_reply(w, gcp, err) && gcp->target.len) {
		ssize_t sr = __do_send(&gcp->target, &gcp->client);

		if (unlikely(sr < 0))
			return (int)sr;
	}
	return err;
}

static int handle_connect(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	int r;

	if (gcp->timer_fd >= 0) {
		/*
		 * If we already have a timer fd, close it and use the new
		 * timer fd instead. There are two timers used in the socks5
		 * case:
		 *
		 *    1. Timer for waiting socks5 auth and command.
		 *    2. Timer for waiting target connect().
		 *
		 * If we've reached this point. Timer no (1) has already
		 * served its purpose and we can close it.
		 */
		__sys_close(gcp->timer_fd);
		gcp->timer_fd = -1;
	}

	/*
	 * The connect timeout bounds the whole operation, across every
	 * candidate address, so it is armed once here rather than per attempt.
	 */
	r = w->ctx->cfg.connect_timeout;
	if (r > 0) {
		struct epoll_event tev;

		r = gwp_create_timer(-1, r, 0);
		if (unlikely(r < 0))
			return r;
		gcp->timer_fd = r;

		tev.events = EPOLLIN;
		tev.data.u64 = PTR_TO_U64(gcp) | EV_BIT_TIMER;
		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, gcp->timer_fd, &tev);
		if (unlikely(r))
			return r;
	}

	/*
	 * If epoll_ctl() calls fail, don't bother closing the
	 * newly created file descriptors as they will be closed
	 * in free_conn_pair() anyway.
	 */
	{
		struct epoll_event ev;

		ev.events = gcp->client.ep_mask;
		ev.data.u64 = PTR_TO_U64(gcp) | EV_BIT_CLIENT;
		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, gcp->client.fd, &ev);
		if (unlikely(r))
			return r;
	}

	/*
	 * Take the first candidate the ACL allows; the same helper walks the
	 * rest, so a candidate that cannot even be started is not fatal while
	 * others remain.
	 */
	r = connect_next_candidate(w, gcp, -EHOSTUNREACH);
	if (r)
		return r;

	r = gcp->conn_state;
	if (CONN_STATE_SOCKS5_MIN <= r && r <= CONN_STATE_SOCKS5_MAX)
		gcp->conn_state = CONN_STATE_SOCKS5_CONNECT;
	else if (CONN_STATE_HTTP_MIN <= r && r <= CONN_STATE_HTTP_MAX)
		gcp->conn_state = CONN_STATE_HTTP_CONNECT;

	log_conn_pair_created(w, gcp);
	return 0;
}

static int arm_poll_for_dns_query(struct gwp_wrk *w,
					struct gwp_conn_pair *gcp)
{
	struct gwp_dns_entry *gde = gcp->gde;
	struct epoll_event ev;
	int r;

	assert(gde);
	assert(gde->ev_fd >= 0);

	ev.events = EPOLLIN;
	ev.data.u64 = PTR_TO_U64(gcp) | EV_BIT_DNS_QUERY;

	r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, gde->ev_fd, &ev);
	if (unlikely(r))
		return r;

	return 0;
}

static void log_dns_query(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			  struct gwp_dns_entry *gde)
{
	struct gwp_ctx *ctx = w->ctx;

	if (gde->res) {
		pr_dbg(&ctx->lh, "DNS query failed: %s:%s (res=%d; idx=%u; cfd=%d; tfd=%d; ca=%s)",
			gde->name, gde->service, gde->res,
			gcp->idx, gcp->client.fd, gcp->target.fd,
			ip_to_str(&gcp->client_addr));
		return;
	}

	pr_dbg(&ctx->lh, "DNS query resolved: %s:%s -> %s (res=%d; idx=%u; cfd=%d; tfd=%d; ca=%s)",
		gde->name, gde->service, ip_to_str(&gde->addrs[0]), gde->res,
		gcp->idx, gcp->client.fd, gcp->target.fd,
		ip_to_str(&gcp->client_addr));
}

__hot
static int handle_ev_dns_query(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_dns_entry *gde = gcp->gde;
	int r;

	assert(gde);
	assert(gde->ev_fd >= 0);
	assert(gcp->conn_state == CONN_STATE_SOCKS5_DNS_QUERY ||
	       gcp->conn_state == CONN_STATE_HTTP_DNS_QUERY);

	r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_DEL, gde->ev_fd, NULL);
	if (unlikely(r))
		return r;

	log_dns_query(w, gcp, gde);
	if (likely(!gde->res)) {
		gwp_conn_set_candidates(gcp, gde->addrs, gde->nr_addrs);
		r = handle_connect(w, gcp);
	} else {
		/*
		 * The name did not resolve, so the origin is unreachable:
		 * answer in whatever protocol the client speaks (SOCKS5 REP,
		 * or HTTP 502) instead of hanging up silently.
		 */
		r = gwp_conn_fail_reply(w, gcp, gde->res);
		if (!r && gcp->target.len) {
			ssize_t sr = __do_send(&gcp->target, &gcp->client);

			if (unlikely(sr < 0))
				r = (int)sr;
		}
		if (!r)
			r = gde->res ? gde->res : -EIO;
	}

	gwp_dns_entry_put(gde);
	gcp->gde = NULL;
	return r;
}

static int handle_ev_auth_file(struct gwp_wrk *w)
{
	static const size_t l = sizeof(struct inotify_event) + NAME_MAX + 1;
	ssize_t r;

	assert(w->ctx->auth);

	r = __sys_read(w->ctx->ino_fd, w->ctx->ino_buf, l);
	if (unlikely(r < 0)) {
		if (r == -EINTR || r == -EAGAIN)
			return 0;

		pr_err(&w->ctx->lh, "Failed to read inotify event: %s", strerror((int)-r));
		return (int)r;
	}

	if (!gwp_inotify_event_matches(w->ctx->ino_buf, (size_t)r,
				       w->ctx->cfg.auth_file))
		return 0;

	gwp_auth_reload(w->ctx->auth);
	pr_info(&w->ctx->lh, "Reloaded authentication file");
	return 0;
}

static int handle_ev_acl_file(struct gwp_wrk *w)
{
	static const size_t l = sizeof(struct inotify_event) + NAME_MAX + 1;
	struct gwp_ctx *ctx = w->ctx;
	ssize_t r;

	assert(ctx->acl);

	r = __sys_read(ctx->acl_ino_fd, ctx->acl_ino_buf, l);
	if (unlikely(r < 0)) {
		if (r == -EINTR || r == -EAGAIN)
			return 0;

		pr_err(&ctx->lh, "Failed to read ACL inotify event: %s",
			strerror((int)-r));
		return (int)r;
	}

	if (!gwp_inotify_event_matches(ctx->acl_ino_buf, (size_t)r,
				       ctx->cfg.acl_file))
		return 0;

	if (gwp_acl_reload(ctx->acl))
		pr_warn(&ctx->lh, "Failed to reload ACL file; keeping current rules");
	else
		pr_info(&ctx->lh, "Reloaded ACL file");
	return 0;
}

static bool is_ev_bit_conn_pair(uint64_t ev_bit)
{
	/* Every attempt slot of a Happy Eyeballs race points at the pair. */
	if (ev_bit >= EV_BIT_TARGET_ATTEMPT &&
	    ev_bit < EV_BIT_TARGET_ATTEMPT +
		     ((uint64_t)GWP_MAX_CONN_CAND << 48ull))
		return true;

	switch (ev_bit) {
	case EV_BIT_CLIENT:
	case EV_BIT_TARGET:
	case EV_BIT_TIMER:
	case EV_BIT_ATTEMPT_TIMER:
	case EV_BIT_CLIENT_SOCKS5:
	case EV_BIT_DNS_QUERY:
	case EV_BIT_CLIENT_PROT:
	case EV_BIT_UDP_RELAY:
		return true;
	default:
		return false;
	}
}

/*
 * SOCKS5 UDP relay: drain the per-connection relay socket. A datagram whose
 * source is (or, for the first one, becomes) the pinned client is unwrapped and
 * forwarded to its encapsulated target; any other source is a target's reply,
 * which is wrapped with a SOCKS5 UDP header and sent back to the client. UDP is
 * lossy, so individual datagram errors are dropped rather than failing the
 * association; only the TCP control connection's close tears it down.
 *
 * The relay socket is dual-stack, so IPv4 and IPv6 targets both work; an IPv4
 * target's address is carried v4-mapped internally and unmapped again for the
 * reply header (see gwp_socks5_addr_to_sockaddr / reply_addr_from_sockaddr).
 *
 * Known limitations, each a follow-up:
 *   - The relay is stateless: it forwards to any encapsulated target and
 *     accepts a reply from any non-client source, without tracking which
 *     targets the client contacted. An off-path host that guesses the
 *     ephemeral relay port can thus inject a forged "target reply" to the
 *     client. Pinning validates the client's IP against the TCP control
 *     connection, so this is bounded to injection (not association hijack);
 *     restricting replies to previously-contacted targets is the fix.
 *   - Domain-name (ATYP=0x03) encapsulated targets need DNS in the datagram
 *     path and are dropped for now.
 *   - There is no target ACL, so this shares the SSRF exposure of any proxy.
 */
static int handle_ev_udp_relay(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	const size_t off = GWP_SOCKS5_UDP_HDR_MAX;
	unsigned char *buf = w->udp_buf;
	int fd = gcp->udp_fd;
	int budget = 64;

	/*
	 * Drain in bounded batches rather than until EAGAIN: a flood on one
	 * association must not starve the rest of the worker. Any datagrams
	 * left unread keep the socket readable, so level-triggered epoll
	 * re-enters this handler on the next wakeup.
	 */
	while (budget-- > 0) {
		struct gwp_sockaddr src;
		socklen_t srclen = sizeof(src);
		struct gwp_udp_out out;
		ssize_t n;

		n = __sys_recvfrom(fd, buf + off, 65535, MSG_NOSIGNAL,
				   &src.sa, &srclen);
		if (n < 0) {
			if (n != -EAGAIN && n != -EINTR)
				pr_dbg(&w->ctx->lh, "UDP relay recvfrom: %s",
					strerror((int)-n));
			return 0;
		}

		if (gwp_udp_relay_classify(w, gcp, buf + off, (size_t)n, &src,
					   &out) == GWP_UDP_DROP)
			continue;

		__sys_sendto(fd, out.buf, out.len, MSG_NOSIGNAL, &out.dst.sa,
			     out.dstlen);
	}

	return 0;
}

/*
 * Register the freshly-bound UDP relay socket; its reply is flushed by the
 * generic prot path.
 */
static int handle_udp_associate(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct epoll_event ev;

	/*
	 * The association is long-lived, so drop the protocol-handshake timeout
	 * that was armed for the negotiation; otherwise it would fire and tear
	 * the relay down mid-session. Closing the timerfd removes it from epoll.
	 */
	if (gcp->timer_fd >= 0) {
		__sys_close(gcp->timer_fd);
		gcp->timer_fd = -1;
	}

	ev.events = EPOLLIN;
	ev.data.u64 = PTR_TO_U64(gcp) | EV_BIT_UDP_RELAY;
	return __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, gcp->udp_fd, &ev);
}

static int chk_socks5(struct gwp_wrk *w, struct gwp_conn_pair *gcp, int r)
{
	if (r == -EINPROGRESS && gcp->conn_state == CONN_STATE_SOCKS5_DNS_QUERY)
		return chk_handle_dns_query(w, gcp);

	if (r == 0 && gcp->conn_state == CONN_STATE_SOCKS5_CONNECT)
		return handle_connect(w, gcp);

	if (r == 0 && gcp->conn_state == CONN_STATE_SOCKS5_UDP_ASSOCIATE)
		return handle_udp_associate(w, gcp);

	return r;
}

static int handle_conn_state_socks5(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	return chk_socks5(w, gcp, gwp_handle_conn_state_socks5(w, gcp));
}

static int chk_http(struct gwp_wrk *w, struct gwp_conn_pair *gcp, int r)
{
	if (r == -EINPROGRESS && gcp->conn_state == CONN_STATE_HTTP_DNS_QUERY)
		return arm_poll_for_dns_query(w, gcp);

	if (r == 0 && gcp->conn_state == CONN_STATE_HTTP_CONNECT)
		return handle_connect(w, gcp);

	return r;
}

static int handle_conn_state_http(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	return chk_http(w, gcp, gwp_handle_conn_state_http(w, gcp));
}

static int handle_conn_state_prot(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	int ct, r = gwp_handle_conn_state_prot(w, gcp);

	if (r == -EAGAIN)
		return r;

	ct = gcp->conn_state;
	if (ct == CONN_STATE_PROT) {
		/*
		 * Still undecided, so no state machine owns this connection
		 * yet and the ranges below do not describe it. It happens
		 * whenever every enabled front-end rejected the bytes: with
		 * only one of --as-socks5/--as-http on there is no fallback
		 * left, so gwp_handle_conn_state_prot() hands back -EINVAL
		 * with the state untouched. Report that rather than treating
		 * it as an impossible state -- it is ordinary garbage input,
		 * and asserting on it lets any client abort the process.
		 */
		return r < 0 ? r : -EINVAL;
	}
	if (CONN_STATE_HTTP_MIN < ct && ct < CONN_STATE_HTTP_MAX) {
		assert(w->ctx->cfg.as_http);
		return chk_http(w, gcp, r);
	} else if (CONN_STATE_SOCKS5_MIN < ct && ct < CONN_STATE_SOCKS5_MAX) {
		assert(w->ctx->cfg.as_socks5);
		return chk_socks5(w, gcp, r);
	} else {
		assert(0 && "Invalid connection state!");
		return -EINVAL;
	}
}

static int handle_ev_client_prot_in(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	ssize_t ret;
	int r, ct;

	ret = __do_recv(&gcp->client);
	if (unlikely(ret < 0))
		return (int)ret;
	if (unlikely(gcp->client.rd_eof))
		return -ECONNRESET;
	if (!ret)
		return 0;

	ct = gcp->conn_state;
	if (ct == CONN_STATE_SOCKS5_UDP_ASSOCIATE) {
		/*
		 * The TCP control connection is idle once the UDP association is
		 * up (the relay runs on gcp->udp_fd). Discard any stray bytes;
		 * a peer close was already turned into -ECONNRESET above and
		 * tears the association down.
		 */
		gcp->client.len = 0;
		return 0;
	}
	if (ct == CONN_STATE_PROT) {
		r = handle_conn_state_prot(w, gcp);
	} else if (CONN_STATE_HTTP_MIN < ct && ct < CONN_STATE_HTTP_MAX) {
		assert(w->ctx->cfg.as_http);
		r = handle_conn_state_http(w, gcp);
	} else if (CONN_STATE_SOCKS5_MIN < ct && ct < CONN_STATE_SOCKS5_MAX) {
		assert(w->ctx->cfg.as_socks5);
		r = handle_conn_state_socks5(w, gcp);
	} else {
		assert(0 && "Invalid connection state!");
		return -EINVAL;
	}

	if (r == -EAGAIN)
		r = 0;

	if (gcp->target.len) {
		ret = __do_send(&gcp->target, &gcp->client);
		if (ret < 0)
			return (int)ret;
	}

	return r;
}

static int handle_ev_client_prot_out(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct epoll_event evl;
	ssize_t ret;
	int r;

	ret = __do_send(&gcp->target, &gcp->client);
	if (ret < 0)
		return (int)ret;

	if (likely(!adj_epl_out(&gcp->target, &gcp->client)))
		return 0;

	pr_dbg(&w->ctx->lh, "Handling short send on client prot data");
	evl.events = gcp->client.ep_mask;
	evl.data.u64 = PTR_TO_U64(gcp) | EV_BIT_CLIENT_PROT;
	r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, gcp->client.fd, &evl);
	if (unlikely(r))
		return r;

	return 0;
}

#ifdef CONFIG_HTTPS
/* Re-arm the client fd under EV_BIT_CLIENT_PROT with @mask. */
static int tls_arm_client(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			  uint32_t mask)
{
	struct epoll_event ev;

	gcp->client.ep_mask = mask;
	ev.events = mask;
	ev.data.u64 = PTR_TO_U64(gcp) | EV_BIT_CLIENT_PROT;
	return __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, gcp->client.fd, &ev);
}

/* Flush queued handshake/alert ciphertext to the client, best effort. */
static int tls_flush_hs(struct gwp_conn *c)
{
	const void *p;
	size_t plen;
	ssize_t n;

	while ((p = gwp_ssl_bio_peek(c->tls, &plen)) != NULL) {
		n = __sys_send(c->fd, p, plen, MSG_NOSIGNAL);
		if (n > 0) {
			gwp_ssl_bio_consume(c->tls, (size_t)n);
			if ((size_t)n < plen)
				break;
		} else if (n == -EAGAIN || n == -EINTR) {
			break;
		} else {
			return (n == 0) ? -ECONNRESET : (int)n;
		}
	}

	return 0;
}

/*
 * Drive the server-side TLS handshake: feed available ciphertext, step the
 * handshake, flush any records it produced. On completion, switch to
 * CONN_STATE_PROT and process any application data the same recv() already
 * buffered inside the engine (no further EPOLLIN would surface it).
 */
static int handle_ev_tls_handshake(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_conn *c = &gcp->client;
	unsigned char cbuf[4096];	/* see do_recv_tls() on the sizing */
	uint32_t mask;
	ssize_t n;
	int hs, r;

	n = __sys_recv(c->fd, cbuf, sizeof(cbuf), MSG_NOSIGNAL);
	if (n > 0) {
		if (gwp_ssl_bio_write(c->tls, cbuf, (size_t)n) < 0)
			return -EIO;
	} else if (n == 0) {
		return -ECONNRESET;		/* peer closed mid-handshake */
	} else if (n != -EAGAIN && n != -EINTR) {
		return (int)n;
	}

	hs = gwp_ssl_handshake(c->tls);
	if (hs == GWP_SSL_ERROR) {
		pr_dbg(&w->ctx->lh, "TLS handshake failed: %s", gwp_ssl_errstr());
		return -ECONNRESET;
	}

	r = tls_flush_hs(c);
	if (r)
		return r;

	if (hs != GWP_SSL_OK) {
		/* Still handshaking: want more ciphertext, and to flush ours. */
		mask = EPOLLIN | EPOLLRDHUP;
		if (gwp_ssl_bio_pending(c->tls) > 0)
			mask |= EPOLLOUT;
		return tls_arm_client(w, gcp, mask);
	}

	pr_dbg(&w->ctx->lh, "TLS handshake complete (cfd=%d, alpn=%s)", c->fd,
	       gwp_ssl_alpn(c->tls) ?: "none");
	gcp->conn_state = CONN_STATE_PROT;
	mask = EPOLLIN | EPOLLRDHUP;
	if (gwp_ssl_bio_pending(c->tls) > 0)
		mask |= EPOLLOUT;
	r = tls_arm_client(w, gcp, mask);
	if (r)
		return r;

	return handle_ev_client_prot_in(w, gcp);
}

/*
 * First-byte probe on a TLS-capable listener. A TLS record begins with 0x16
 * (handshake); SOCKS5 starts 0x05, SOCKS4 0x04 and HTTP with an ASCII letter,
 * so 0x16 is unambiguous. Non-TLS clients fall through to CONN_STATE_PROT with
 * the peeked byte left in the socket for the normal plaintext path.
 */
static int handle_ev_tls_detect(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	unsigned char b;
	ssize_t n;

	n = __sys_recv(gcp->client.fd, &b, 1, MSG_PEEK | MSG_NOSIGNAL);
	if (n < 0) {
		if (n == -EAGAIN || n == -EINTR)
			return 0;
		return (int)n;
	}
	if (n == 0)
		return -ECONNRESET;

	if (b != 0x16) {
		gcp->conn_state = CONN_STATE_PROT;
		return 0;
	}

	gcp->client.tls = gwp_ssl_server_new(ctx->ssl_ctx);
	if (!gcp->client.tls) {
		pr_err(&ctx->lh, "Failed to allocate TLS connection state");
		return -ENOMEM;
	}

	gcp->conn_state = CONN_STATE_TLS_HANDSHAKE;
	return handle_ev_tls_handshake(w, gcp);
}
#endif /* CONFIG_HTTPS */

static int handle_ev_client_prot(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				 struct epoll_event *ev)
{
	int r;

#ifdef CONFIG_HTTPS
	if (gcp->conn_state == CONN_STATE_TLS_DETECT) {
		r = handle_ev_tls_detect(w, gcp);
		if (r)
			return r;
		/* Only a plaintext fall-through continues to the PROT path. */
		if (gcp->conn_state != CONN_STATE_PROT)
			return 0;
	} else if (gcp->conn_state == CONN_STATE_TLS_HANDSHAKE) {
		return handle_ev_tls_handshake(w, gcp);
	}
#endif

	if (unlikely(!(ev->events & (EPOLLIN | EPOLLOUT))))
		return -EIO;

	if (ev->events & EPOLLOUT) {
		r = handle_ev_client_prot_out(w, gcp);
		if (r)
			return r;
	}

	if (ev->events & EPOLLIN) {
		r = handle_ev_client_prot_in(w, gcp);
		if (r)
			return r;

#ifdef CONFIG_HTTPS
		/*
		 * Application data already decrypted and buffered in the engine
		 * would not be surfaced by another EPOLLIN (its ciphertext is
		 * already off the socket), so drain it here while the protocol
		 * buffer still has room.
		 */
		while (gcp->client.tls && gcp->conn_state == CONN_STATE_PROT &&
		       gcp->client.len < gcp->client.cap &&
		       gwp_ssl_pending(gcp->client.tls) > 0) {
			r = handle_ev_client_prot_in(w, gcp);
			if (r)
				return r;
		}
#endif
	}

	return 0;
}

static int handle_event(struct gwp_wrk *w, struct epoll_event *ev)
{
	uint64_t ev_bit;
	void *udata;
	int r;

	ev_bit = GET_EV_BIT(ev->data.u64);
	udata = U64_TO_PTR(CLEAR_EV_BIT(ev->data.u64));

	/*
	 * A racing connect attempt: the slot index rides in the tag, so the
	 * pair pointer in the low bits is untouched.
	 */
	if (ev_bit >= EV_BIT_TARGET_ATTEMPT &&
	    ev_bit < EV_BIT_TARGET_ATTEMPT +
		     ((uint64_t)GWP_MAX_CONN_CAND << 48ull)) {
		uint8_t slot = (ev_bit - EV_BIT_TARGET_ATTEMPT) >> 48ull;

		r = handle_ev_target_attempt(w, udata, slot);
		goto out;
	}

	switch (ev_bit) {
	case EV_BIT_ATTEMPT_TIMER:
		r = handle_ev_attempt_timer(w, udata);
		break;
	case EV_BIT_ACCEPT:
		r = handle_ev_accept(w, ev);
		break;
	case EV_BIT_EVENTFD:
		r = handle_ev_eventfd(w, ev);
		break;
	case EV_BIT_TARGET:
		r = handle_ev_target(w, udata, ev);
		break;
	case EV_BIT_CLIENT:
		r = handle_ev_client(w, udata, ev);
		break;
	case EV_BIT_CLIENT_PROT:
		r = handle_ev_client_prot(w, udata, ev);
		break;
	case EV_BIT_UDP_RELAY:
		r = handle_ev_udp_relay(w, udata);
		break;
	case EV_BIT_TIMER:
		r = handle_ev_timer(w, udata);
		break;
	case EV_BIT_DNS_QUERY:
		r = handle_ev_dns_query(w, udata);
		break;
	case EV_BIT_SOCKS5_AUTH_FILE:
		r = handle_ev_auth_file(w);
		break;
	case EV_BIT_ACL_FILE:
		r = handle_ev_acl_file(w);
		break;
	case EV_BIT_RAW_DNS_QUERY:
		r = handle_ev_raw_dns_query(w);
		break;
	default:
		pr_err(&w->ctx->lh, "Unknown event bit: %" PRIu64, ev_bit);
		return -EINVAL;
	}

out:
	if (r && is_ev_bit_conn_pair(ev_bit)) {
		struct gwp_conn_pair *gcp = udata;
		r = free_conn_pair(w, gcp);
	}

	return r;
}

static int handle_events(struct gwp_wrk *w, int nr_events)
{
	struct epoll_event *events = w->events;
	struct gwp_ctx *ctx = w->ctx;
	int i, r = 0;

	for (i = 0; i < nr_events; i++) {
		if (unlikely(ctx->stop))
			break;

		r = handle_event(w, &events[i]);
		if (unlikely(r < 0))
			break;

		if (w->ev_need_reload)
			break;
	}

	return r;
}

static int fish_events(struct gwp_wrk *w)
{
	int r;

	w->ev_need_reload = false;
	r = __sys_epoll_wait(w->ep_fd, w->events, w->evsz, -1);
	if (unlikely(r < 0)) {
		if (r != -EINTR)
			pr_err(&w->ctx->lh, "epoll_wait failed: %s", strerror(-r));
		else
			r = 0;
	}

	return r;
}

int gwp_ctx_thread_entry_epoll(struct gwp_wrk *w)
{
	struct gwp_ctx *ctx = w->ctx;
	int r = 0;

	pr_info(&ctx->lh, "Worker %u started (epoll)", w->idx);

	while (!ctx->stop) {
		r = fish_events(w);
		if (unlikely(r < 0))
			break;

		r = handle_events(w, r);
		if (unlikely(r < 0))
			break;
	}

	return r;
}

__cold
void gwp_ctx_signal_all_epoll(struct gwp_ctx *ctx)
{
	int i;

	ctx->stop = true;
	for (i = 0; i < ctx->cfg.nr_workers; i++) {
		struct gwp_wrk *w = &ctx->workers[i];
		int r;

		do {
			if (w->ev_fd < 0)
				break;
			r = eventfd_write(w->ev_fd, 1);
		} while ((r < 0) && (r == -EINTR));
	}
}
