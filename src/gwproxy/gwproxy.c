// SPDX-License-Identifier: GPL-2.0-only
/*
 * gwproxy - A simple TCP proxy server.
 *
 * Copyright (C) 2025 Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#include <gwproxy/gwproxy.h>
#include <gwproxy/common.h>
#include <gwproxy/log.h>
#include <gwproxy/acl.h>
#include <gwproxy/ev/epoll.h>
#ifdef CONFIG_IO_URING
#include <gwproxy/ev/io_uring.h>
#endif
#ifdef CONFIG_HTTPS
#include <gwproxy/ssl.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include <assert.h>
#include <stdarg.h>
#include <time.h>
#include <inttypes.h>
#include <stdatomic.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <getopt.h>
#include <signal.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <netinet/tcp.h>
#include <sys/timerfd.h>
#include <sys/resource.h>
#include <sys/inotify.h>

/* Long-only options (no short letter): values >= 128 are skipped by the
 * short-option string builder below. */
enum {
	OPT_ACL_ALLOW_ALL = 0x100,
	OPT_DNS_CACHE_MAX_ENTRIES,
};

static const struct option long_opts[] = {
	{ "help",		no_argument,		NULL,	'h' },
	{ "event-loop",		required_argument,	NULL,	'e' },
	{ "bind",		required_argument,	NULL,	'b' },
	{ "target",		required_argument,	NULL,	't' },
	{ "as-socks5",		required_argument,	NULL,	'S' },
	{ "as-http",		required_argument,	NULL,	'H' },
	{ "udp-associate",	required_argument,	NULL,	'U' },
	{ "prefer-ipv6",	required_argument,	NULL,	'Q' },
	{ "protocol-timeout",	required_argument,	NULL,	'o' },
	{ "auth-file",		required_argument,	NULL,	'A' },
	{ "acl-file",		required_argument,	NULL,	'a' },
	{ "acl-allow-all",	no_argument,		NULL,	OPT_ACL_ALLOW_ALL },
	{ "dns-cache-secs",	required_argument,	NULL,	'L' },
	{ "dns-cache-max-entries", required_argument,	NULL,	OPT_DNS_CACHE_MAX_ENTRIES },
	{ "nr-workers",		required_argument,	NULL,	'w' },
	{ "nr-dns-workers",	required_argument,	NULL,	'W' },
	{ "connect-timeout",	required_argument,	NULL,	'c' },
	{ "connect-attempt-delay", required_argument,	NULL,	'D' },
	{ "target-buf-size",	required_argument,	NULL,	'T' },
	{ "client-buf-size",	required_argument,	NULL,	'C' },
	{ "tcp-nodelay",	required_argument,	NULL,	'd' },
	{ "tcp-quickack",	required_argument,	NULL,	'K' },
	{ "tcp-keepalive",	required_argument,	NULL,	'k' },
	{ "tcp-keepidle",	required_argument,	NULL,	'i' },
	{ "tcp-keepintvl",	required_argument,	NULL,	'l' },
	{ "tcp-keepcnt",	required_argument,	NULL,	'g' },
	{ "log-level",		required_argument,	NULL,	'm' },
	{ "log-file",		required_argument,	NULL,	'f' },
	{ "pid-file",		required_argument,	NULL,	'p' },
	{ "upstream-proxy",	required_argument,	NULL,	'x' },
	{ "mark",		required_argument,	NULL,	'M' },
	{ "bind-source",	required_argument,	NULL,	'B' },
	{ "bind-iface",		required_argument,	NULL,	'I' },
	{ "as-transparent",	required_argument,	NULL,	'R' },
#ifdef CONFIG_HTTPS
	{ "tls-cert",		required_argument,	NULL,	'E' },
	{ "tls-key",		required_argument,	NULL,	'Y' },
#endif
#ifdef CONFIG_NEW_DNS_RESOLVER
	{ "dns-server",		required_argument,	NULL,	'j' },
	{ "raw-dns",		required_argument,	NULL,	'r' },
#endif
	{ NULL,			0,			NULL,	0 }
};

static const struct gwp_cfg default_opts = {
	.event_loop		= "epoll",
	.bind			= "[::]:1080",
	.target			= NULL,
	.as_socks5		= false,
	.as_http		= false,
	.udp_associate		= true,
	.prefer_ipv6		= false,
	.use_raw_dns		= false,
	.protocol_timeout	= 10,
	.auth_file		= NULL,
	.acl_file		= NULL,
	.dns_cache_secs		= 0,
	.dns_cache_max_entries	= 65536,
	.nr_workers		= 4,
	.nr_dns_workers		= 4,
	.connect_timeout	= 5,
	.connect_attempt_delay	= 250,
	.target_buf_size	= 16384,
	.client_buf_size	= 16384,
	.tcp_nodelay		= 1,
	.tcp_quickack		= 1,
	.tcp_keepalive		= 1,
	.tcp_keepidle		= 60,
	.tcp_keepintvl		= 10,
	.tcp_keepcnt		= 5,
	.log_level		= 3,
	.log_file		= "/dev/stdout",
	.pid_file		= NULL,
	.dns_servers		= "1.1.1.1",
	.upstream_proxy	= NULL,
	.mark			= 0,
	.bind_source		= NULL,
	.bind_iface		= NULL,
	.as_transparent		= false
};

__cold
static void show_help(const char *app)
{
	printf("Usage: %s [options]\n", app);
	printf("Options:\n");
	printf("  -h, --help                      Show this help message and exit\n");
	printf("  -e, --event-loop=name           Specify the event loop to use (default: %s)\n", default_opts.event_loop);
	printf("                                  Available values: epoll, io_uring\n");
	printf("  -b, --bind=addr:port            Bind to the specified address (default: %s)\n", default_opts.bind);
	printf("  -t, --target=addr:port          Target address to connect to\n");
	printf("  -S, --as-socks5=0|1             Run as a SOCKS5 proxy (default: %d)\n", default_opts.as_socks5);
	printf("  -H, --as-http=0|1               Run as an HTTP proxy (default: %d)\n", default_opts.as_http);
	printf("  -U, --udp-associate=0|1         Allow SOCKS5 UDP ASSOCIATE; 0 rejects it with REP 0x07 (default: %d)\n", default_opts.udp_associate);
	printf("  -Q, --prefer-ipv6=0|1           Prefer IPv6 for proxy DNS queries (default: %d)\n", default_opts.prefer_ipv6);
	printf("  -o, --protocol-timeout=sec      Timeout for protocol handshake process (default: %d)\n", default_opts.protocol_timeout);
	printf("  -A, --auth-file=file            File with username:password credentials for SOCKS5 and HTTP auth (default: no auth)\n");
	printf("  -a, --acl-file=file             iptables-style ACL rule file for target/client filtering\n");
	printf("                                  (default: a built-in ACL that rejects private/loopback target ranges)\n");
	printf("      --acl-allow-all             Do not apply the built-in default ACL (allow all; ignored with --acl-file)\n");
	printf("  -L, --dns-cache-secs=sec        Proxy DNS cache duration in seconds (default: %d)\n", default_opts.dns_cache_secs);
	printf("                                  Set to 0 or a negative number to disable DNS caching.\n");
	printf("      --dns-cache-max-entries=nr  Max DNS cache entries; 0 = unlimited (default: %d)\n", default_opts.dns_cache_max_entries);
	printf("  -w, --nr-workers=nr             Number of worker threads (default: %d)\n", default_opts.nr_workers);
	printf("  -W, --nr-dns-workers=nr         Number of DNS worker threads for SOCKS5 (default: %d)\n", default_opts.nr_dns_workers);
	printf("  -c, --connect-timeout=sec       Connection to target timeout in seconds (default: %d)\n", default_opts.connect_timeout);
	printf("  -D, --connect-attempt-delay=ms  Delay before racing the next target address (Happy Eyeballs); 0 disables racing (default: %d)\n", default_opts.connect_attempt_delay);
	printf("  -T, --target-buf-size=nr        Target buffer size in bytes (default: %d)\n", default_opts.target_buf_size);
	printf("  -C, --client-buf-size=nr        Client buffer size in bytes (default: %d)\n", default_opts.client_buf_size);
	printf("  -d, --tcp-nodelay=0|1           Enable/disable TCP_NODELAY (default: %d)\n", default_opts.tcp_nodelay);
	printf("  -K, --tcp-quickack=0|1          Enable/disable TCP_QUICKACK (default: %d)\n", default_opts.tcp_quickack);
	printf("  -k, --tcp-keepalive=0|1         Enable/disable TCP_KEEPALIVE (default: %d)\n", default_opts.tcp_keepalive);
	printf("  -i, --tcp-keepidle=sec          TCP_KEEPIDLE in seconds (default: %d)\n", default_opts.tcp_keepidle);
	printf("  -l, --tcp-keepintvl=sec         TCP_KEEPINTVL in seconds (default: %d)\n", default_opts.tcp_keepintvl);
	printf("  -g, --tcp-keepcnt=nr            TCP_KEEPCNT (default: %d)\n", default_opts.tcp_keepcnt);
	printf("  -m, --log-level=level           Set log level (0=none, 1=error, 2=warning, 3=info, 4=debug, default: %d)\n", default_opts.log_level);
	printf("  -f, --log-file=file             Log to the specified file (default: %s)\n", default_opts.log_file);
	printf("  -p, --pid-file=file             Write PID to the specified file (default is no pid file)\n");
	printf("  -x, --upstream-proxy=url        Route outgoing connections through an upstream proxy\n");
	printf("                                  URL: socks5://[user:pass@]host:port  (local DNS)\n");
	printf("                                       socks5h://[user:pass@]host:port (proxy resolves the host)\n");
	printf("                                       http://[user:pass@]host:port    (HTTP CONNECT)\n");
	printf("  -M, --mark=nr                   Set SO_MARK (fwmark) on outgoing connections (needs CAP_NET_ADMIN or CAP_NET_RAW; 0 = off)\n");
	printf("  -B, --bind-source=ip[:port]     Bind outgoing connections to this source address (default -j BIND --to-source)\n");
	printf("                                  Skipped for targets of the other address family; omit the port for an ephemeral one\n");
	printf("  -I, --bind-iface=name           Bind outgoing connections to this interface (SO_BINDTODEVICE)\n");
	printf("                                  Both are strict: a failed bind drops the connection. An ACL -j BIND rule replaces\n");
	printf("                                  them wholesale for the connections it matches\n");
	printf("  -R, --as-transparent=0|1        Transparent proxy: take the target from SO_ORIGINAL_DST (iptables REDIRECT) (default: %d)\n", default_opts.as_transparent);
#ifdef CONFIG_HTTPS
	printf("  -E, --tls-cert=file             PEM certificate chain; enables TLS termination on the listener (auto-detected per connection)\n");
	printf("  -Y, --tls-key=file              PEM private key matching --tls-cert\n");
#endif
#ifdef CONFIG_NEW_DNS_RESOLVER
	printf("  -j, --dns-server=addr:port      DNS server address (default: system resolver)\n");
	printf("  -r, --raw-dns=0|1               Use raw DNS for SOCKS5 (default: %d)\n", default_opts.use_raw_dns);
#endif
	printf("\n");
}

/*
 * Whether --event-loop selects the io_uring backend. "iou" is an accepted
 * alias for "io_uring" (see gwp_ctx_parse_ev()), so both spellings must be
 * recognised when gating features that io_uring does not support yet.
 */
static bool ev_is_io_uring(const struct gwp_cfg *cfg)
{
	return cfg->event_loop &&
	       (!strcmp(cfg->event_loop, "io_uring") ||
		!strcmp(cfg->event_loop, "iou"));
}

__cold
static int parse_options(int argc, char *argv[], struct gwp_cfg *cfg)
{
	#define ERR_WRAP "==============================================\n"
	#define NR_OPTS ((sizeof(long_opts) / sizeof(long_opts[0])) - 1)
	char short_opts[(NR_OPTS * 2) + 1], *p;
	size_t i;
	int c;

	p = short_opts;
	for (i = 0; i < NR_OPTS; i++) {
		/* Long-only options use a val >= 128 and have no short letter. */
		if (long_opts[i].val <= 0 || long_opts[i].val >= 128)
			continue;
		*p++ = long_opts[i].val;
		if (long_opts[i].has_arg == required_argument ||
		    long_opts[i].has_arg == optional_argument)
			*p++ = ':';
	}
	*p = '\0';
	#undef NR_OPTS

	*cfg = default_opts;
	while (1) {
		c = getopt_long(argc, argv, short_opts, long_opts, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			show_help(argv[0]);
			exit(0);
		case 'e':
			cfg->event_loop = optarg;
			break;
		case 'b':
			cfg->bind = optarg;
			break;
		case 't':
			cfg->target = optarg;
			break;
		case 'S':
			cfg->as_socks5 = !!atoi(optarg);
			break;
		case 'H':
			cfg->as_http = !!atoi(optarg);
			break;
		case 'U':
			cfg->udp_associate = !!atoi(optarg);
			break;
		case 'Q':
			cfg->prefer_ipv6 = !!atoi(optarg);
			break;
		case 'o':
			cfg->protocol_timeout = atoi(optarg);
			break;
		case 'A':
			cfg->auth_file = optarg;
			break;
		case 'a':
			cfg->acl_file = optarg;
			break;
		case OPT_ACL_ALLOW_ALL:
			cfg->acl_allow_all = true;
			break;
		case 'L':
			cfg->dns_cache_secs = atoi(optarg);
			break;
		case OPT_DNS_CACHE_MAX_ENTRIES:
			cfg->dns_cache_max_entries = atoi(optarg);
			break;
		case 'w':
			cfg->nr_workers = atoi(optarg);
			break;
		case 'W':
			cfg->nr_dns_workers = atoi(optarg);
			break;
		case 'c':
			cfg->connect_timeout = atoi(optarg);
			break;
		case 'D':
			cfg->connect_attempt_delay = atoi(optarg);
			break;
		case 'T':
			cfg->target_buf_size = atoi(optarg);
			break;
		case 'C':
			cfg->client_buf_size = atoi(optarg);
			break;
		case 'd':
			cfg->tcp_nodelay = !!atoi(optarg);
			break;
		case 'K':
			cfg->tcp_quickack = !!atoi(optarg);
			break;
		case 'k':
			cfg->tcp_keepalive = !!atoi(optarg);
			break;
		case 'i':
			cfg->tcp_keepidle = atoi(optarg);
			break;
		case 'l':
			cfg->tcp_keepintvl = atoi(optarg);
			break;
		case 'g':
			cfg->tcp_keepcnt = atoi(optarg);
			break;
		case 'm':
			cfg->log_level = atoi(optarg);
			break;
		case 'f':
			cfg->log_file = optarg;
			break;
		case 'p':
			cfg->pid_file = optarg;
			break;
		case 'x':
			cfg->upstream_proxy = optarg;
			break;
		case 'M':
			cfg->mark = atoi(optarg);
			break;
		case 'B':
			cfg->bind_source = optarg;
			break;
		case 'I':
			cfg->bind_iface = optarg;
			break;
		case 'R':
			cfg->as_transparent = !!atoi(optarg);
			break;
#ifdef CONFIG_HTTPS
		case 'E':
			cfg->tls_cert = optarg;
			break;
		case 'Y':
			cfg->tls_key = optarg;
			break;
#endif
		case 'j':
			cfg->dns_servers = optarg;
			break;
		case 'r':
			cfg->use_raw_dns = !!atoi(optarg);
			break;
		default:
			fprintf(stderr, "Unknown option: %c\n", c);
			show_help(argv[0]);
			return -EINVAL;
		}
	}


	if (cfg->use_raw_dns && ev_is_io_uring(cfg)) {
		fprintf(stderr, ERR_WRAP "Error: The raw DNS feature is currently not supported with the io_uring event loop\n" ERR_WRAP);
		goto einval;
	}

	if (cfg->use_raw_dns && cfg->dns_cache_secs) {
		fprintf(stderr, ERR_WRAP "Error: The -L/--dns-cache-secs option is not supported with the raw DNS feature\n" ERR_WRAP);
		goto einval;
	}

#ifdef CONFIG_HTTPS
	if ((cfg->tls_cert != NULL) != (cfg->tls_key != NULL)) {
		fprintf(stderr, ERR_WRAP "Error: --tls-cert and --tls-key must be provided together\n" ERR_WRAP);
		goto einval;
	}
#endif

	if (cfg->as_transparent && (cfg->as_socks5 || cfg->as_http)) {
		fprintf(stderr, ERR_WRAP "Error: --as-transparent cannot be combined with --as-socks5 or --as-http\n" ERR_WRAP);
		goto einval;
	}

	if (cfg->as_transparent && cfg->target) {
		fprintf(stderr, ERR_WRAP "Error: --target must not be set with --as-transparent (the target comes from SO_ORIGINAL_DST)\n" ERR_WRAP);
		goto einval;
	}

	if (!cfg->as_socks5 && !cfg->as_http && !cfg->as_transparent && !cfg->target) {
		fprintf(stderr, ERR_WRAP "Error: --target is required unless --as-socks5=1, --as-http=1 or --as-transparent=1\n" ERR_WRAP);
		goto einval;
	}

	if (cfg->nr_workers <= 0) {
		fprintf(stderr, ERR_WRAP "Error: --nr-workers must be at least 1.\n" ERR_WRAP);
		goto einval;
	}

	if (cfg->target_buf_size <= 1) {
		fprintf(stderr, ERR_WRAP "Error: --target-buf-size must be greater than 1.\n" ERR_WRAP);
		goto einval;
	}

	if (cfg->client_buf_size <= 1) {
		fprintf(stderr, ERR_WRAP "Error: --client-buf-size must be greater than 1.\n" ERR_WRAP);
		goto einval;
	}

	if (cfg->as_socks5 || cfg->as_http) {
		if (cfg->client_buf_size < 256) {
			fprintf(stderr, ERR_WRAP "Error: --client-buf-size must be at least 256 for SOCKS5 or HTTP.\n" ERR_WRAP);
			goto einval;
		}

		if (cfg->target_buf_size < 256) {
			fprintf(stderr, ERR_WRAP "Error: --target-buf-size must be at least 256 for SOCKS5 or HTTP.\n" ERR_WRAP);
			goto einval;
		}
	}

	return 0;

einval:
	fprintf(stderr, "\n");
	show_help(argv[0]);
	return -EINVAL;
}

#ifdef CONFIG_NEW_DNS_RESOLVER
static int gwp_ctx_init_raw_dns(struct gwp_wrk *w)
{
	struct gwp_ctx *ctx = w->ctx;
	int r;

	w->dns = calloc(1, sizeof(*w->dns));
	if (!w->dns)
		return -ENOMEM;

	/*
	 * TODO(Viro_SSFS): Support multiple DNS servers by splitting
	 *                  ctx->cfg.dns_servers by comma.
	 *
	 * For now, support only one DNS server.
	 */
	w->dns->nr = 1;
	w->dns->resolvers = calloc(w->dns->nr, sizeof(*w->dns->resolvers));
	if (!w->dns->resolvers) {
		r = -ENOMEM;
		goto err_dns;
	}

	r = gwp_dns_res_init(ctx, &w->dns->resolvers[0], ctx->cfg.dns_servers);
	if (r < 0)
		goto err_resolvers;

	pr_dbg(&ctx->lh, "Worker %u initialized raw DNS resolver: %s (fd=%d)",
		w->idx, ctx->cfg.dns_servers, w->dns->resolvers[0].udp_fd);
	return 0;

err_resolvers:
	free(w->dns->resolvers);
	w->dns->resolvers = NULL;
err_dns:
	free(w->dns);
	w->dns = NULL;
	return r;
}

static void gwp_ctx_free_raw_dns(struct gwp_wrk *w)
{
	size_t i;

	if (!w->dns)
		return;

	if (w->dns->resolvers) {
		for (i = 0; i < w->dns->nr; i++)
			gwp_dns_res_free(&w->dns->resolvers[i]);
		free(w->dns->resolvers);
		w->dns->resolvers = NULL;
	}

	free(w->dns);
	w->dns = NULL;
}

static int gwp_alloc_dns_packet(struct gwp_conn_pair *gcp)
{
	gcp->gdp = calloc(1, sizeof(*gcp->gdp));
	return gcp->gdp ? 0 : -ENOMEM;
}

static void gwp_free_dns_packet(struct gwp_conn_pair *gcp)
{
	if (gcp->gdp) {
		free(gcp->gdp->host);
		free(gcp->gdp);
		gcp->gdp = NULL;
	}
}

static int gwp_raw_dns_resolve(struct gwp_wrk *w,
			       struct gwp_conn_pair *gcp,
			       const char *host,
			       const char *port)
{
	struct gwp_dns_resolver *res;
	struct gwp_dns_packet *gdp;
	int r;

	assert(w->dns);

	res = &w->dns->resolvers[0];
	r = gwp_alloc_dns_packet(gcp);
	if (r < 0)
		return r;

	gdp = gcp->gdp;
	gdp->host = strdup(host);
	if (!gdp->host) {
		r = -ENOMEM;
		goto out_err;
	}

	gdp->restyp = w->ctx->cfg.prefer_ipv6 ?
		GWP_DNS_RESTYP_PREFER_IPV6 :
		GWP_DNS_RESTYP_PREFER_IPV4;

	gdp->port = (uint16_t)atoi(port);
	gdp->buf_len = sizeof(gdp->buf);
	gdp->gcp = gcp;
	r = gwp_dns_res_prep_query(res, gdp);
	if (r < 0)
		goto out_err;

	return -EINPROGRESS;

out_err:
	gwp_free_dns_packet(gcp);
	return r;
}
#else /* #ifdef CONFIG_NEW_DNS_RESOLVER */
static int gwp_ctx_init_raw_dns(struct gwp_wrk __unused *w)
{
	return -ENOSYS;
}

static void gwp_ctx_free_raw_dns(struct gwp_wrk __unused *w)
{
}

static int gwp_raw_dns_resolve(struct gwp_wrk __unused *w,
			       struct gwp_conn_pair __unused *gcp,
			       const char __unused *host,
			       const char __unused *port)
{
	return -ENOSYS;
}
#endif /* #ifdef CONFIG_NEW_DNS_RESOLVER */

#define FULL_ADDRSTRLEN (INET6_ADDRSTRLEN + sizeof(":65535[]") - 1)

__hot
const char *ip_to_str(const struct gwp_sockaddr *gs)
{
	static __thread char buf[8][FULL_ADDRSTRLEN];
	static __thread uint8_t idx = 0;
	char *bp = buf[idx++ % 8];

	return convert_ssaddr_to_str(bp, gs) ? NULL : bp;
}

__cold
static int gwp_ctx_init_log(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;
	int r = 0;

	if (!strcmp("/dev/stdout", cfg->log_file)) {
		ctx->lh.handle = stdout;
	} else if (!strcmp("/dev/stderr", cfg->log_file)) {
		ctx->lh.handle = stderr;
	} else if (!*cfg->log_file) {
		ctx->lh.handle = NULL;
	} else {
		ctx->lh.handle = fopen(cfg->log_file, "ab");
		if (!ctx->lh.handle) {
			r = -errno;
			pr_err(&ctx->lh, "Failed to open log file '%s': %s",
				cfg->log_file, strerror(-r));
		}
	}

	ctx->lh.level = ctx->cfg.log_level;
	return r;
}

__cold
static void gwp_ctx_free_log(struct gwp_ctx *ctx)
{
	if (ctx->lh.handle &&
	    ctx->lh.handle != stdout &&
	    ctx->lh.handle != stderr) {
		fclose(ctx->lh.handle);
		ctx->lh.handle = NULL;
	}
}

__cold
static int gwp_ctx_init_pid_file(struct gwp_ctx *ctx)
{
	FILE *f;
	int r;

	f = fopen(ctx->cfg.pid_file, "wb");
	if (!f) {
		r = -errno;
		pr_warn(&ctx->lh, "Failed to open PID file '%s': %s",
			ctx->cfg.pid_file, strerror(-r));
		return r;
	}

	r = getpid();
	pr_info(&ctx->lh, "Writing PID to '%s' (pid=%d)", ctx->cfg.pid_file, r);
	fprintf(f, "%d\n", r);
	fclose(f);
	return 0;
}

__cold
static int gwp_ctx_init_thread_sock(struct gwp_wrk *w,
				    const struct gwp_sockaddr *ba)
{
	struct gwp_ctx *ctx = w->ctx;
	int type = SOCK_STREAM | SOCK_CLOEXEC |
			(ctx->ev_used == GWP_EV_EPOLL ? SOCK_NONBLOCK : 0);
	struct gwp_cfg *cfg = &w->ctx->cfg;
	socklen_t slen;
	int fd, r, v;

	r = ba->sa.sa_family;
	if (r == AF_INET) {
		slen = sizeof(struct sockaddr_in);
	} else if (r == AF_INET6) {
		slen = sizeof(struct sockaddr_in6);
	} else {
		pr_err(&w->ctx->lh, "Unsupported address family: %d", r);
		return -EAFNOSUPPORT;
	}

	fd = __sys_socket(r, type, 0);
	if (fd < 0) {
		pr_err(&w->ctx->lh, "Failed to create socket: %s", strerror(-r));
		return r;
	}

	v = 1;
	__sys_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
	__sys_setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &v, sizeof(v));

	r = __sys_bind(fd, (struct sockaddr *)ba, slen);
	if (r < 0) {
		pr_err(&w->ctx->lh, "Failed to bind socket: %s", strerror(-r));
		goto out_close;
	}

	r = __sys_listen(fd, SOMAXCONN);
	if (r < 0) {
		pr_err(&w->ctx->lh, "Failed to listen on socket: %s", strerror(-r));
		goto out_close;
	}

	w->tcp_fd = fd;
	pr_info(&w->ctx->lh, "Worker %u is listening on %s (fd=%d)", w->idx,
		cfg->bind, fd);
	return 0;

out_close:
	__sys_close(fd);
	w->tcp_fd = -1;
	return r;
}

__cold
static void gwp_ctx_free_thread_sock(struct gwp_wrk *w)
{
	if (w->tcp_fd >= 0) {
		__sys_close(w->tcp_fd);
		pr_dbg(&w->ctx->lh, "Worker %u socket closed (fd=%d)", w->idx,
			w->tcp_fd);
		w->tcp_fd = -1;
	}
}

static int gwp_ctx_init_thread_event(struct gwp_wrk *w)
{
	switch (w->ctx->ev_used) {
	case GWP_EV_EPOLL:
		return gwp_ctx_init_thread_epoll(w);
	case GWP_EV_IO_URING:
#ifdef CONFIG_IO_URING
		return gwp_ctx_init_thread_io_uring(w);
#else
		pr_err(&w->ctx->lh, "IO_URING support is not enabled in this build");
		return -ENOSYS;
#endif
	default:
		pr_err(&w->ctx->lh, "Unknown event loop type: %d", w->ctx->ev_used);
		return -EINVAL;
	}
}

static void gwp_ctx_free_thread_event(struct gwp_wrk *w)
{
	switch (w->ctx->ev_used) {
	case GWP_EV_EPOLL:
		gwp_ctx_free_thread_epoll(w);
		break;
	case GWP_EV_IO_URING:
#ifdef CONFIG_IO_URING
		gwp_ctx_free_thread_io_uring(w);
#else
		pr_err(&w->ctx->lh, "IO_URING support is not enabled in this build");
#endif
		break;
	default:
		pr_err(&w->ctx->lh, "Unknown event loop type: %d", w->ctx->ev_used);
		break;
	}
}

__cold
static int gwp_ctx_init_thread(struct gwp_wrk *w,
			       const struct gwp_sockaddr *bind_addr)
{
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_cfg *cfg = &ctx->cfg;
	int r;

	r = gwp_ctx_init_thread_sock(w, bind_addr);
	if (r < 0) {
		pr_err(&ctx->lh, "gwp_ctx_init_thread_sock: %s\n", strerror(-r));
		return r;
	}


	if (cfg->use_raw_dns) {
		r = gwp_ctx_init_raw_dns(w);
		if (r < 0) {
			pr_err(&ctx->lh, "Failed to initialize raw DNS: %s", strerror(-r));
			goto out_err;
		}
	}

	r = gwp_ctx_init_thread_event(w);
	if (r < 0) {
		pr_err(&ctx->lh, "gwp_ctx_init_thread_event: %s\n", strerror(-r));
		goto out_err_raw_dns;
	}

	return r;

out_err_raw_dns:
	if (cfg->use_raw_dns)
		gwp_ctx_free_raw_dns(w);
out_err:
	gwp_ctx_free_thread_sock(w);
	return r;
}

static void free_conn(struct gwp_conn *conn);

static void log_conn_pair_close(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	pr_info(&w->ctx->lh,
		"Closing connection pair (idx=%u, cfd=%d, tfd=%d, ca=%s, ta=%s)",
		gcp->idx, gcp->client.fd, gcp->target.fd,
		ip_to_str(&gcp->client_addr),
		ip_to_str(&gcp->target_addr));
}

__cold
static void gwp_ctx_free_thread_sock_pairs(struct gwp_wrk *w)
{
	struct gwp_conn_slot *gcs = &w->conn_slot;
	size_t i;

	if (!gcs->pairs)
		return;

	for (i = 0; i < gcs->nr; i++) {
		struct gwp_conn_pair *gcp = gcs->pairs[i];
		if (!gcp)
			continue;

		log_conn_pair_close(w, gcp);
		free_conn(&gcp->target);
		free_conn(&gcp->client);
		if (gcp->timer_fd >= 0)
			__sys_close(gcp->timer_fd);
		if (gcp->udp_fd >= 0)
			__sys_close(gcp->udp_fd);
		gwp_conn_close_attempts(gcp);
		free(gcp->udp_iou);	/* io_uring relay scratch, else NULL */

		/*
		 * s5_conn and http_conn share a union, so the protocol object
		 * must be freed through the correct type; freeing an http_conn
		 * as a SOCKS5 conn corrupts memory. Mirror gwp_free_conn_pair().
		 */
		switch (gcp->prot_type) {
		case GWP_PROT_TYPE_SOCKS5:
			gwp_socks5_conn_free(gcp->s5_conn);
			break;
		case GWP_PROT_TYPE_HTTP:
			gwp_http_conn_free(gcp->http_conn);
			break;
		}

#ifdef CONFIG_HTTPS
		gwp_ssl_free(gcp->client.tls);
#if defined(CONFIG_IO_URING)
		free(gcp->tls_io);
#endif
#endif

		free(gcp);
	}

	free(gcs->pairs);
	gcs->pairs = NULL;
	gcs->nr = 0;
	gcs->cap = 0;
}

__cold
static void gwp_ctx_signal_all_workers(struct gwp_ctx *ctx)
{
	if (!ctx->workers)
		return;

	if (ctx->ev_used == GWP_EV_EPOLL) {
		gwp_ctx_signal_all_epoll(ctx);
	} else if (ctx->ev_used == GWP_EV_IO_URING) {
#ifdef CONFIG_IO_URING
		gwp_ctx_signal_all_io_uring(ctx);
#endif
	}
}

__cold
static void gwp_ctx_free_thread(struct gwp_wrk *w)
{
	struct gwp_cfg *cfg = &w->ctx->cfg;

	if (cfg->use_raw_dns)
		gwp_ctx_free_raw_dns(w);

	gwp_ctx_free_thread_sock_pairs(w);
	gwp_ctx_free_thread_sock(w);
	gwp_ctx_free_thread_event(w);
}

__cold
static int gwp_ctx_init_threads(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;
	struct gwp_sockaddr bind_addr;
	struct gwp_wrk *workers, *w;
	int i, r;

	if (cfg->nr_workers <= 0) {
		pr_err(&ctx->lh, "Number of workers must be at least 1\n");
		return -EINVAL;
	}

	r = convert_str_to_ssaddr(cfg->bind, &bind_addr, 0);
	if (r) {
		pr_err(&ctx->lh, "Invalid bind address '%s'\n", cfg->bind);
		return r;
	}

	workers = calloc(cfg->nr_workers, sizeof(*workers));
	if (!workers)
		return -ENOMEM;

	ctx->workers = workers;
	for (i = 0; i < cfg->nr_workers; i++) {
		w = &workers[i];
		w->ctx = ctx;
		w->idx = i;
		r = gwp_ctx_init_thread(w, &bind_addr);
		if (r < 0)
			goto out_err;
	}

	return 0;

out_err:
	while (i--)
		gwp_ctx_free_thread(&workers[i]);
	free(workers);
	ctx->workers = NULL;
	return r;
}

__cold
static void gwp_ctx_free_threads(struct gwp_ctx *ctx)
{
	struct gwp_wrk *w, *workers = ctx->workers;
	int i;

	if (!workers)
		return;

	ctx->stop = true;
	gwp_ctx_signal_all_workers(ctx);
	for (i = 0; i < ctx->cfg.nr_workers; i++) {
		w = &workers[i];
		if (!w->need_join)
			continue;

		pr_dbg(&ctx->lh, "Joining worker thread %d", i);
		pthread_join(w->thread, NULL);
		w->need_join = false;
	}

	for (i = 0; i < ctx->cfg.nr_workers; i++)
		gwp_ctx_free_thread(&workers[i]);

	free(workers);
	ctx->workers = NULL;
}

static const char *path_basename(const char *path)
{
	const char *slash = strrchr(path, '/');

	return slash ? slash + 1 : path;
}

/*
 * Add an inotify watch that survives an atomic replace of `path`. We watch the
 * *parent directory*, not the file: an inode watch is silently dropped the
 * moment an editor, `install`, or `mv` swaps the file via rename, and never
 * fires again. Watching the directory for IN_CLOSE_WRITE (in-place writes) and
 * IN_MOVED_TO (rename-into-place) catches both update styles; handlers narrow
 * the reported events down to the file's basename with
 * gwp_inotify_event_matches(). Returns the watch descriptor or -errno.
 */
static int add_reload_watch(int ino_fd, const char *path)
{
	const char *slash = strrchr(path, '/');
	char dir[PATH_MAX];
	int r;

	if (!slash) {
		dir[0] = '.';
		dir[1] = '\0';
	} else {
		size_t n = (size_t)(slash - path);

		if (n == 0)		/* "/file": watch the root directory */
			n = 1;
		if (n >= sizeof(dir))
			return -ENAMETOOLONG;
		memcpy(dir, path, n);
		dir[n] = '\0';
	}

	r = inotify_add_watch(ino_fd, dir, IN_CLOSE_WRITE | IN_MOVED_TO);
	return (r < 0) ? -errno : r;
}

/*
 * True when a drained inotify buffer names the basename of `path`. The reload
 * watches sit on the parent directory (see add_reload_watch), so handlers call
 * this to reload only for their own file and ignore unrelated directory churn.
 */
bool gwp_inotify_event_matches(const void *buf, size_t len, const char *path)
{
	const char *base = path_basename(path);
	size_t off = 0;

	while (off + sizeof(struct inotify_event) <= len) {
		const struct inotify_event *e =
			(const struct inotify_event *)((const char *)buf + off);
		size_t rec = sizeof(*e) + e->len;

		/*
		 * The kernel dropped events (queue overflow, delivered as a
		 * nameless wd=-1 record). Our file's change may have been among
		 * the lost ones, so force a reload rather than miss it.
		 */
		if (e->mask & IN_Q_OVERFLOW)
			return true;

		if (off + rec > len)
			break;
		if (e->len && !strcmp(e->name, base))
			return true;
		off += rec;
	}
	return false;
}

/*
 * Load the shared credential store from the auth file (if configured) and set
 * up an inotify watch so it is hot-reloaded on change. The store is shared by
 * the SOCKS5 and HTTP CONNECT front-ends. Leaves ctx->auth NULL (and the
 * inotify fields disabled) when no auth file is configured.
 */
static int gwp_ctx_init_auth(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;
	int r;

	ctx->auth = NULL;
	ctx->ino_fd = -1;
	ctx->ino_buf = NULL;

	if (!cfg->auth_file || !*cfg->auth_file) {
		pr_dbg(&ctx->lh, "Authentication disabled (no auth file)");
		return 0;
	}

	r = gwp_auth_create(&ctx->auth, cfg->auth_file);
	if (r < 0) {
		pr_err(&ctx->lh, "Failed to load auth file '%s': %s",
			cfg->auth_file, strerror(-r));
		return r;
	}

	r = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (r < 0) {
		pr_err(&ctx->lh, "Failed to initialize inotify: %s", strerror(-r));
		goto out_err;
	}

	pr_dbg(&ctx->lh, "Inotify file descriptor initialized (fd=%d)", r);

	ctx->ino_fd = r;
	r = add_reload_watch(ctx->ino_fd, cfg->auth_file);
	if (r < 0) {
		pr_err(&ctx->lh, "Failed to add inotify watch: %s", strerror(-r));
		goto out_err;
	}

	pr_dbg(&ctx->lh, "Inotify watch added for '%s' (wd=%d)", cfg->auth_file, r);

	ctx->ino_buf = malloc(sizeof(struct inotify_event) + NAME_MAX + 1);
	if (!ctx->ino_buf) {
		pr_err(&ctx->lh, "Failed to allocate inotify buffer: %s", strerror(ENOMEM));
		r = -ENOMEM;
		goto out_err;
	}

	return 0;

out_err:
	if (ctx->ino_fd >= 0) {
		__sys_close(ctx->ino_fd);
		ctx->ino_fd = -1;
	}
	gwp_auth_destroy(ctx->auth);
	ctx->auth = NULL;
	return r;
}

static void gwp_ctx_free_auth(struct gwp_ctx *ctx)
{
	if (ctx->ino_buf) {
		free(ctx->ino_buf);
		ctx->ino_buf = NULL;
		pr_dbg(&ctx->lh, "Inotify buffer freed");
	}

	if (ctx->ino_fd >= 0) {
		__sys_close(ctx->ino_fd);
		ctx->ino_fd = -1;
		pr_dbg(&ctx->lh, "Inotify file descriptor closed");
	}

	gwp_auth_destroy(ctx->auth);
	ctx->auth = NULL;
}

/*
 * Applied when no --acl-file is given (and --acl-allow-all is not set): an
 * SSRF-hardening default that rejects outgoing connections to loopback and
 * private address ranges while accepting all clients. --acl-file overrides it
 * wholesale; --acl-allow-all disables it (allow everything).
 */
static const char gwp_acl_default_rules[] =
	"-P INPUT ACCEPT\n"
	"-A OUTPUT -d 10.0.0.0/8 -j REJECT\n"
	"-A OUTPUT -d 127.0.0.0/8 -j REJECT\n"
	"-A OUTPUT -d 192.168.0.0/16 -j REJECT\n"
	"-A OUTPUT -d 172.16.0.0/12 -j REJECT\n"
	"-A OUTPUT -d fe80::/10 -j REJECT\n"
	"-A OUTPUT -d fc00::/7 -j REJECT\n"
	"-P OUTPUT ACCEPT\n";

/*
 * Load the ACL rule file (--acl-file) and watch it for changes so it is
 * hot-reloaded, mirroring the auth store. Unlike auth (prot-only), the ACL is
 * global to every proxy mode, so this is initialised from gwp_ctx_init()
 * regardless of SOCKS5/HTTP/transparent/plain forwarding. With no file it
 * applies the built-in default ACL, unless --acl-allow-all leaves it disabled
 * (NULL, watch fd -1).
 */
static int gwp_ctx_init_acl(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;
	int r;

	ctx->acl = NULL;
	ctx->acl_ino_fd = -1;
	ctx->acl_ino_buf = NULL;

	if (!cfg->acl_file || !*cfg->acl_file) {
		if (cfg->acl_allow_all) {
			pr_dbg(&ctx->lh, "ACL disabled (--acl-allow-all)");
			return 0;
		}

		/* No file to watch/reload: the default rules are compiled in. */
		r = gwp_acl_parse_str(&ctx->acl, gwp_acl_default_rules);
		if (r < 0) {
			pr_err(&ctx->lh, "Failed to build default ACL: %s",
				strerror(-r));
			ctx->acl = NULL;
			return r;
		}
		pr_info(&ctx->lh,
			"Applied built-in default ACL (loopback/private targets blocked; --acl-allow-all to disable)");
		return 0;
	}

	r = gwp_acl_create(&ctx->acl, cfg->acl_file);
	if (r < 0) {
		pr_err(&ctx->lh, "Failed to load ACL file '%s': %s",
			cfg->acl_file, strerror(-r));
		return r;
	}

	r = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (r < 0) {
		pr_err(&ctx->lh, "Failed to initialize ACL inotify: %s",
			strerror(-r));
		goto out_err;
	}
	ctx->acl_ino_fd = r;

	r = add_reload_watch(ctx->acl_ino_fd, cfg->acl_file);
	if (r < 0) {
		pr_err(&ctx->lh, "Failed to add ACL inotify watch: %s",
			strerror(-r));
		goto out_err;
	}

	ctx->acl_ino_buf = malloc(sizeof(struct inotify_event) + NAME_MAX + 1);
	if (!ctx->acl_ino_buf) {
		r = -ENOMEM;
		goto out_err;
	}

	pr_info(&ctx->lh, "Loaded ACL file '%s'", cfg->acl_file);
	return 0;

out_err:
	if (ctx->acl_ino_fd >= 0) {
		__sys_close(ctx->acl_ino_fd);
		ctx->acl_ino_fd = -1;
	}
	gwp_acl_destroy(ctx->acl);
	ctx->acl = NULL;
	return r;
}

static void gwp_ctx_free_acl(struct gwp_ctx *ctx)
{
	if (ctx->acl_ino_buf) {
		free(ctx->acl_ino_buf);
		ctx->acl_ino_buf = NULL;
	}
	if (ctx->acl_ino_fd >= 0) {
		__sys_close(ctx->acl_ino_fd);
		ctx->acl_ino_fd = -1;
	}
	gwp_acl_destroy(ctx->acl);
	ctx->acl = NULL;
}

/*
 * Evaluate the ACL OUTPUT chain for a connection's resolved TCP target. Returns
 * true when the connection is allowed. With no ACL loaded, or when the target
 * has no locally-resolved IP (e.g. a socks5h remote-DNS upstream, where only a
 * domain is known), it is allowed here; domain-based rules are applied
 * separately once wired in.
 */
/* Host-order port of a sockaddr, regardless of family. */
static uint16_t sa_port_h(const struct gwp_sockaddr *s)
{
	return ntohs(s->sa.sa_family == AF_INET ? s->i4.sin_port
						: s->i6.sin6_port);
}

static int upstream_dst_from_sockaddr(const struct gwp_sockaddr *sa,
				      struct gwp_socks5_addr *out);

/*
 * Evaluate the ACL OUTPUT chain for a connection to @target from @client (with
 * an optional requested @domain / @user). Returns the verdict; allows (with no
 * eval) when there is no ACL, or nothing to match on. When @do_dnat is set and a
 * matching -j DNAT rule produced a concrete address, the rewritten destination
 * is written back to *@target (for the direct connection and, via the caller,
 * the upstream) and *@dnat_out (when non-NULL) is set true. Composable -j MARK /
 * -j BIND modifiers are surfaced in *@so_out.
 */
static enum gwp_acl_verdict acl_out(struct gwp_ctx *ctx,
				    const struct gwp_sockaddr *client,
				    struct gwp_sockaddr *target,
				    const char *domain, const char *user,
				    struct gwp_conn_sockopt *so_out,
				    bool *dnat_out,
				    enum gwp_acl_proto proto, bool do_dnat)
{
	int fam = target ? target->sa.sa_family : 0;
	bool have_ip = (fam == AF_INET || fam == AF_INET6);
	enum gwp_acl_verdict v;
	struct gwp_acl_req req;

	if (so_out)
		memset(so_out, 0, sizeof(*so_out));
	if (dnat_out)
		*dnat_out = false;

	if (!ctx->acl)
		return GWP_ACL_ACCEPT;
	/* A domain-only request (remote-DNS upstream) still matches -m domain. */
	if (!have_ip && !domain)
		return GWP_ACL_ACCEPT;

	memset(&req, 0, sizeof(req));
	req.client = client;
	req.target = have_ip ? target : NULL;
	req.domain = domain;
	req.user = user;
	req.proto = proto;
	req.dport = have_ip ? sa_port_h(target) : 0;
	req.sport = client ? sa_port_h(client) : 0;

	v = gwp_acl_eval_output(ctx->acl, &req);
	if (v != GWP_ACL_ACCEPT)
		return v;

	/*
	 * Apply a matched DNAT when it produced a concrete address, rewriting
	 * the destination for both the direct path (*target) and, via the
	 * caller, the upstream destination. A port-only DNAT with no base IP
	 * (e.g. a socks5h domain request) yields no address and is skipped.
	 */
	if (do_dnat && req.dnat_applied && req.dnat.sa.sa_family) {
		if (have_ip)
			pr_info(&ctx->lh, "ACL DNAT %s -> %s",
				ip_to_str(target), ip_to_str(&req.dnat));
		else
			pr_info(&ctx->lh, "ACL DNAT %s -> %s",
				domain ? domain : "?", ip_to_str(&req.dnat));
		*target = req.dnat;
		if (dnat_out)
			*dnat_out = true;
	}
	/* Surface composable -j MARK / -j BIND to the socket-creation path. */
	if (so_out && req.mark_set) {
		so_out->mark_set = true;
		so_out->mark = req.mark;
	}
	if (so_out && req.bind.set)
		so_out->bind = req.bind;
	return v;
}

/* Verdict only (no DNAT), for the UDP relay's per-datagram target. */
bool gwp_ctx_acl_output_allowed(struct gwp_ctx *ctx,
				const struct gwp_sockaddr *client,
				const struct gwp_sockaddr *target,
				const char *user, enum gwp_acl_proto proto)
{
	struct gwp_sockaddr tmp = *target;

	return acl_out(ctx, client, &tmp, NULL, user, NULL, NULL, proto,
		       false) == GWP_ACL_ACCEPT;
}

/* Verdict + DNAT rewrite of *@target, for the accept-time plain/transparent
 * forwarding path (which has no gwp_conn_pair yet, hence no username). */
bool gwp_ctx_acl_output_dnat(struct gwp_ctx *ctx,
			     const struct gwp_sockaddr *client,
			     struct gwp_sockaddr *target,
			     struct gwp_conn_sockopt *so,
			     enum gwp_acl_proto proto)
{
	return acl_out(ctx, client, target, NULL, NULL, so, NULL, proto,
		       true) == GWP_ACL_ACCEPT;
}

/* The authenticated username for an ACL "-m user" match, or NULL when the
 * connection carried no proxy authentication. */
static const char *gcp_req_user(const struct gwp_conn_pair *gcp)
{
	if (gcp->prot_type == GWP_PROT_TYPE_SOCKS5 && gcp->s5_conn)
		return gwp_socks5_conn_username(gcp->s5_conn);
	if (gcp->prot_type == GWP_PROT_TYPE_HTTP && gcp->http_conn)
		return gwp_http_conn_username(gcp->http_conn);
	return NULL;
}

bool gwp_ctx_acl_target_allowed(struct gwp_ctx *ctx, struct gwp_conn_pair *gcp)
{
	bool dnat = false;
	enum gwp_acl_verdict v;

	v = acl_out(ctx, &gcp->client_addr, &gcp->target_addr, gcp->req_domain,
		    gcp_req_user(gcp), &gcp->acl_sockopt, &dnat,
		    GWP_ACL_PROTO_TCP, true);
	if (v != GWP_ACL_ACCEPT)
		return false;

	/*
	 * When chaining to an upstream by remote DNS (socks5h), up_dst carries
	 * the requested hostname. A DNAT has rewritten target_addr to a concrete
	 * IP, so push that into up_dst too, making the upstream connect to the
	 * DNAT target instead of resolving the original name. For socks5:// the
	 * up_dst is still unset here (ver == 0) and is finalised from the
	 * (already rewritten) target_addr after the upstream connects.
	 */
	if (dnat && ctx->upstream.enabled && gcp->up_dst.ver != 0) {
		__be16 orig_port = gcp->up_dst.port;

		upstream_dst_from_sockaddr(&gcp->target_addr, &gcp->up_dst);
		/*
		 * An address-only DNAT (--to <ip> with no port) has no port to
		 * apply for a domain request (the target IP was unknown at eval
		 * time), so target_addr carries port 0. Keep the client's
		 * original requested port instead of connecting to :0.
		 */
		if (gcp->up_dst.port == 0)
			gcp->up_dst.port = orig_port;
	}

	return true;
}

/*
 * Evaluate the ACL INPUT chain for an incoming client. Returns true when the
 * client is allowed (always so when no ACL is loaded). @proto distinguishes the
 * client's TCP control connection (accept time) from a UDP association it later
 * requests.
 */
bool gwp_ctx_acl_client_allowed(struct gwp_ctx *ctx,
				const struct gwp_sockaddr *client,
				enum gwp_acl_proto proto)
{
	struct gwp_acl_req req;

	if (!ctx->acl)
		return true;

	memset(&req, 0, sizeof(req));
	req.client = client;
	req.proto = proto;
	req.sport = sa_port_h(client);
	return gwp_acl_eval_input(ctx->acl, &req) == GWP_ACL_ACCEPT;
}

static int gwp_ctx_init_socks5(struct gwp_ctx *ctx)
{
	struct gwp_socks5_cfg s5cfg;
	int r;

	pr_dbg(&ctx->lh, "Initializing SOCKS5 context");
	memset(&s5cfg, 0, sizeof(s5cfg));
	s5cfg.auth = ctx->auth;
	s5cfg.udp_associate = ctx->cfg.udp_associate;
	r = gwp_socks5_ctx_init(&ctx->socks5, &s5cfg);
	if (r < 0) {
		pr_err(&ctx->lh, "Failed to initialize SOCKS5 context: %s",
			strerror(-r));
		return r;
	}

	return 0;
}

static void gwp_ctx_free_socks5(struct gwp_ctx *ctx)
{
	assert(ctx->cfg.as_socks5);
	gwp_socks5_ctx_free(ctx->socks5);
	ctx->socks5 = NULL;
	pr_dbg(&ctx->lh, "SOCKS5 context freed");
}

static int gwp_ctx_init_dns(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;
	const struct gwp_dns_cfg dns_cfg = {
		.cache_expiry = cfg->dns_cache_secs,
		.max_entries = cfg->dns_cache_max_entries > 0 ?
			       (uint32_t)cfg->dns_cache_max_entries : 0,
		.restyp = cfg->prefer_ipv6 ? GWP_DNS_RESTYP_PREFER_IPV6 : 0,
		.nr_workers = cfg->nr_dns_workers
	};
	int r;

	if ((!cfg->as_socks5 && !cfg->as_http) || cfg->use_raw_dns) {
		ctx->dns = NULL;
		return 0;
	}

	r = gwp_dns_ctx_init(&ctx->dns, &dns_cfg);
	if (r < 0) {
		pr_err(&ctx->lh, "Failed to initialize DNS context: %s", strerror(-r));
		return r;
	}

	return 0;
}

static void gwp_ctx_free_dns(struct gwp_ctx *ctx)
{
	if (!ctx->dns)
		return;

	gwp_dns_ctx_free(ctx->dns);
	ctx->dns = NULL;
	pr_dbg(&ctx->lh, "DNS context freed");
}

static int gwp_ctx_parse_ev(struct gwp_ctx *ctx)
{
	const char *ev = ctx->cfg.event_loop;

	if (!ev || !*ev) {
		ctx->ev_used = GWP_EV_EPOLL;
		pr_dbg(&ctx->lh, "Using default event loop: epoll");
		return 0;
	}

	if (!strcmp(ev, "epoll")) {
		ctx->ev_used = GWP_EV_EPOLL;
		pr_dbg(&ctx->lh, "Using event loop: epoll");
	} else if (!strcmp(ev, "io_uring") || !strcmp(ev, "iou")) {
		ctx->ev_used = GWP_EV_IO_URING;
		pr_dbg(&ctx->lh, "Using event loop: io_uring");
	} else {
		pr_err(&ctx->lh, "Unknown event loop '%s'", ev);
		return -EINVAL;
	}

	return 0;
}

__cold
static int gwp_ctx_init_prot(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;
	int r;

	ctx->socks5 = NULL;
	ctx->auth = NULL;
	ctx->ino_fd = -1;
	ctx->ino_buf = NULL;

	/*
	 * SOCKS5 and HTTP may run together on the same port: the connection
	 * protocol handler tries SOCKS5 first and falls back to HTTP (see
	 * gwp_handle_conn_state_prot()). Authentication credentials are shared
	 * between the two, so the store is set up here (once) whenever a proxy
	 * front-end is enabled; HTTP per-connection state is allocated lazily.
	 */
	if (!cfg->as_socks5 && !cfg->as_http)
		return 0;

	r = gwp_ctx_init_auth(ctx);
	if (r < 0)
		return r;

	if (cfg->as_socks5) {
		r = gwp_ctx_init_socks5(ctx);
		if (r < 0) {
			gwp_ctx_free_auth(ctx);
			return r;
		}
	}

	return 0;
}

__cold
static void gwp_ctx_free_prot(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;

	if (cfg->as_socks5)
		gwp_ctx_free_socks5(ctx);

	if (cfg->as_socks5 || cfg->as_http)
		gwp_ctx_free_auth(ctx);
}

/*
 * Parse a --upstream-proxy URL of the form:
 *
 *    socks5://[user:pass@]host:port     (gwproxy resolves the target)
 *    socks5h://[user:pass@]host:port    (the upstream proxy resolves it)
 *    http://[user:pass@]host:port       (HTTP CONNECT, cleartext to the proxy)
 *    https://[user:pass@]host:port      (HTTP CONNECT, TLS to the proxy)
 *
 * The port is optional and defaults to 1080 for socks5 and 8080 for http.
 */
__cold
int gwp_parse_upstream(const char *url, struct gwp_upstream *up)
{
	char buf[512], *at, *host;
	const char *rest;
	uint16_t def_port;
	bool has_port;
	size_t n;
	int r;

	memset(up, 0, sizeof(*up));

	if (!strncmp(url, "socks5h://", 10)) {
		up->type = GWP_UPSTREAM_SOCKS5;
		up->remote_dns = true;
		rest = url + 10;
		def_port = 1080;
	} else if (!strncmp(url, "socks5://", 9)) {
		up->type = GWP_UPSTREAM_SOCKS5;
		up->remote_dns = false;
		rest = url + 9;
		def_port = 1080;
	} else if (!strncmp(url, "https://", 8)) {
		up->type = GWP_UPSTREAM_HTTP;
		up->use_tls = true;
		up->remote_dns = true;	/* the HTTP proxy resolves the CONNECT host */
		rest = url + 8;
		def_port = 8080;
	} else if (!strncmp(url, "http://", 7)) {
		up->type = GWP_UPSTREAM_HTTP;
		up->remote_dns = true;
		rest = url + 7;
		def_port = 8080;
	} else {
		return -EINVAL;
	}

	n = strlen(rest);
	if (n == 0 || n >= sizeof(buf))
		return -EINVAL;
	memcpy(buf, rest, n + 1);

	/* Optional "user:pass@" credentials; split at the last '@'. */
	at = strrchr(buf, '@');
	if (at) {
		char *creds = buf, *pass;
		size_t ul, pl;

		*at = '\0';
		host = at + 1;

		pass = strchr(creds, ':');
		if (pass)
			*pass++ = '\0';

		ul = strlen(creds);
		pl = pass ? strlen(pass) : 0;
		if (ul == 0 || ul > 255 || pl > 255)
			return -EINVAL;

		up->has_auth = true;
		up->ulen = (uint8_t)ul;
		up->plen = (uint8_t)pl;
		memcpy(up->user, creds, ul + 1);
		if (pass)
			memcpy(up->pass, pass, pl + 1);
	} else {
		host = buf;
	}

	/*
	 * convert_str_to_ssaddr() ignores an explicit port in the string when
	 * a non-zero default_port is passed, so only pass the default when the
	 * host has no port of its own.
	 */
	if (host[0] == '[') {
		char *rb = strchr(host, ']');
		has_port = rb && rb[1] == ':';
	} else {
		has_port = strchr(host, ':') != NULL;
	}

	r = convert_str_to_ssaddr(host, &up->addr, has_port ? 0 : def_port);
	if (r)
		return r;

	up->enabled = true;
	return 0;
}

/*
 * Turn --bind-source/--bind-iface into the ready-made bind spec the connect
 * path applies when no ACL -j BIND rule claimed the connection. Done once here
 * rather than per connection, and validated here so a typo (a malformed
 * address, an interface name that cannot fit IFNAMSIZ) is a startup error
 * instead of every connection quietly failing later.
 *
 * The interface is not probed against the running system: a device named here
 * may legitimately appear after gwproxy starts (a WireGuard or PPP link), and
 * the strict per-connection bind already fails safe until it does.
 */
__cold
static int gwp_ctx_init_bind_def(struct gwp_ctx *ctx)
{
	struct gwp_acl_bind *b = &ctx->bind_def;
	struct gwp_cfg *cfg = &ctx->cfg;
	size_t l;

	memset(b, 0, sizeof(*b));

	if (cfg->bind_iface) {
		l = strlen(cfg->bind_iface);
		if (!l || l >= sizeof(b->iface)) {
			pr_err(&ctx->lh,
			       "Invalid --bind-iface value '%s': an interface name is 1 to %zu characters",
			       cfg->bind_iface, sizeof(b->iface) - 1);
			return -EINVAL;
		}
		memcpy(b->iface, cfg->bind_iface, l + 1);
		b->set = true;
	}

	if (cfg->bind_source) {
		if (gwp_acl_parse_bind_source(cfg->bind_source, &b->src)) {
			pr_err(&ctx->lh,
			       "Invalid --bind-source value '%s': expected an IP literal, optionally 'ip:port' or '[v6]:port'",
			       cfg->bind_source);
			return -EINVAL;
		}
		b->have_src = true;
		b->set = true;
	}

	if (b->set)
		pr_info(&ctx->lh, "Outgoing connections bind to source %s on interface %s by default",
			b->have_src ? ip_to_str(&b->src) : "(any)",
			b->iface[0] ? b->iface : "(any)");

	return 0;
}

#ifdef CONFIG_HTTPS
__cold
static int gwp_ctx_init_tls(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;
	int r;

	ctx->ssl_ctx = NULL;
	if (!cfg->tls_cert)	/* validated: cert and key are both set or both unset */
		return 0;

	r = gwp_ssl_ctx_server_create(&ctx->ssl_ctx, cfg->tls_cert, cfg->tls_key);
	if (r < 0) {
		pr_err(&ctx->lh, "Failed to load TLS cert/key ('%s' / '%s'): %s",
		       cfg->tls_cert, cfg->tls_key, gwp_ssl_errstr());
		return r;
	}

	pr_info(&ctx->lh, "TLS termination enabled on the listener (cert=%s)",
		cfg->tls_cert);
	return 0;
}

__cold
static void gwp_ctx_free_tls(struct gwp_ctx *ctx)
{
	gwp_ssl_ctx_free(ctx->ssl_ctx);
	ctx->ssl_ctx = NULL;
}
#else /* !CONFIG_HTTPS */
static int gwp_ctx_init_tls(struct gwp_ctx *ctx)
{
	ctx->ssl_ctx = NULL;
	return 0;
}

static void gwp_ctx_free_tls(struct gwp_ctx *ctx)
{
	(void)ctx;
}
#endif /* CONFIG_HTTPS */

__cold
static int gwp_ctx_init(struct gwp_ctx *ctx)
{
	int r;

	r = gwp_ctx_init_log(ctx);
	if (r < 0)
		return r;

	r = gwp_ctx_parse_ev(ctx);
	if (r < 0)
		goto out_free_log;

	r = gwp_ctx_init_bind_def(ctx);
	if (r < 0)
		goto out_free_log;

	if (ctx->cfg.upstream_proxy) {
		r = gwp_parse_upstream(ctx->cfg.upstream_proxy,
					      &ctx->upstream);
		if (r) {
			pr_err(&ctx->lh, "Invalid --upstream-proxy value '%s'",
			       ctx->cfg.upstream_proxy);
			goto out_free_log;
		}
		if (ctx->upstream.use_tls) {
			pr_err(&ctx->lh, "An https:// (TLS) upstream proxy is not supported yet; use http:// or socks5[h]://");
			r = -ENOTSUP;
			goto out_free_log;
		}
		pr_info(&ctx->lh, "Routing outgoing connections via upstream %s proxy %s (%s DNS)",
			ctx->upstream.type == GWP_UPSTREAM_HTTP ? "HTTP" : "SOCKS5",
			ip_to_str(&ctx->upstream.addr),
			ctx->upstream.remote_dns ? "remote" : "local");
	}

	/*
	 * A transparent proxy takes the target from SO_ORIGINAL_DST per
	 * connection, so there is no --target to resolve here.
	 */
	if (!ctx->cfg.as_socks5 && !ctx->cfg.as_http && !ctx->cfg.as_transparent) {
		const char *t = ctx->cfg.target;

		/*
		 * With socks5h:// the upstream proxy resolves the target, so
		 * we must not resolve --target locally; keep it as a hostname
		 * to hand to the proxy later.
		 */
		if (ctx->upstream.enabled && ctx->upstream.remote_dns)
			r = 0;
		else
			r = convert_str_to_ssaddr(t, &ctx->target_addr, 0);
		if (r) {
			pr_err(&ctx->lh, "Invalid target address '%s'", t);
			goto out_free_log;
		}
	}

	if (ctx->cfg.mark) {
		int tfd = __sys_socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);

		if (tfd >= 0) {
			r = __sys_setsockopt(tfd, SOL_SOCKET, SO_MARK,
					     &ctx->cfg.mark, sizeof(ctx->cfg.mark));
			__sys_close(tfd);
			if (r) {
				pr_err(&ctx->lh, "Cannot set --mark=%d (SO_MARK): %s (CAP_NET_ADMIN or CAP_NET_RAW required)",
				       ctx->cfg.mark, strerror(-r));
				goto out_free_log;
			}
		}
	}

	if (ctx->cfg.pid_file)
		gwp_ctx_init_pid_file(ctx);

	r = gwp_ctx_init_tls(ctx);
	if (r < 0)
		goto out_free_log;

	r = gwp_ctx_init_prot(ctx);
	if (r < 0)
		goto out_free_tls;

	r = gwp_ctx_init_acl(ctx);
	if (r < 0)
		goto out_free_prot;

	r = gwp_ctx_init_dns(ctx);
	if (r < 0)
		goto out_free_acl;

	r = gwp_ctx_init_threads(ctx);
	if (r < 0) {
		pr_err(&ctx->lh, "Failed to initialize worker threads: %s", strerror(-r));
		goto out_free_dns;
	}

	return 0;

out_free_dns:
	gwp_ctx_free_dns(ctx);
out_free_acl:
	gwp_ctx_free_acl(ctx);
out_free_prot:
	gwp_ctx_free_prot(ctx);
out_free_tls:
	gwp_ctx_free_tls(ctx);
out_free_log:
	gwp_ctx_free_log(ctx);
	return r;
}

__cold
static void gwp_ctx_stop(struct gwp_ctx *ctx)
{
	ctx->stop = true;
	gwp_ctx_signal_all_workers(ctx);
}

__cold
static void gwp_ctx_free(struct gwp_ctx *ctx)
{
	gwp_ctx_stop(ctx);
	gwp_ctx_free_threads(ctx);
	gwp_ctx_free_dns(ctx);
	gwp_ctx_free_acl(ctx);
	gwp_ctx_free_prot(ctx);
	gwp_ctx_free_tls(ctx);
	gwp_ctx_free_log(ctx);
}

__cold
static int init_conn(struct gwp_conn *conn, uint32_t buf_size)
{
	conn->fd = -1;
	conn->len = 0;
	conn->cap = buf_size;
	conn->ep_mask = 0;
	conn->buf = NULL;
	return posix_memalign((void **)&conn->buf, 4096, buf_size) ? -ENOMEM : 0;
}

static void free_conn(struct gwp_conn *conn)
{
	if (!conn)
		return;

	if (conn->buf)
		free(conn->buf);

	if (conn->fd >= 0)
		__sys_close(conn->fd);

	conn->len = 0;
	conn->cap = 0;
	conn->ep_mask = 0;
}

static int expand_conn_slot(struct gwp_wrk *w)
{
	struct gwp_conn_slot *gcs = &w->conn_slot;
	struct gwp_ctx *ctx = w->ctx;

	if (gcs->nr >= gcs->cap) {
		uint32_t new_cap = gcs->cap ? gcs->cap * 2 : 16;
		struct gwp_conn_pair **new_pairs;

		new_pairs = realloc(gcs->pairs, new_cap * sizeof(*new_pairs));
		if (!new_pairs)
			return -ENOMEM;

		gcs->pairs = new_pairs;
		gcs->cap = new_cap;
		pr_dbg(&ctx->lh, "Increased connection slot capacity to %u", gcs->cap);
	}

	return 0;
}

__hot
struct gwp_conn_pair *gwp_alloc_conn_pair(struct gwp_wrk *w)
{
	struct gwp_conn_slot *gcs = &w->conn_slot;
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_cfg *cfg = &ctx->cfg;
	struct gwp_conn_pair *gcp;
	int r;

	r = expand_conn_slot(w);
	if (unlikely(r))
		return NULL;

	gcp = calloc(1, sizeof(*gcp));
	if (!gcp)
		return NULL;

	/*
	 * Both event loops carry this pointer in the low 48 bits of the event
	 * word (see EV_BIT_ALL). Refusing the connection is a poor outcome, but
	 * it is a diagnosable one: proceeding would hand the loops a pointer
	 * they silently truncate on the way back out.
	 */
	if (unlikely(!EV_PTR_OK(gcp))) {
		pr_err(&ctx->lh,
		       "BUG: connection pair %p has bits 48..63 set; the event word cannot carry it",
		       (void *)gcp);
		free(gcp);
		return NULL;
	}

	assert(cfg->target_buf_size > 1);
	assert(cfg->client_buf_size > 1);
	r = init_conn(&gcp->target, cfg->target_buf_size);
	if (r)
		goto out_free_gcp;
	r = init_conn(&gcp->client, cfg->client_buf_size);
	if (r)
		goto out_free_target_conn;

	gcp->timer_fd = -1;
	gcp->udp_fd = -1;
	gcp->attempt_timer_fd = -1;
	memset(gcp->attempt_fd, 0xff, sizeof(gcp->attempt_fd));	/* all -1 */
	gcp->idx = gcs->nr;
	gcp->conn_state = CONN_STATE_INIT;
	gcs->pairs[gcs->nr++] = gcp;
	gcp->flags = 0;
	gcp->prot_type = GWP_PROT_TYPE_NONE;
	return gcp;

out_free_target_conn:
	free_conn(&gcp->target);
out_free_gcp:
	free(gcp);
	pr_err(&ctx->lh, "Failed to allocate connection pair: %s", strerror(-r));
	return NULL;
}

static int shrink_conn_slot(struct gwp_wrk *w)
{
	struct gwp_conn_slot *gcs = &w->conn_slot;
	struct gwp_conn_pair **new_pairs;
	struct gwp_ctx *ctx = w->ctx;
	uint32_t new_cap;

	if (!gcs->pairs)
		return 0;

	if (!gcs->nr) {
		free(gcs->pairs);
		gcs->pairs = NULL;
		gcs->cap = 0;
		pr_dbg(&ctx->lh, "Connection slot capacity shrunk to 0");
		return 0;
	}

	if (gcs->cap <= 16 || (gcs->cap - gcs->nr) < 16)
		return 0;

	new_cap = gcs->nr;
	new_pairs = realloc(gcs->pairs, new_cap * sizeof(*new_pairs));
	if (!new_pairs) {
		pr_err(&ctx->lh, "Failed to shrink connection slot!");
		return -ENOMEM;
	}
	gcs->pairs = new_pairs;
	gcs->cap = new_cap;
	pr_dbg(&ctx->lh, "Connection slot capacity shrunk to %u", gcs->cap);
	return 0;
}

__hot
int gwp_free_conn_pair(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_conn_slot *gcs = &w->conn_slot;
	struct gwp_conn_pair *tmp;
	uint32_t i = gcp->idx;

	tmp = gcs->pairs[i];
	assert(tmp == gcp);
	if (unlikely(tmp != gcp))
		return -EINVAL;

	log_conn_pair_close(w, gcp);

	if (gcp->flags & GWP_CONN_FLAG_NO_CLOSE_FD)
		gcp->target.fd = gcp->client.fd = gcp->timer_fd = gcp->udp_fd = -1;

	tmp = gcs->pairs[--gcs->nr];
	gcs->pairs[gcs->nr] = NULL;
	gcs->pairs[i] = tmp;
	tmp->idx = i;

	free_conn(&gcp->target);
	free_conn(&gcp->client);

	if (gcp->timer_fd >= 0)
		__sys_close(gcp->timer_fd);
	if (gcp->udp_fd >= 0)
		__sys_close(gcp->udp_fd);
	gwp_conn_close_attempts(gcp);

#ifdef CONFIG_NEW_DNS_RESOLVER
	if (w->ctx->cfg.use_raw_dns && gcp->gdp) {
		/*
		 * A raw DNS query may still be outstanding in the resolver's
		 * session map (connection torn down before the reply arrived);
		 * drop it so the map slot is not left dangling at this freed
		 * gcp, then free the packet (including gdp->host).
		 */
		gwp_dns_res_drop_query(&w->dns->resolvers[0], gcp, gcp->gdp->txid);
		gwp_free_dns_packet(gcp);
	} else if (gcp->gde) {
		gwp_dns_entry_put(gcp->gde);
	}
#else
	if (gcp->gde)
		gwp_dns_entry_put(gcp->gde);
#endif

	switch (gcp->prot_type) {
	case GWP_PROT_TYPE_SOCKS5:
		gwp_socks5_conn_free(gcp->s5_conn);
		break;
	case GWP_PROT_TYPE_HTTP:
		gwp_http_conn_free(gcp->http_conn);
		break;
	}

#ifdef CONFIG_HTTPS
	gwp_ssl_free(gcp->client.tls);
#if defined(CONFIG_IO_URING)
	free(gcp->tls_io);	/* flat buffer struct; NULL unless io_uring+TLS */
#endif
#endif

	free(gcp);
	shrink_conn_slot(w);
	return 0;
}

/*
 * These come from linux/netfilter_ipv4.h and
 * linux/netfilter_ipv6/ip6_tables.h, but including those headers tends to
 * clash with <netinet/in.h>. The values are part of the stable UAPI.
 */
#ifndef SO_MARK
#define SO_MARK 36
#endif
#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif
#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST 80
#endif

/*
 * Fetch the pre-DNAT destination of a connection redirected to us by iptables
 * REDIRECT (used by --as-transparent). @client is the accepted peer address,
 * used to pick the right protocol level (an IPv4 or v4-mapped peer carries an
 * IPv4 original destination).
 */
int gwp_get_orig_dst(int fd, const struct gwp_sockaddr *client,
		     struct gwp_sockaddr *dst)
{
	socklen_t len;
	bool v4;

	v4 = (client->sa.sa_family == AF_INET) ||
	     (client->sa.sa_family == AF_INET6 &&
	      IN6_IS_ADDR_V4MAPPED(&client->i6.sin6_addr));

	memset(dst, 0, sizeof(*dst));
	if (v4) {
		len = sizeof(dst->i4);
		return __sys_getsockopt(fd, IPPROTO_IP, SO_ORIGINAL_DST,
					&dst->i4, &len);
	}

	len = sizeof(dst->i6);
	return __sys_getsockopt(fd, IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST,
				&dst->i6, &len);
}

static int setskopt_int(int fd, int level, int optname, int value)
{
	return __sys_setsockopt(fd, level, optname, &value, sizeof(value));
}

/*
 * Apply a bind spec to socket @fd before connect: pin the outgoing interface
 * (SO_BINDTODEVICE) and/or source address (bind()). Strict -- any failure is
 * returned so the caller drops the connection rather than proceeding on the
 * default route/source (which would leak traffic via the wrong path). @dst is
 * the address about to be connected, used to require a matching source family.
 * Neither operation needs a capability of its own: SO_BINDTODEVICE has been
 * unprivileged since Linux 5.7 (it wanted CAP_NET_RAW, never CAP_NET_ADMIN,
 * before that), and bind() to a locally configured address never needed one.
 * A source port below 1024 still needs CAP_NET_BIND_SERVICE.
 *
 * @b is either an ACL -j BIND rule or, when @global, the --bind-source /
 * --bind-iface default. The only difference is the family mismatch: an explicit
 * rule that names a source of the wrong family is a configuration error and is
 * refused, whereas the global default must not turn a dual-stack proxy into a
 * single-family one -- an IPv4 --bind-source simply does not apply to an IPv6
 * target, so the source is skipped and the connection proceeds. An interface
 * has no family, so --bind-iface still applies to every target.
 */
static int apply_conn_bind(struct gwp_wrk *w, int fd,
			   const struct gwp_sockaddr *dst,
			   const struct gwp_acl_bind *b, bool global)
{
	const char *tag = global ? "bind default" : "ACL BIND";
	int r;

	if (b->iface[0]) {
		r = __sys_setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
				     b->iface, (socklen_t)strlen(b->iface));
		if (unlikely(r < 0)) {
			pr_err(&w->ctx->lh,
			       "%s: SO_BINDTODEVICE(%s) failed: %s (no such interface, or a kernel older than 5.7 without CAP_NET_RAW)",
			       tag, b->iface, strerror(-r));
			return r;
		}
	}

	if (b->have_src) {
		const struct gwp_sockaddr *s = &b->src;
		socklen_t len;

		/* The source family must match the socket/target family. */
		if (s->sa.sa_family != dst->sa.sa_family) {
			if (global) {
				pr_dbg(&w->ctx->lh,
				       "bind default: --bind-source does not apply to target %s (other address family)",
				       ip_to_str(dst));
				return 0;
			}
			pr_err(&w->ctx->lh,
			       "ACL BIND: --to-source family does not match target %s",
			       ip_to_str(dst));
			return -EAFNOSUPPORT;
		}

		len = (s->sa.sa_family == AF_INET) ? sizeof(struct sockaddr_in)
						   : sizeof(struct sockaddr_in6);
		r = __sys_bind(fd, &s->sa, len);
		if (unlikely(r < 0)) {
			pr_err(&w->ctx->lh, "%s: bind(%s) failed: %s",
			       tag, ip_to_str(s), strerror(-r));
			return r;
		}
	}
	return 0;
}

void gwp_setup_cli_sock_options(struct gwp_wrk *w, int fd)
{
	struct gwp_cfg *cfg = &w->ctx->cfg;

	if (cfg->tcp_nodelay)
		setskopt_int(fd, IPPROTO_TCP, TCP_NODELAY, 1);

	if (cfg->tcp_keepalive)
		setskopt_int(fd, SOL_SOCKET, SO_KEEPALIVE, 1);

	if (cfg->tcp_keepidle > 0)
		setskopt_int(fd, IPPROTO_TCP, TCP_KEEPIDLE, cfg->tcp_keepidle);

	if (cfg->tcp_keepintvl > 0)
		setskopt_int(fd, IPPROTO_TCP, TCP_KEEPINTVL, cfg->tcp_keepintvl);

	if (cfg->tcp_keepcnt > 0)
		setskopt_int(fd, IPPROTO_TCP, TCP_KEEPCNT, cfg->tcp_keepcnt);
}

__hot
int gwp_create_sock_target(struct gwp_wrk *w, struct gwp_sockaddr *addr,
			   const struct gwp_conn_sockopt *so,
			   bool *is_target_alive, bool non_block)
{
	int t = SOCK_STREAM | SOCK_CLOEXEC | (non_block ? SOCK_NONBLOCK : 0);
	socklen_t len;
	int fd, r;

	fd = __sys_socket(addr->sa.sa_family, t, 0);
	if (unlikely(fd < 0))
		return fd;

	gwp_setup_cli_sock_options(w, fd);

	/*
	 * Mark the outgoing connection for policy routing / iptables matching.
	 * A per-connection -j MARK from the ACL overrides the global --mark, and
	 * is strict like -j BIND: if SO_MARK fails (it needs CAP_NET_ADMIN or,
	 * since Linux 5.11, CAP_NET_RAW) the connection is dropped rather than
	 * egressing unmarked via the wrong route. The coarse global --mark stays
	 * best-effort.
	 */
	if (so && so->mark_set) {
		r = setskopt_int(fd, SOL_SOCKET, SO_MARK, (int)so->mark);
		if (unlikely(r < 0)) {
			pr_err(&w->ctx->lh,
			       "ACL MARK: SO_MARK=%u failed: %s (CAP_NET_ADMIN or CAP_NET_RAW required)",
			       so->mark, strerror(-r));
			__sys_close(fd);
			return r;
		}
	} else if (w->ctx->cfg.mark) {
		setskopt_int(fd, SOL_SOCKET, SO_MARK, w->ctx->cfg.mark);
	}

	/*
	 * Pin the source interface/address before connect. Strict -- a failure
	 * drops the connection rather than falling back to the wrong source
	 * (see apply_conn_bind). A matching ACL -j BIND rule replaces the
	 * global --bind-source/--bind-iface default wholesale, exactly as -j
	 * MARK replaces --mark: a rule that names only an interface must not
	 * silently inherit the global source address, which would apply a
	 * policy neither the rule nor the default describes.
	 */
	if (so && so->bind.set) {
		r = apply_conn_bind(w, fd, addr, &so->bind, false);
		if (unlikely(r)) {
			__sys_close(fd);
			return r;
		}
	} else if (w->ctx->bind_def.set) {
		r = apply_conn_bind(w, fd, addr, &w->ctx->bind_def, true);
		if (unlikely(r)) {
			__sys_close(fd);
			return r;
		}
	}

	/*
	 * Do not connect if non_block is false, as we
	 * will not be able to handle the connection
	 * in a non-blocking way.
	 */
	if (!non_block) {
		if (is_target_alive)
			*is_target_alive = false;
		return fd;
	}

	len = (addr->sa.sa_family == AF_INET) ? sizeof(struct sockaddr_in)
					      : sizeof(struct sockaddr_in6);
	r = __sys_connect(fd, &addr->sa, len);
	if (likely(r)) {
		if (r != -EINPROGRESS) {
			__sys_close(fd);
			return r;
		}
		*is_target_alive = false;
	} else {
		*is_target_alive = true;
	}

	return fd;
}

__hot
int gwp_create_timer(int fd, int sec, int nsec)
{
	static const int flags = TFD_CLOEXEC | TFD_NONBLOCK;
	const struct itimerspec its = {
		.it_value.tv_sec = sec,
		.it_value.tv_nsec = nsec,
		.it_interval.tv_sec = 0,
		.it_interval.tv_nsec = 0,
	};
	bool need_close = false;
	int r;

	if (fd < 0) {
		fd = __sys_timerfd_create(CLOCK_MONOTONIC, flags);
		if (fd < 0)
			return fd;

		need_close = true;
	}

	r = __sys_timerfd_settime(fd, 0, &its, NULL);
	if (r < 0) {
		if (need_close)
			__sys_close(fd);
		return r;
	}

	return fd;
}

static int socks5_translate_err(int err)
{
	switch (err) {
	case 0:
		return GWP_SOCKS5_REP_SUCCESS;
	case -EPERM:
	case -EACCES:
		return GWP_SOCKS5_REP_NOT_ALLOWED;
	case -ENETUNREACH:
		return GWP_SOCKS5_REP_NETWORK_UNREACHABLE;
	case -EHOSTUNREACH:
		return GWP_SOCKS5_REP_HOST_UNREACHABLE;
	case -ECONNREFUSED:
		return GWP_SOCKS5_REP_CONN_REFUSED;
	case -ETIMEDOUT:
		return GWP_SOCKS5_REP_TTL_EXPIRED;
	default:
		return GWP_SOCKS5_REP_FAILURE;
	}
}

static int get_local_addr_for_socks5(struct gwp_ctx *ctx, int fd,
				     struct gwp_socks5_addr *ba)
{
	struct gwp_sockaddr t;
	socklen_t len = sizeof(t);
	int r;

	r = __sys_getsockname(fd, &t.sa, &len);
	if (r < 0) {
		pr_err(&ctx->lh, "getsockname error: %s", strerror(-r));
		return r;
	}

	switch (t.sa.sa_family) {
	case AF_INET:
		ba->ver = GWP_SOCKS5_ATYP_IPV4;
		memcpy(&ba->ip4, &t.i4.sin_addr, 4);
		ba->port = t.i4.sin_port;
		return 0;
	case AF_INET6:
		ba->ver = GWP_SOCKS5_ATYP_IPV6;
		memcpy(&ba->ip6, &t.i6.sin6_addr, 16);
		ba->port = t.i6.sin6_port;
		return 0;
	default:
		pr_err(&ctx->lh, "Unsupported address family %d for local socket",
			t.sa.sa_family);
		return -EAFNOSUPPORT;
	}
}

/*
 * Build a SOCKS5 CONNECT reply for the downstream client into an arbitrary
 * output buffer. @err is 0 on success or a positive errno on failure.
 */
__hot
int gwp_socks5_build_connect_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				   int err, void *out, size_t *out_len)
{
	struct gwp_socks5_conn *sc = gcp->s5_conn;
	struct gwp_socks5_addr ba;
	int r;

	if (err == 0) {
		r = get_local_addr_for_socks5(w->ctx, gcp->target.fd, &ba);
		if (unlikely(r))
			return r;
	} else {
		memset(&ba, 0, sizeof(ba));
		ba.ver = GWP_SOCKS5_ATYP_IPV4;
	}

	err = socks5_translate_err(err);
	return gwp_socks5_conn_cmd_connect_res(sc, &ba, err, out, out_len);
}

__hot
int gwp_socks5_prep_connect_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				  int err)
{
	size_t out_len = gcp->target.cap - gcp->target.len;
	void *out = gcp->target.buf + gcp->target.len;
	int r;

	r = gwp_socks5_build_connect_reply(w, gcp, err, out, &out_len);
	if (r < 0)
		return r;

	gcp->target.len += out_len;
	return 0;
}

int gwp_conn_fail_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp, int err)
{
	/*
	 * The two event loops report a connect timeout with different errnos:
	 * epoll's timerfd path uses -ETIMEDOUT, io_uring's timeout CQE gives
	 * -ETIME. Normalise, or the SOCKS5 mapping below would answer the
	 * generic REP 0x01 on io_uring instead of 0x06 (TTL expired).
	 */
	bool timed_out = (err == -ETIMEDOUT || err == -ETIME);

	if (timed_out)
		err = -ETIMEDOUT;

	if (gcp->prot_type == GWP_PROT_TYPE_SOCKS5)
		return gwp_socks5_prep_connect_reply(w, gcp, err);

	if (gcp->prot_type == GWP_PROT_TYPE_HTTP) {
		void *out = gcp->target.buf + gcp->target.len;
		size_t cap = gcp->target.cap - gcp->target.len;
		int r;

		if (timed_out)
			r = gwp_http_build_gateway_timeout_reply(out, cap);
		else
			r = gwp_http_build_bad_gateway_reply(out, cap);
		if (r < 0)
			return r;
		gcp->target.len += (uint32_t)r;
		return 0;
	}

	return 0;	/* plain/transparent forwarding speaks no protocol */
}

int gwp_acl_reject_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	pr_info(&w->ctx->lh, "ACL denied target %s for client %s (idx=%u)",
		ip_to_str(&gcp->target_addr), ip_to_str(&gcp->client_addr),
		gcp->idx);

	if (gcp->prot_type == GWP_PROT_TYPE_SOCKS5) {
		int r = gwp_socks5_prep_connect_reply(w, gcp, -EACCES);

		if (r)
			return r;
	} else if (gcp->prot_type == GWP_PROT_TYPE_HTTP) {
		int r = gwp_http_build_forbidden_reply(
				gcp->target.buf + gcp->target.len,
				gcp->target.cap - gcp->target.len);

		if (r < 0)
			return r;
		gcp->target.len += (uint32_t)r;
	}
	return -EACCES;
}

static int queue_dns_resolution(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				const char *host, const char *port)
{
	struct gwp_dns_ctx *dns = w->ctx->dns;
	struct gwp_dns_entry *gde;

	gde = gwp_dns_queue(dns, host, port);
	if (unlikely(!gde)) {
		pr_err(&w->ctx->lh, "Failed to allocate DNS entry for %s:%s", host, port);
		return -ENOMEM;
	}

	gcp->gde = gde;
	return -EINPROGRESS;
}

/*
 * Fill @out (SOCKS5 address form) from a resolved sockaddr. Used to hand the
 * already-resolved destination IP to the upstream SOCKS5 proxy (socks5://).
 */
static int upstream_dst_from_sockaddr(const struct gwp_sockaddr *sa,
				      struct gwp_socks5_addr *out)
{
	memset(out, 0, sizeof(*out));
	switch (sa->sa.sa_family) {
	case AF_INET:
		out->ver = GWP_SOCKS5_ATYP_IPV4;
		memcpy(out->ip4, &sa->i4.sin_addr, 4);
		out->port = sa->i4.sin_port;
		return 0;
	case AF_INET6:
		out->ver = GWP_SOCKS5_ATYP_IPV6;
		memcpy(out->ip6, &sa->i6.sin6_addr, 16);
		out->port = sa->i6.sin6_port;
		return 0;
	default:
		return -EAFNOSUPPORT;
	}
}

/*
 * Fill @out as a domain-name destination. Used with socks5h:// so the upstream
 * proxy performs the resolution.
 */
static int upstream_dst_from_domain(const char *host, uint16_t port,
				    struct gwp_socks5_addr *out)
{
	size_t hl = strlen(host);

	if (hl == 0 || hl > 255)
		return -EINVAL;

	memset(out, 0, sizeof(*out));
	out->ver = GWP_SOCKS5_ATYP_DOMAIN;
	out->domain.len = (uint8_t)hl;
	memcpy(out->domain.str, host, hl);
	out->domain.str[hl] = '\0';
	out->port = htons(port);
	return 0;
}

/*
 * Split a "host:port" (or "[ipv6]:port") string and fill @out as a domain
 * destination. Used for plain --target mode with socks5h://.
 */
static int upstream_dst_from_hostport(const char *hostport,
				      struct gwp_socks5_addr *out)
{
	char buf[300], *colon, *host;
	size_t hl, n = strlen(hostport);
	int port;

	if (n == 0 || n >= sizeof(buf))
		return -EINVAL;
	memcpy(buf, hostport, n + 1);

	colon = strrchr(buf, ':');
	if (!colon)
		return -EINVAL;
	*colon = '\0';
	port = atoi(colon + 1);
	if (port <= 0 || port > 65535)
		return -EINVAL;

	host = buf;
	hl = strlen(host);
	if (host[0] == '[' && hl >= 2 && host[hl - 1] == ']') {
		host[hl - 1] = '\0';
		host++;
	}

	return upstream_dst_from_domain(host, (uint16_t)port, out);
}

/*
 * Finalize gcp->up_dst (the destination requested from the upstream proxy)
 * right before the client handshake. If a socks5h domain was already captured
 * during protocol parsing, keep it; otherwise derive it from the resolved
 * target IP (socks5://), or from the configured --target host for plain mode
 * with socks5h://.
 */
/*
 * Format gcp->up_dst as an HTTP authority ("host:port" or "[ipv6]:port") for an
 * upstream CONNECT request. Returns 0 on success, -EINVAL on a bad address.
 */
int gwp_upstream_authority(const struct gwp_socks5_addr *dst, char *buf,
			   size_t cap)
{
	uint16_t port = ntohs(dst->port);
	char ip[INET6_ADDRSTRLEN];
	int n;

	switch (dst->ver) {
	case GWP_SOCKS5_ATYP_DOMAIN:
		n = snprintf(buf, cap, "%s:%u", dst->domain.str, port);
		break;
	case GWP_SOCKS5_ATYP_IPV4:
		if (!inet_ntop(AF_INET, dst->ip4, ip, sizeof(ip)))
			return -EINVAL;
		n = snprintf(buf, cap, "%s:%u", ip, port);
		break;
	case GWP_SOCKS5_ATYP_IPV6:
		if (!inet_ntop(AF_INET6, dst->ip6, ip, sizeof(ip)))
			return -EINVAL;
		n = snprintf(buf, cap, "[%s]:%u", ip, port);
		break;
	default:
		return -EINVAL;
	}

	if (n < 0 || (size_t)n >= cap)
		return -EINVAL;
	return 0;
}

int gwp_upstream_finalize_dst(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;

	if (gcp->up_dst.ver != 0)
		return 0;

	if (ctx->upstream.remote_dns && !ctx->cfg.as_socks5 && !ctx->cfg.as_http)
		return upstream_dst_from_hostport(ctx->cfg.target, &gcp->up_dst);

	return upstream_dst_from_sockaddr(&gcp->target_addr, &gcp->up_dst);
}

int gwp_conn_close_attempts(struct gwp_conn_pair *gcp)
{
	int n = 0;
	uint8_t i;

	for (i = 0; i < GWP_MAX_CONN_CAND; i++) {
		if (gcp->attempt_fd[i] < 0)
			continue;
		__sys_close(gcp->attempt_fd[i]);
		gcp->attempt_fd[i] = -1;
		n++;
	}

	if (gcp->attempt_timer_fd >= 0) {
		__sys_close(gcp->attempt_timer_fd);
		gcp->attempt_timer_fd = -1;
		n++;
	}

	return n;
}

void gwp_conn_set_candidates(struct gwp_conn_pair *gcp,
			     const struct gwp_sockaddr *addrs, uint8_t nr)
{
	if (nr > GWP_MAX_CONN_CAND)
		nr = GWP_MAX_CONN_CAND;

	memcpy(gcp->cand, addrs, (size_t)nr * sizeof(*addrs));
	gcp->nr_cand = nr;
	gcp->next_cand = 0;

	/*
	 * Keep target_addr meaningful for callers that read it before the
	 * first attempt starts (logging, upstream_dst_from_sockaddr()).
	 */
	if (nr)
		gcp->target_addr = gcp->cand[0];
}

void gwp_conn_set_single_candidate(struct gwp_conn_pair *gcp,
				   const struct gwp_sockaddr *addr)
{
	gwp_conn_set_candidates(gcp, addr, 1);
}

static int prepare_target_addr_domain(struct gwp_wrk *w,
				      struct gwp_conn_pair *gcp,
				      const char *host, const char *port)
{
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_cfg *cfg = &ctx->cfg;
	int r;

	/* Remember the requested hostname for ACL "-m domain" matching. */
	gcp->req_domain = host;

	/*
	 * socks5h://: don't resolve locally; hand the hostname to the upstream
	 * proxy. up_dst carries the domain and we're ready to connect.
	 */
	if (ctx->upstream.enabled && ctx->upstream.remote_dns) {
		/*
		 * Strict: atoi() stops at the first non-digit and reports the
		 * prefix, so a port carrying trailing junk was silently
		 * accepted. Unlike the resolving paths below, nothing else
		 * validates this string before it becomes the upstream's
		 * destination port.
		 */
		char *endp;
		unsigned long p = strtoul(port, &endp, 10);

		if (endp == port || *endp || !p || p > 65535)
			return -EINVAL;
		return upstream_dst_from_domain(host, (uint16_t)p, &gcp->up_dst);
	}

	if (cfg->use_raw_dns) {
		return gwp_raw_dns_resolve(w, gcp, host, port);
	} else {
		struct gwp_sockaddr addrs[GWP_MAX_CONN_CAND];
		uint8_t nr = 0;

		r = gwp_dns_cache_lookup_list(ctx->dns, host, port, addrs,
					      GWP_MAX_CONN_CAND, &nr);
		if (!r) {
			gwp_conn_set_candidates(gcp, addrs, nr);
			pr_dbg(&ctx->lh, "Found %s:%s in DNS cache %s (%u addr)",
				host, port, ip_to_str(&gcp->target_addr), nr);
			return 0;
		}

		return queue_dns_resolution(w, gcp, host, port);
	}
}

static int socks5_prepare_target_addr_domain(struct gwp_wrk *w,
					     struct gwp_conn_pair *gcp)
{
	struct gwp_socks5_addr *dst;
	const char *host;
	char portstr[6];
	uint16_t port;
	int r;

	dst = &gcp->s5_conn->dst_addr;
	port = ntohs(dst->port);
	host = dst->domain.str;
	snprintf(portstr, sizeof(portstr), "%hu", port);
	r = prepare_target_addr_domain(w, gcp, host, portstr);
	if (r == -EINPROGRESS)
		gcp->conn_state = CONN_STATE_SOCKS5_DNS_QUERY;

	return r;
}

int gwp_socks5_prepare_target_addr(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_sockaddr *ta = &gcp->target_addr;
	struct gwp_socks5_conn *sc = gcp->s5_conn;
	struct gwp_socks5_addr *dst;

	assert(sc);

	dst = &sc->dst_addr;
	memset(ta, 0, sizeof(*ta));
	switch (dst->ver) {
	case GWP_SOCKS5_ATYP_IPV4:
		memcpy(&ta->i4.sin_addr, &dst->ip4, 4);
		ta->i4.sin_port = dst->port;
		ta->i4.sin_family = AF_INET;
		gwp_conn_set_single_candidate(gcp, ta);
		return 0;
	case GWP_SOCKS5_ATYP_IPV6:
		memcpy(&ta->i6.sin6_addr, &dst->ip6, 16);
		ta->i6.sin6_port = dst->port;
		ta->i6.sin6_family = AF_INET6;
		gwp_conn_set_single_candidate(gcp, ta);
		return 0;
	case GWP_SOCKS5_ATYP_DOMAIN:
		return socks5_prepare_target_addr_domain(w, gcp);
	}

	return -ENOSYS;
}

int gwp_socks5_handle_data(struct gwp_conn_pair *gcp)
{
	struct gwp_socks5_conn *sc = gcp->s5_conn;
	size_t out_len, in_len;
	void *in, *out;
	int r;

	assert(sc);

	in = gcp->client.buf;
	in_len = gcp->client.len;
	out = gcp->target.buf + gcp->target.len;
	out_len = gcp->target.cap - gcp->target.len;
	r = gwp_socks5_conn_handle_data(sc, in, &in_len, out, &out_len);
	gwp_conn_buf_advance(&gcp->client, in_len);
	gcp->target.len += out_len;
	return (r == -EAGAIN) ? 0 : r;
}

static int handle_socks5_prot(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	int r;

	/*
	 * Only on the first pass. The greeting need not arrive in one segment,
	 * and a second allocation would leak the first and throw away the
	 * parser state along with it.
	 */
	if (!gcp->s5_conn) {
		gcp->s5_conn = gwp_socks5_conn_alloc(ctx->socks5);
		if (!gcp->s5_conn) {
			pr_err(&ctx->lh, "Failed to allocate SOCKS5 connection");
			return -ENOMEM;
		}
		/*
		 * Claim the connection as SOCKS5 now, exactly as the HTTP side
		 * does: s5_conn and http_conn share a union, and gwp_free_conn_pair()
		 * picks the member to free by prot_type. Leaving it NONE while
		 * the greeting is still arriving means a teardown in that window
		 * frees neither, which a client can repeat at will.
		 */
		gcp->prot_type = GWP_PROT_TYPE_SOCKS5;
	}

	r = gwp_socks5_handle_data(gcp);
	if (r < 0) {
		gwp_socks5_conn_free(gcp->s5_conn);
		gcp->s5_conn = NULL;
		/* Unclaim it, so an HTTP fallback can take the union over. */
		gcp->prot_type = GWP_PROT_TYPE_NONE;
		return r;
	}

	if (gcp->s5_conn->state == GWP_SOCKS5_ST_INIT) {
		/*
		 * The greeting is still incomplete, so the protocol remains
		 * undecided -- the parser needs VER and NMETHODS before it can
		 * even reject a non-SOCKS5 first byte, and it has consumed
		 * nothing. Report that rather than success: gwp_socks5_handle_data()
		 * folds the parser's -EAGAIN into 0 for its other caller, and
		 * taking that 0 at face value here would leave the pair in
		 * CONN_STATE_PROT while claiming the state machine had advanced.
		 * epoll's dispatcher asserts on exactly that combination.
		 */
		return -EAGAIN;
	}

	/*
	 * This must be a SOCKS5 data connection, there is no possibility to
	 * fallback to HTTP because the SOCKS5 parser already sees the SOCKS5
	 * header.
	 */
	gcp->conn_state = CONN_STATE_SOCKS5_DATA;
	gcp->prot_type = GWP_PROT_TYPE_SOCKS5;
	return 0;
}

/* Write the IPv4-mapped IPv6 form (::ffff:a.b.c.d) of a 4-byte address. */
static void set_v4mapped(struct in6_addr *a6, const void *v4)
{
	memset(a6, 0, sizeof(*a6));
	a6->s6_addr[10] = 0xff;
	a6->s6_addr[11] = 0xff;
	memcpy(&a6->s6_addr[12], v4, 4);
}

/* Canonicalise an address to (is_v4, pointer to its 4- or 16-byte IP). */
static void sockaddr_canon_ip(const struct gwp_sockaddr *a, bool *is_v4,
			      const uint8_t **ip)
{
	if (a->sa.sa_family == AF_INET) {
		*is_v4 = true;
		*ip = (const uint8_t *)&a->i4.sin_addr;
		return;
	}
	if (IN6_IS_ADDR_V4MAPPED(&a->i6.sin6_addr)) {
		*is_v4 = true;
		*ip = &a->i6.sin6_addr.s6_addr[12];
		return;
	}
	*is_v4 = false;
	*ip = a->i6.sin6_addr.s6_addr;
}

/*
 * Compare two addresses by IP only (not port), treating an IPv4 address and its
 * IPv4-mapped IPv6 form as equal. The UDP relay socket is dual-stack, so a
 * datagram's source is always AF_INET6 (v4-mapped for an IPv4 peer) while the
 * pinned client address may be either family; this bridges them.
 */
bool gwp_sockaddr_ip_eq(const struct gwp_sockaddr *a, const struct gwp_sockaddr *b)
{
	const uint8_t *ai, *bi;
	bool av4, bv4;

	sockaddr_canon_ip(a, &av4, &ai);
	sockaddr_canon_ip(b, &bv4, &bi);
	if (av4 != bv4)
		return false;
	return !memcmp(ai, bi, av4 ? 4 : 16);
}

bool gwp_sockaddr_eq(const struct gwp_sockaddr *a, const struct gwp_sockaddr *b)
{
	if (a->sa.sa_family != b->sa.sa_family)
		return false;
	if (a->sa.sa_family == AF_INET)
		return a->i4.sin_port == b->i4.sin_port &&
		       a->i4.sin_addr.s_addr == b->i4.sin_addr.s_addr;
	if (a->sa.sa_family == AF_INET6)
		return a->i6.sin6_port == b->i6.sin6_port &&
		       !memcmp(&a->i6.sin6_addr, &b->i6.sin6_addr, 16);
	return false;
}

enum gwp_udp_act gwp_udp_relay_classify(struct gwp_wrk *w,
					struct gwp_conn_pair *gcp,
					unsigned char *base, size_t n,
					const struct gwp_sockaddr *src,
					struct gwp_udp_out *out)
{
	bool client_dgram;

	if (gcp->udp_pinned) {
		client_dgram = gwp_sockaddr_eq(src, &gcp->udp_peer);
	} else {
		/*
		 * Until the client is pinned nothing can be relayed back, so
		 * accept only its first datagram, and only from the same IP as
		 * its TCP control connection (RFC 1928); this keeps an off-path
		 * source from hijacking the association.
		 */
		if (!gwp_sockaddr_ip_eq(src, &gcp->client_addr))
			return GWP_UDP_DROP;
		gcp->udp_peer = *src;
		gcp->udp_pinned = true;
		client_dgram = true;
	}

	if (client_dgram) {
		/* Client -> target: strip the header, forward the payload. */
		struct gwp_socks5_addr dst;
		struct gwp_sockaddr tsa;
		socklen_t tslen;
		size_t hdr_len;

		if (gwp_socks5_udp_parse_hdr(base, n, &dst, &hdr_len))
			return GWP_UDP_DROP;
		if (gwp_socks5_addr_to_sockaddr(&dst, &tsa, &tslen))
			return GWP_UDP_DROP;	/* domain target: unsupported */
		if (!gwp_ctx_acl_output_allowed(w->ctx, &gcp->udp_peer, &tsa,
						gcp_req_user(gcp),
						GWP_ACL_PROTO_UDP))
			return GWP_UDP_DROP;	/* ACL denied this datagram */
		out->buf = base + hdr_len;
		out->len = n - hdr_len;
		out->dst = tsa;
		out->dstlen = tslen;
		return GWP_UDP_TO_TARGET;
	} else {
		/* Target -> client: prepend a header in the front slack. */
		struct gwp_socks5_addr sa;
		size_t h, hlen;

		gwp_socks5_reply_addr_from_sockaddr(src, &sa);
		h = (sa.ver == GWP_SOCKS5_ATYP_IPV4) ? 3 + 1 + 4 + 2
						     : 3 + 1 + 16 + 2;
		if (gwp_socks5_udp_build_hdr(&sa, base - h, h, &hlen))
			return GWP_UDP_DROP;
		/* The relay is dual-stack, so udp_peer is always AF_INET6. */
		out->buf = base - h;
		out->len = h + n;
		out->dst = gcp->udp_peer;
		out->dstlen = sizeof(gcp->udp_peer.i6);
		return GWP_UDP_TO_CLIENT;
	}
}

int gwp_socks5_addr_to_sockaddr(const struct gwp_socks5_addr *a,
				struct gwp_sockaddr *sa, socklen_t *slen)
{
	/*
	 * The relay socket is dual-stack AF_INET6, so every target is expressed
	 * as an IPv6 sockaddr: an IPv4 target becomes its IPv4-mapped form so
	 * one socket can reach both families.
	 */
	memset(sa, 0, sizeof(*sa));
	switch (a->ver) {
	case GWP_SOCKS5_ATYP_IPV4:
		sa->i6.sin6_family = AF_INET6;
		set_v4mapped(&sa->i6.sin6_addr, a->ip4);
		sa->i6.sin6_port = a->port;
		*slen = sizeof(sa->i6);
		return 0;
	case GWP_SOCKS5_ATYP_IPV6:
		sa->i6.sin6_family = AF_INET6;
		memcpy(&sa->i6.sin6_addr, a->ip6, 16);
		sa->i6.sin6_port = a->port;
		*slen = sizeof(sa->i6);
		return 0;
	default:
		/* Domain targets in relayed datagrams need DNS; not yet. */
		return -EAFNOSUPPORT;
	}
}

/*
 * Fill a SOCKS5 header address from a UDP reply's source. The relay is
 * dual-stack so the source is AF_INET6; a v4-mapped source is unmapped back to
 * an IPv4 ATYP so the client sees the target it actually addressed.
 */
void gwp_socks5_reply_addr_from_sockaddr(const struct gwp_sockaddr *src,
					 struct gwp_socks5_addr *a)
{
	if (src->sa.sa_family == AF_INET) {
		a->ver = GWP_SOCKS5_ATYP_IPV4;
		memcpy(a->ip4, &src->i4.sin_addr, 4);
		a->port = src->i4.sin_port;
		return;
	}
	if (IN6_IS_ADDR_V4MAPPED(&src->i6.sin6_addr)) {
		a->ver = GWP_SOCKS5_ATYP_IPV4;
		memcpy(a->ip4, &src->i6.sin6_addr.s6_addr[12], 4);
		a->port = src->i6.sin6_port;
		return;
	}
	a->ver = GWP_SOCKS5_ATYP_IPV6;
	memcpy(a->ip6, &src->i6.sin6_addr, 16);
	a->port = src->i6.sin6_port;
}

int gwp_socks5_udp_associate_setup(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	static const int type = SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC;
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_socks5_addr bnd;
	struct gwp_sockaddr local, relay;
	socklen_t slen = sizeof(local);
	int fd = -1, r, rep = GWP_SOCKS5_REP_SUCCESS;
	size_t out_len;

	/*
	 * UDP ASSOCIATE is not chained through an upstream proxy: an HTTP
	 * upstream cannot carry UDP at all, and SOCKS5 upstream UDP is not
	 * implemented. Binding a local relay here would silently bypass the
	 * configured chain, so refuse the command instead.
	 */
	if (ctx->upstream.enabled) {
		rep = GWP_SOCKS5_REP_COMMAND_NOT_SUPPORTED;
		goto reply;
	}

	/*
	 * Re-check the INPUT chain for this client as a UDP request: a "-p udp"
	 * rule cannot match at accept time, where the control connection is TCP.
	 */
	if (!gwp_ctx_acl_client_allowed(ctx, &gcp->client_addr,
					GWP_ACL_PROTO_UDP)) {
		pr_info(&ctx->lh, "ACL denied UDP ASSOCIATE for client %s",
			ip_to_str(&gcp->client_addr));
		rep = GWP_SOCKS5_REP_NOT_ALLOWED;
		goto reply;
	}

	/*
	 * The relay is a dual-stack IPv6 socket bound to the wildcard address so
	 * one socket can both receive from the client and reach IPv4 and IPv6
	 * targets (a socket bound to a single-family local address cannot egress
	 * the other family). BND.ADDR must still be an address the client can
	 * reach, so it is taken from the proxy address the client connected to
	 * (getsockname() on the control fd), paired with the relay's ephemeral
	 * port. Widening the bind to the wildcard does not change the threat
	 * model: the port is ephemeral and the client is IP-pinned.
	 */
	r = __sys_getsockname(gcp->client.fd, &local.sa, &slen);
	if (r < 0) {
		pr_err(&ctx->lh, "UDP associate: getsockname(client) failed: %s",
			strerror(-r));
		rep = GWP_SOCKS5_REP_FAILURE;
		goto reply;
	}

	fd = __sys_socket(AF_INET6, type, 0);
	if (fd < 0) {
		pr_err(&ctx->lh, "UDP associate: socket() failed: %s", strerror(-fd));
		rep = GWP_SOCKS5_REP_FAILURE;
		goto reply;
	}

	setskopt_int(fd, IPPROTO_IPV6, IPV6_V6ONLY, 0);
	if (ctx->cfg.mark)
		setskopt_int(fd, SOL_SOCKET, SO_MARK, ctx->cfg.mark);

	memset(&relay, 0, sizeof(relay));
	relay.i6.sin6_family = AF_INET6;
	relay.i6.sin6_addr = in6addr_any;
	relay.i6.sin6_port = 0;
	r = __sys_bind(fd, &relay.sa, sizeof(relay.i6));
	if (r < 0) {
		pr_err(&ctx->lh, "UDP associate: bind() failed: %s", strerror(-r));
		__sys_close(fd);
		fd = -1;
		rep = GWP_SOCKS5_REP_FAILURE;
		goto reply;
	}

	/* BND.ADDR from the control connection, BND.PORT from the relay socket. */
	slen = sizeof(relay);
	r = __sys_getsockname(fd, &relay.sa, &slen);
	if (r < 0) {
		pr_err(&ctx->lh, "UDP associate: getsockname(relay) failed: %s",
			strerror(-r));
		__sys_close(fd);
		fd = -1;
		rep = GWP_SOCKS5_REP_FAILURE;
		goto reply;
	}
	if (local.sa.sa_family == AF_INET) {
		bnd.ver = GWP_SOCKS5_ATYP_IPV4;
		memcpy(bnd.ip4, &local.i4.sin_addr, 4);
	} else {
		bnd.ver = GWP_SOCKS5_ATYP_IPV6;
		memcpy(bnd.ip6, &local.i6.sin6_addr, 16);
	}
	bnd.port = relay.i6.sin6_port;

	gcp->udp_fd = fd;
	pr_info(&ctx->lh,
		"SOCKS5 UDP ASSOCIATE relay bound (idx=%u, cfd=%d, ufd=%d)",
		gcp->idx, gcp->client.fd, fd);

reply:
	out_len = gcp->target.cap - gcp->target.len;
	r = gwp_socks5_conn_cmd_udp_associate_res(gcp->s5_conn,
			(rep == GWP_SOCKS5_REP_SUCCESS) ? &bnd : NULL, rep,
			gcp->target.buf + gcp->target.len, &out_len);
	if (r < 0)
		return r;
	gcp->target.len += (uint32_t)out_len;

	return (rep == GWP_SOCKS5_REP_SUCCESS) ? 0 : -ECONNREFUSED;
}

int gwp_handle_conn_state_socks5(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	int r, ct;

	ct = gcp->conn_state;
	if (ct == CONN_STATE_PROT) {
		return handle_socks5_prot(w, gcp);
	} else if (ct == CONN_STATE_SOCKS5_DATA) {
		r = gwp_socks5_handle_data(gcp);
		if (r)
			return r;
	} else if (ct == CONN_STATE_SOCKS5_DNS_QUERY ||
		   ct == CONN_STATE_SOCKS5_CONNECT) {
		/*
		 * The request is parsed; we are waiting on the resolver or on
		 * connect(), and the client is still armed for input because
		 * arm_poll_for_dns_query() only adds the resolver's eventfd.
		 * A client that pipelines data behind its request therefore
		 * arrives here, which is rude rather than impossible -- it
		 * used to abort the process.
		 *
		 * There is nothing to parse yet, so leave the bytes buffered:
		 * once the target is up, forwarding sends them on, which is
		 * what the client was banking on.
		 */
		return -EAGAIN;
	} else {
		assert(0 && "Invalid SOCKS5 connection state");
		return -EINVAL;
	}

	if (gcp->s5_conn->state == GWP_SOCKS5_ST_CMD_CONNECT) {
		r = gwp_socks5_prepare_target_addr(w, gcp);
		if (r == -EINPROGRESS) {
			gcp->conn_state = CONN_STATE_SOCKS5_DNS_QUERY;
			return r;
		}

		if (!r)
			gcp->conn_state = CONN_STATE_SOCKS5_CONNECT;
	} else if (gcp->s5_conn->state == GWP_SOCKS5_ST_CMD_UDP_ASSOCIATE) {
		/*
		 * Bind the relay socket and queue the reply; both event loops
		 * then arm their own relay (handle_udp_associate on epoll,
		 * arm_udp_relay on io_uring).
		 */
		r = gwp_socks5_udp_associate_setup(w, gcp);
		if (!r)
			gcp->conn_state = CONN_STATE_SOCKS5_UDP_ASSOCIATE;
	}

	return r;
}

/*
 * Queue the HTTP 407 "Proxy Authentication Required" reply for the client. It
 * is written into the client-bound buffer; the event loop flushes it before
 * tearing the connection down (the same path as SOCKS5 error replies). Returns
 * a negative error so the caller drops the connection.
 */
static int http_reject_unauthorized(struct gwp_conn_pair *gcp)
{
	int r = gwp_http_build_auth_required_reply(gcp->target.buf + gcp->target.len,
						   gcp->target.cap - gcp->target.len);
	if (r < 0)
		return -ENOBUFS;

	gcp->target.len += (uint32_t)r;
	return -EACCES;
}

/*
 * Queue the HTTP 431 reply for a request header that will not fit in the
 * client buffer, so the client is told its header is too large instead of just
 * having the connection reset. Same mechanism as the 407 above: written to the
 * client-bound buffer, flushed by the event loop before teardown. Returns a
 * negative error so the caller drops the connection.
 */
static int http_reject_too_large(struct gwp_conn_pair *gcp)
{
	int r = gwp_http_build_too_large_reply(gcp->target.buf + gcp->target.len,
					       gcp->target.cap - gcp->target.len);
	if (r < 0)
		return -E2BIG;

	gcp->target.len += (uint32_t)r;
	return -E2BIG;
}

/*
 * Prepend a rewritten origin-form forward request to any request-body bytes
 * already buffered in client.buf, so the forwarding path streams it to the
 * origin.
 */
static int http_inject_forward_request(struct gwp_conn_pair *gcp,
				       const char *req, size_t req_len)
{
	if (req_len > (size_t)(gcp->client.cap - gcp->client.len))
		return -E2BIG;

	if (gcp->client.len)
		memmove(gcp->client.buf + req_len, gcp->client.buf, gcp->client.len);
	memcpy(gcp->client.buf, req, req_len);
	gcp->client.len += (uint32_t)req_len;
	return 0;
}

/* Resolve and connect to @host:@port, setting the HTTP connect/DNS state. */
static int http_connect_target(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			       const char *host, const char *port)
{
	int r = prepare_target_addr_domain(w, gcp, host, port);

	if (r == -EINPROGRESS)
		gcp->conn_state = CONN_STATE_HTTP_DNS_QUERY;
	else if (!r)
		gcp->conn_state = CONN_STATE_HTTP_CONNECT;

	return r;
}

int gwp_handle_conn_state_http(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	const char *req = NULL;
	size_t in_len, req_len = 0;
	char *host, *port;
	int r;

	if (gcp->conn_state == CONN_STATE_PROT) {
		gcp->http_conn = gwp_http_conn_alloc();
		if (!gcp->http_conn) {
			pr_err(&ctx->lh, "Failed to allocate HTTP connection");
			return -ENOMEM;
		}
		/*
		 * Claim the connection as HTTP now, so a teardown while the
		 * header is still arriving frees http_conn (gwp_free_conn_pair
		 * switches on prot_type).
		 */
		gcp->prot_type = GWP_PROT_TYPE_HTTP;
		gcp->conn_state = CONN_STATE_HTTP_HDR;
	} else if (gcp->conn_state == CONN_STATE_HTTP_DNS_QUERY ||
		   gcp->conn_state == CONN_STATE_HTTP_CONNECT) {
		/* Pipelined behind the request; see the SOCKS5 side. */
		return -EAGAIN;
	} else if (gcp->conn_state != CONN_STATE_HTTP_HDR) {
		assert(0 && "Invalid HTTP connection state");
		return -EINVAL;
	}

	in_len = gcp->client.len;
	r = gwp_http_conn_process(gcp->http_conn, ctx->auth, gcp->client.buf,
				  &in_len, &host, &port, &req, &req_len);
	gwp_conn_buf_advance(&gcp->client, in_len);

	switch (r) {
	case GWP_HTTP_NEED_MORE:
		/*
		 * Header still incomplete. If the client buffer is already full
		 * the parser can never accumulate the rest (a header line longer
		 * than the buffer), so reject rather than ask a full,
		 * level-triggered socket to be read again -- which would
		 * busy-spin until the protocol timeout fires.
		 */
		if (gcp->client.len >= gcp->client.cap)
			return http_reject_too_large(gcp);
		return 0;
	case GWP_HTTP_NEED_AUTH:
		return http_reject_unauthorized(gcp);
	case GWP_HTTP_CONNECT:
		return http_connect_target(w, gcp, host, port);
	case GWP_HTTP_FORWARD:
		r = http_inject_forward_request(gcp, req, req_len);
		if (r == -E2BIG)
			return http_reject_too_large(gcp);
		if (r < 0)
			return r;
		return http_connect_target(w, gcp, host, port);
	default:	/* GWP_HTTP_ERR */
		pr_dbg(&ctx->lh, "Invalid HTTP request (fd=%d)", gcp->client.fd);
		return -EINVAL;
	}
}

int gwp_handle_conn_state_prot(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_cfg *cfg = &w->ctx->cfg;
	struct gwp_ctx *ctx = w->ctx;
	bool socks5_einval = false;
	int r = 0;

	assert(gcp->target.fd < 0);
	assert(cfg->as_http || cfg->as_socks5);
	assert(gcp->conn_state == CONN_STATE_PROT);

	/*
	 * At this point, the used protocol may not be known yet.
	 *
	 * If both as_socks5 and as_http and are true. Then, try
	 * parsing as SOCKS5 first. If it fails with -EINVAL, try
	 * parsing as HTTP.
	 *
	 * This allows a single server port be used as both HTTP
	 * and SOCKS5 simultaneously.
	 */
	if (cfg->as_socks5) {
		r = gwp_handle_conn_state_socks5(w, gcp);
		if (r != -EINVAL)
			return r;
		socks5_einval = true;
	}

	if (cfg->as_http) {
		if (socks5_einval)
			pr_dbg(&ctx->lh,
				"Not a socks5 protocol, fallback to HTTP (fd=%d; ca=%s)",
				gcp->client.fd, ip_to_str(&gcp->client_addr));

		r = gwp_handle_conn_state_http(w, gcp);
		if (r != -EINVAL)
			return r;
	}

	return r;
}

noinline
static void *gwp_ctx_thread_entry(void *arg)
{
	struct gwp_wrk *w = arg;
	struct gwp_ctx *ctx = w->ctx;
	int r;

	switch (ctx->ev_used) {
	case GWP_EV_EPOLL:
		r = gwp_ctx_thread_entry_epoll(w);
		break;
	case GWP_EV_IO_URING:
#ifdef CONFIG_IO_URING
		r = gwp_ctx_thread_entry_io_uring(w);
#else
		pr_err(&ctx->lh, "IO_URING support is not enabled in this build");
		r = -ENOSYS;
#endif
		break;
	default:
		pr_err(&ctx->lh, "Unknown event loop type: %d", ctx->ev_used);
		r = -EINVAL;
		break;
	}

	ctx->stop = true;
	gwp_ctx_signal_all_workers(ctx);
	pr_info(&ctx->lh, "Worker %u stopped", w->idx);
	return (void *)(intptr_t)r;
}

static int gwp_ctx_run(struct gwp_ctx *ctx)
{
	int i, r;

	for (i = 0; i < ctx->cfg.nr_workers; i++) {
		struct gwp_wrk *w = &ctx->workers[i];
		char tmp[128];

		/*
		 * Skip the first worker as it will
		 * run on the main thread.
		 */
		if (i == 0)
			continue;

		r = pthread_create(&w->thread, NULL, &gwp_ctx_thread_entry, w);
		if (r) {
			gwp_ctx_stop(ctx);
			pr_err(&ctx->lh, "Failed to create worker thread %d: %s",
				i, strerror(r));
			return -r;
		}

		w->need_join = true;
		snprintf(tmp, sizeof(tmp), "gwproxy-wrk-%d", i);
		pthread_setname_np(w->thread, tmp);
	}

	return (int)(intptr_t)gwp_ctx_thread_entry(&ctx->workers[0]);
}

static struct gwp_ctx *g_ctx = NULL;

__cold
static void sig_handler(int sig)
{
	if (g_ctx)
		gwp_ctx_stop(g_ctx);

	(void)sig;
}

static void prepare_rlimit(void)
{
	struct rlimit rl;
	int r;

	r = getrlimit(RLIMIT_NOFILE, &rl);
	if (r < 0) {
		fprintf(stderr, "Failed to get RLIMIT_NOFILE: %s\n", strerror(errno));
		return;
	}

	rl.rlim_cur = rl.rlim_max;
	r = setrlimit(RLIMIT_NOFILE, &rl);
	if (r < 0) {
		fprintf(stderr, "Failed to set RLIMIT_NOFILE: %s\n", strerror(errno));
		return;
	}
}

int main(int argc, char *argv[])
{
	struct sigaction sa = { .sa_handler = &sig_handler };
	struct gwp_ctx ctx;
	int r;

	memset(&ctx, 0, sizeof(ctx));
	r = parse_options(argc, argv, &ctx.cfg);
	if (r < 0)
		goto out;

	prepare_rlimit();
	r = gwp_ctx_init(&ctx);
	if (r < 0)
		goto out;

	g_ctx = &ctx;
	r |= sigaction(SIGINT, &sa, NULL);
	r |= sigaction(SIGTERM, &sa, NULL);
	sa.sa_handler = SIG_IGN;
	r |= sigaction(SIGPIPE, &sa, NULL);
	if (r < 0) {
		r = -errno;
		fprintf(stderr, "Failed to set signal handlers: %s\n", strerror(-r));
		goto out_free;
	}

	r = gwp_ctx_run(&ctx);
out_free:
	gwp_ctx_free(&ctx);
out:
	return -r;
}
