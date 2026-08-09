// SPDX-License-Identifier: GPL-2.0-only
/*
 * gwnet_http1.c - HTTP/1.x parser implementation.
 *
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <gwproxy/http1.h>
#include "common.h"

static inline size_t min_st(size_t a, size_t b)
{
	return (a < b) ? a : b;
}

/**
 * Checks if a character is a valid 'tchar' as defined in RFC 7230,
 * Section 3.2.6.
 *
 * Reference: https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.6
 *
 * A 'tchar' is any visible (VCHAR) character except delimiters,
 * specifically: "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-"
 * / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA.
 *
 * @param  c The character to check, represented as an int.
 * @return 1 if the character is a valid 'tchar', 0 otherwise.
 */
static inline int is_tchar(int c)
{
	/* Digits. */
	if (c >= '0' && c <= '9')
		return 1;

	/* Uppercase */
	if (c >= 'A' && c <= 'Z')
		return 1;

	/* Lowercase */
	if (c >= 'a' && c <= 'z')
		return 1;

	/* The 15 extra symbols from the spec */
	switch (c) {
	case '!': case '#': case '$': case '%': case '&':
	case '\'': case '*': case '+': case '-': case '.':
	case '^': case '_': case '`': case '|': case '~':
		return 1;
	default:
		return 0;
	}
}

static inline int is_space(int c)
{
	return (c == ' ' || c == '\t');
}

static inline int is_vchar(int c)
{
	/* Visible characters are from 0x20 to 0x7E, inclusive. */
	if (c >= 0x20 && c <= 0x7E)
		return 1;

	/* DEL character is not a visible character. */
	if (c == 0x7F)
		return 0;

	return 0;
}

static inline int is_alpha(int c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

/**
 * Check if the given HTTP header field key is one of the standard
 * headers that are allowed to appear multiple times in a message and
 * should be merged into a single comma-separated header value
 * according to the HTTP specification.
 *
 * @param key The header field name to check (case-insensitive).
 * @param n   The length of the header field name.
 * @return    true if the header is allowed to be provided multiple
 *            times and should be merged; false otherwise.
 */
static bool is_field_allowed_to_be_duplicate(const char *key, size_t n)
{
	static const char *comma_separated_list_headers[] = {
		/* RFC 7231, Section 5.3.2 */
		"Accept",
		/* RFC 7231, Section 5.3.3 */
		"Accept-Charset",
		/* RFC 7231, Section 5.3.4 */
		"Accept-Encoding",
		/* RFC 7231, Section 5.3.5 */
		"Accept-Language",
		/* RFC 7233, Section 2.3 */
		"Accept-Ranges",
		/* RFC 7231, Section 7.4.1 */
		"Allow",
		/* RFC 7234, Section 5.2 */
		"Cache-Control",
		/* RFC 7230, Section 6.1 */
		"Connection",
		/* RFC 7232, Section 3.1 */
		"If-Match",
		/* RFC 7232, Section 3.2 */
		"If-None-Match",
		/* RFC 7233, Section 3.1 */
		"Range",
		/* RFC 7234, Section 5.4 */
		"Pragma",
		/* RFC 7235, Section 4.3 */
		"Proxy-Authenticate",
		/* RFC 7230, Section 4.3 */
		"TE",
		/* RFC 7230, Section 4.4 */
		"Trailer",
		/* RFC 7230, Section 3.3.1 */
		"Transfer-Encoding",
		/* RFC 7230, Section 6.7 */
		"Upgrade",
		/* RFC 7231, Section 7.1.4 */
		"Vary",
		/* RFC 7230, Section 5.7.1 */
		"Via",
		/* RFC 7234, Section 5.5 */
		"Warning",
		/* RFC 7235, Section 4.1 */
		"WWW-Authenticate",

		NULL
	};

	const char **p;

	for (p = comma_separated_list_headers; *p; p++) {
		const char *hdr = *p;
		size_t hdr_len = strlen(hdr);

		if (n == hdr_len && !strncasecmp(key, hdr, n))
			return true;
	}

	return false;
}


/**
 * Parse the first line of an HTTP/1.x request header, also known as
 * the request line. According to RFC 9112, Section 3.1.1, the request
 * line consists of the method, request-target, and HTTP version,
 * separated by spaces and terminated by CRLF.
 *
 * Example:
 *   GET /index.html HTTP/1.1\r\n
 *
 * It extracts and validates these components from the provided parsing
 * context and stores them in the request header structure.
 *
 * Reference:
 *   RFC 9112, Section 3:
 *   https://datatracker.ietf.org/doc/html/rfc9112#section-3
 *
 * @param ctx  Pointer to the HTTP header parsing context.
 * @param hdr  Pointer to the HTTP request header structure to populate.
 * @return     0 on success,
 *             -EAGAIN if more data is needed,
 *             -EINVAL if the request line is malformed,
 *             -ENOMEM if memory allocation fails,
 *             -E2BIG  if the request line exceeds the maximum length.
 */
static int parse_hdr_req_first_line(struct gwnet_http_hdr_pctx *ctx,
				    struct gwnet_http_req_hdr *hdr)
{
	struct method_entry {
		const char str[9];
		uint8_t len;
		uint8_t code;
	};
	static const struct method_entry methods[] = {
		{ "GET",	3, GWNET_HTTP_METHOD_GET },
		{ "POST",	4, GWNET_HTTP_METHOD_POST },
		{ "PUT",	3, GWNET_HTTP_METHOD_PUT },
		{ "DELETE",	6, GWNET_HTTP_METHOD_DELETE },
		{ "HEAD",	4, GWNET_HTTP_METHOD_HEAD },
		{ "OPTIONS",	7, GWNET_HTTP_METHOD_OPTIONS },
		{ "PATCH",	5, GWNET_HTTP_METHOD_PATCH },
		{ "TRACE",	5, GWNET_HTTP_METHOD_TRACE },
		{ "CONNECT",	7, GWNET_HTTP_METHOD_CONNECT }
	};
	static const size_t nr_methods = sizeof(methods) / sizeof(methods[0]);
	size_t i, cmpl, reml, off = 0, len = ctx->len - ctx->off;
	const char *uri, *qs, *path, *buf = &ctx->buf[ctx->off];
	uint32_t uri_len, qs_len, path_len;
	uint8_t method_code, version_code;

	if (!len)
		return -EAGAIN;

	method_code = GWNET_HTTP_METHOD_UNKNOWN;
	for (i = 0; i < nr_methods; i++) {
		const struct method_entry *me = &methods[i];
		size_t mlen = me->len;

		cmpl = min_st(len, mlen);
		if (memcmp(buf, me->str, cmpl))
			continue;

		if (cmpl < mlen)
			return -EAGAIN;

		method_code = me->code;
		off += mlen;
		break;
	}

	if (method_code == GWNET_HTTP_METHOD_UNKNOWN)
		return -EINVAL;

	if (off >= len)
		return -EAGAIN;

	/*
	 * After the method, there must be a space.
	 */
	if (!is_space(buf[off]))
		return -EINVAL;


	off++;
	if (ctx->tot_len + off >= ctx->max_len)
		return -E2BIG;
	if (off >= len)
		return -EAGAIN;

	/*
	 * Per RFC 7230, Section 5.3.1:
	 * When making a request directly to an origin server,
	 * other than a CONNECT or server-wide OPTIONS request
	 * a client MUST send only the absolute path and query
	 * components of the target URI as the request-target.
	 * If the target URI's path component is empty, the
	 * client MUST send "/" as the path within the
	 * origin-form of request-target.
	 */
	if (method_code != GWNET_HTTP_METHOD_CONNECT &&
	    method_code != GWNET_HTTP_METHOD_OPTIONS) {
		/*
		 * Origin-form starts with '/'. absolute-form (which a client
		 * uses to address a forwarding proxy, RFC 7230 Section 5.3.2)
		 * starts with a scheme, i.e. an alphabetic character; it is
		 * validated in full once the whole request-target has been
		 * captured below.
		 */
		if (buf[off] != '/' && !is_alpha(buf[off]))
			return -EINVAL;
	} else {
		if (!is_vchar(buf[off]))
			return -EINVAL;
	}

	path = uri = &buf[off];
	qs = NULL;
	path_len = uri_len = qs_len = 0;

	/*
	 * Keep going until we find a space character.
	 */
	while (1) {
		char c = buf[off++];

		if (off >= len)
			return -EAGAIN;

		if (ctx->tot_len + off >= ctx->max_len)
			return -E2BIG;

		if (is_space(c))
			break;

		if (!is_vchar(c))
			return -EINVAL;

		uri_len++;
		if (qs)
			qs_len++;
		else
			path_len++;

		/*
		 * If we find a question mark, start assigning the
		 * the query string.
		 *
		 * Only the FIRST one delimits it (RFC 3986 Section 3.4): every
		 * later '?' is an ordinary query character, already counted
		 * into @qs_len above. Acting on those too would rewind @path_len
		 * once per '?' even though only the first was ever added to it,
		 * underflowing this unsigned counter on a target with more
		 * trailing '?' than leading path characters -- "GET /???" is
		 * enough -- and would leave @qs pointing past the last '?'
		 * while @qs_len still measures from the first.
		 */
		if (c == '?' && !qs) {
			qs = &buf[off];
			path_len--;
		}
	}

	/*
	 * Trim trailing slashes from the path.
	 *
	 * @path_len may be zero here when the request-target has an empty
	 * path (e.g. a CONNECT or OPTIONS target that starts with '?'), so
	 * guard the index to avoid an out-of-bounds read on path[-1].
	 */
	while (path_len > 0 && path[path_len - 1] == '/') {
		if (path_len == 1)
			break; /* Keep at least one slash. */
		path_len--;
	}

	/*
	 * A non-origin-form target on a non-CONNECT/OPTIONS request must be
	 * absolute-form: scheme "://" host [...]. Require the "://" delimiter
	 * so a bare target that is neither origin- nor absolute-form (e.g.
	 * "GET foo HTTP/1.1") is still rejected. The proxy layer parses out the
	 * host/port/path from the captured uri.
	 */
	if (method_code != GWNET_HTTP_METHOD_CONNECT &&
	    method_code != GWNET_HTTP_METHOD_OPTIONS && uri[0] != '/') {
		uint32_t k;
		bool abs_form = false;

		for (k = 0; k + 2 < uri_len; k++) {
			if (uri[k] == ':' && uri[k + 1] == '/' &&
			    uri[k + 2] == '/') {
				abs_form = true;
				break;
			}
		}

		if (!abs_form)
			return -EINVAL;
	}

	/*
	 * Parse the HTTP version. Only support HTTP/1.0 and HTTP/1.1.
	 */
	reml = len - off;
	cmpl = min_st(reml, 7);
	if (memcmp(&buf[off], "HTTP/1.", cmpl))
		return -EINVAL;
	if (cmpl < 7)
		return -EAGAIN;

	off += 7;
	if (off >= len)
		return -EAGAIN;

	/*
	 * Check exceeding length upfront, we know that
	 * the HTTP version is always 8 characters long
	 * followed by a CRLF (or just LF).
	 */
	if (ctx->tot_len + off + 1 + 1 >= ctx->max_len)
		return -E2BIG;

	switch (buf[off]) {
	case '0':
		version_code = GWNET_HTTP_VER_1_0;
		break;
	case '1':
		version_code = GWNET_HTTP_VER_1_1;
		break;
	default:
		return -EINVAL;
	}

	if (++off >= len)
		return -EAGAIN;

	/*
	 * After the HTTP version, expect a CRLF. But the CR
	 * is optional, so we can also accept just LF.
	 */
	if (buf[off] == '\r') {
		if (++off >= len)
			return -EAGAIN;
	}

	if (buf[off] != '\n')
		return -EINVAL;

	++off;
	if (ctx->tot_len + off >= ctx->max_len)
		return -E2BIG;

	hdr->path = malloc(path_len + 1);
	if (unlikely(!hdr->path))
		return -ENOMEM;

	hdr->uri = malloc(uri_len + 1);
	if (unlikely(!hdr->uri))
		goto free_path;

	if (qs_len) {
		hdr->qs = malloc(qs_len + 1);
		if (unlikely(!hdr->qs))
			goto free_uri;
		memcpy(hdr->qs, qs, qs_len);
		hdr->qs[qs_len] = '\0';
	}

	memcpy(hdr->path, path, path_len);
	hdr->path[path_len] = '\0';
	memcpy(hdr->uri, uri, uri_len);
	hdr->uri[uri_len] = '\0';

	hdr->method = method_code;
	hdr->version = version_code;
	ctx->off += off;
	ctx->tot_len += off;
	return 0;

free_uri:
	free(hdr->uri);
	hdr->uri = NULL;
free_path:
	free(hdr->path);
	hdr->path = NULL;
	return -ENOMEM;
}

/**
 * Parse the first line of an HTTP/1.x response header, also known as
 * the status line. According to RFC 7230 Section 3.1.2, the status
 * line is formatted as: HTTP-version SP status-code SP reason-phrase
 * CRLF.
 *
 * Example:
 *   HTTP/1.1 200 OK\r\n
 *
 * It extracts the HTTP version, status code, and reason phrase from
 * the response header's first line and populates the provided
 * response header structure.
 *
 * Reference:
 *   RFC 7230, Section 3.1.2:
 *   https://datatracker.ietf.org/doc/html/rfc7230#section-3.1.2
 *
 * @param ctx Pointer to the HTTP header parsing context.
 * @param hdr Pointer to the HTTP response header structure to populate.
 * @return    0 on success,
 *            -EAGAIN if more data is needed,
 *            -EINVAL if the first line is malformed,
 *            -ENOMEM if memory allocation fails.
 */
static int parse_hdr_res_first_line(struct gwnet_http_hdr_pctx *ctx,
				    struct gwnet_http_res_hdr *hdr)
{
	size_t off = 0, len = ctx->len - ctx->off, cmpl, reml, i;
	const char *reason, *buf = &ctx->buf[ctx->off], *p;
	uint8_t version_code;
	uint32_t reason_len;
	char rcode[3];
	uint16_t code;

	if (!len)
		return -EAGAIN;

	/*
	 * Parse the HTTP version. Only support HTTP/1.0 and HTTP/1.1.
	 */
	reml = len - off;
	cmpl = min_st(reml, 7);
	if (memcmp(buf, "HTTP/1.", cmpl))
		return -EINVAL;
	if (cmpl < 7)
		return -EAGAIN;

	off += 7;
	if (off >= len)
		return -EAGAIN;
	if (ctx->tot_len + off >= ctx->max_len)
		return -E2BIG;

	switch (buf[off]) {
	case '0':
		version_code = GWNET_HTTP_VER_1_0;
		break;
	case '1':
		version_code = GWNET_HTTP_VER_1_1;
		break;
	default:
		return -EINVAL;
	}

	if (++off >= len)
		return -EAGAIN;
	if (ctx->tot_len + off >= ctx->max_len)
		return -E2BIG;

	/*
	 * After the HTTP version, there must be a space.
	 */
	if (!is_space(buf[off]))
		return -EINVAL;

	off++;
	if (ctx->tot_len + off >= ctx->max_len)
		return -E2BIG;
	if (off >= len)
		return -EAGAIN;


	/*
	 * Parse the HTTP response code. It must be a 3-digit number
	 * between 100 and 599, inclusive.
	 */
	rcode[0] = buf[off++];
	if (rcode[0] < '1' || rcode[0] > '5')
		return -EINVAL;
	if (off >= len)
		return -EAGAIN;

	for (i = 1; i <= 2; i++) {
		rcode[i] = buf[off++];
		if (rcode[i] < '0' || rcode[i] > '9')
			return -EINVAL;
		if (off >= len)
			return -EAGAIN;
	}

	code = (rcode[0] - '0') * 100 +
	       (rcode[1] - '0') * 10 +
	       (rcode[2] - '0');

	/*
	 * After the response code, there must be a space.
	 */
	if (!is_space(buf[off]))
		return -EINVAL;

	/*
	 * Keep going until we find a non-space character.
	 */
	while (is_space(buf[off])) {
		if (++off >= len)
			return -EAGAIN;
		if (ctx->tot_len + off >= ctx->max_len)
			return -E2BIG;
	}

	/*
	 * After the space, there may be a reason phrase.
	 * The reason phrase is optional, if it exists,
	 * it must only contain vchar or space chars.
	 *
	 * It ends with a CRLF, but the CR is optional.
	 */
	reason = &buf[off];
	reason_len = 0;

	while (1) {
		char c = buf[off];

		if (c == '\r' || c == '\n')
			break;

		if (++off >= len)
			return -EAGAIN;
		if (ctx->tot_len + off >= ctx->max_len)
			return -E2BIG;

		if (!is_vchar(c) && !is_space(c))
			return -EINVAL;

		reason_len++;
	}

	if (buf[off] == '\r') {
		if (++off >= len)
			return -EAGAIN;
		if (ctx->tot_len + off >= ctx->max_len)
			return -E2BIG;
	}

	if (buf[off] != '\n')
		return -EINVAL;
	++off;
	if (ctx->tot_len + off >= ctx->max_len)
		return -E2BIG;

	if (reason_len) {
		/*
		 * Trim the trailing whitespaces from
		 * the reason phrase.
		 */
		p = &reason[reason_len - 1];
		while (p >= reason && is_space(*p)) {
			--reason_len;
			--p;
		}
	}

	hdr->reason = malloc(reason_len + 1);
	if (!hdr->reason)
		return -ENOMEM;

	memcpy(hdr->reason, reason, reason_len);
	hdr->reason[reason_len] = '\0';
	hdr->version = version_code;
	hdr->code = code;
	ctx->off += off;
	ctx->tot_len += off;
	return 0;
}

/**
 * Parse HTTP header fields from the provided parsing context.
 *
 * According to RFC 7230, Section 3.2: "Each header field consists of a
 * case-insensitive field name followed by a colon (":"), optional
 * whitespace, and the field value."
 *
 * Reference: RFC 7230, Section 3.2 - Header Fields
 * https://datatracker.ietf.org/doc/html/rfc7230#section-3.2
 *
 * @param ctx Pointer to the HTTP header parsing context.
 * @param ff  Pointer to the structure where parsed header fields will be
 *            stored.
 * @return    0 on success,
 *            -EAGAIN if more data is needed,
 *            -EINVAL if the header fields are malformed,
 *            -ENOMEM if memory allocation fails,
 *            -E2BIG  if the header fields exceed the maximum length.
 */
static int parse_hdr_fields(struct gwnet_http_hdr_pctx *ctx,
			    struct gwnet_http_hdr_fields *ff)
{
	size_t off = 0, len = ctx->len - ctx->off;
	const char *buf = &ctx->buf[ctx->off];
	int r;

	if (!len)
		return -EAGAIN;

	while (1) {
		const char *k, *v, *p;
		uint32_t kl, vl;

		if (buf[off] == '\r') {
			if (++off >= len)
				return -EAGAIN;
			if (ctx->tot_len + off >= ctx->max_len)
				return -E2BIG;
		}

		if (buf[off] == '\n') {
			++off;
			if (ctx->tot_len + off >= ctx->max_len)
				return -E2BIG;
			ctx->off += off;
			break;
		}

		/*
		 * Parse the key. The key must only contain tchar
		 * characters, and must end with a colon.
		 *
		 * After the colon, there may be a space, but it is
		 * optional. If it exists, it must be followed by
		 * a vchar or space characters.
		 *
		 * The value may contain trailing space characters,
		 * they must be trimmed.
		 *
		 * The value may be empty, but the key must not.
		 */
		k = &buf[off];
		kl = 0;
		while (1) {
			if (off >= len)
				return -EAGAIN;

			if (ctx->tot_len + off >= ctx->max_len)
				return -E2BIG;

			if (buf[off] == ':')
				break;

			if (!is_tchar(buf[off]))
				return -EINVAL;

			kl++;
			off++;
		}

		if (!kl)
			return -EINVAL;

		if (++off >= len)
			return -EAGAIN;

		/*
		 * Keep going until we find a non-space character.
		 */
		while (is_space(buf[off])) {
			if (++off >= len)
				return -EAGAIN;

			if (ctx->tot_len + off >= ctx->max_len)
				return -E2BIG;
		}

		v = &buf[off];
		vl = 0;
		while (1) {
			char c = buf[off];

			if (c == '\r' || c == '\n')
				break;

			if (!is_vchar(c) && !is_space(c))
				return -EINVAL;

			vl++;
			off++;
			if (off >= len)
				return -EAGAIN;

			if (ctx->tot_len + off >= ctx->max_len)
				return -E2BIG;
		}

		if (buf[off] == '\r') {
			if (++off >= len)
				return -EAGAIN;
			if (ctx->tot_len + off >= ctx->max_len)
				return -E2BIG;
		}

		if (buf[off] != '\n')
			return -EINVAL;
		++off;
		if (ctx->tot_len + off >= ctx->max_len)
			return -E2BIG;

		if (vl) {
			/*
			 * Trim trailing whitespaces from the value.
			 */
			p = &v[vl - 1];
			while (p >= v && is_space(*p)) {
				--vl;
				--p;
			}
		}

		r = gwnet_http_hdr_fields_addl(ff, k, kl, v, vl);
		if (r)
			return (r < 0) ? r : -EINVAL;

		ctx->tot_len += off;
		ctx->off += off;
		if (off >= len)
			return -EAGAIN;

		buf = &ctx->buf[ctx->off];
		len = ctx->len - ctx->off;
		off = 0;
	}

	return 0;
}

int gwnet_http_hdr_pctx_init(struct gwnet_http_hdr_pctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->state = GWNET_HTTP_HDR_PARSE_ST_INIT;
	return 0;
}

void gwnet_http_hdr_pctx_free(struct gwnet_http_hdr_pctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
}

static void prepare_parser(struct gwnet_http_hdr_pctx *ctx)
{
	ctx->tot_len = 0;
	if (!ctx->max_len)
		ctx->max_len = (1024ull*16ull) + 1ull;
	else
		ctx->max_len += 1ull;
}

static int __gwnet_http_req_hdr_parse(struct gwnet_http_hdr_pctx *ctx,
				      struct gwnet_http_req_hdr *hdr)
{
	int r = 0;

	if (ctx->state == GWNET_HTTP_HDR_PARSE_ST_INIT) {
		ctx->state = GWNET_HTTP_HDR_PARSE_ST_FIRST_LINE;
		memset(hdr, 0, sizeof(*hdr));
		prepare_parser(ctx);
	}

	if (ctx->state == GWNET_HTTP_HDR_PARSE_ST_FIRST_LINE) {
		r = parse_hdr_req_first_line(ctx, hdr);
		if (r)
			return r;
		ctx->state = GWNET_HTTP_HDR_PARSE_ST_FIELDS;
	}

	if (ctx->state == GWNET_HTTP_HDR_PARSE_ST_FIELDS) {
		r = parse_hdr_fields(ctx, &hdr->fields);
		if (r)
			return r;
		ctx->state = GWNET_HTTP_HDR_PARSE_ST_DONE;
	}

	return r;
}

static int __gwnet_http_res_hdr_parse(struct gwnet_http_hdr_pctx *ctx,
				      struct gwnet_http_res_hdr *hdr)
{
	int r = 0;

	if (ctx->state == GWNET_HTTP_HDR_PARSE_ST_INIT) {
		ctx->state = GWNET_HTTP_HDR_PARSE_ST_FIRST_LINE;
		memset(hdr, 0, sizeof(*hdr));
		prepare_parser(ctx);
	}

	if (ctx->state == GWNET_HTTP_HDR_PARSE_ST_FIRST_LINE) {
		r = parse_hdr_res_first_line(ctx, hdr);
		if (r)
			return r;
		ctx->state = GWNET_HTTP_HDR_PARSE_ST_FIELDS;
	}

	if (ctx->state == GWNET_HTTP_HDR_PARSE_ST_FIELDS) {
		r = parse_hdr_fields(ctx, &hdr->fields);
		if (r)
			return r;
		ctx->state = GWNET_HTTP_HDR_PARSE_ST_DONE;
	}

	return r;
}

static int hdr_translate_ret_err(struct gwnet_http_hdr_pctx *ctx, int r)
{
	switch (r) {
	case 0:
		ctx->err = GWNET_HTTP_HDR_ERR_NONE;
		break;
	case -EAGAIN:
		ctx->err = GWNET_HTTP_HDR_ERR_INCOMPLETE;
		break;
	case -EINVAL:
		ctx->err = GWNET_HTTP_HDR_ERR_MALFORMED;
		break;
	case -E2BIG:
		ctx->err = GWNET_HTTP_HDR_ERR_TOO_LONG;
		break;
	default:
		ctx->err = GWNET_HTTP_HDR_ERR_INTERNAL;
		break;
	}

	return r;
}

__hot
int gwnet_http_req_hdr_parse(struct gwnet_http_hdr_pctx *ctx,
			     struct gwnet_http_req_hdr *hdr)
{
	return hdr_translate_ret_err(ctx, __gwnet_http_req_hdr_parse(ctx, hdr));
}

__hot
int gwnet_http_res_hdr_parse(struct gwnet_http_hdr_pctx *ctx,
			     struct gwnet_http_res_hdr *hdr)
{
	return hdr_translate_ret_err(ctx, __gwnet_http_res_hdr_parse(ctx, hdr));
}

__hot
void gwnet_http_req_hdr_free(struct gwnet_http_req_hdr *hdr)
{
	if (!hdr)
		return;

	free(hdr->path);
	free(hdr->uri);
	free(hdr->qs);
	gwnet_http_hdr_fields_free(&hdr->fields);
	memset(hdr, 0, sizeof(*hdr));
}

__hot
void gwnet_http_res_hdr_free(struct gwnet_http_res_hdr *hdr)
{
	if (!hdr)
		return;

	free(hdr->reason);
	gwnet_http_hdr_fields_free(&hdr->fields);
	memset(hdr, 0, sizeof(*hdr));
}

__hot
void gwnet_http_hdr_fields_free(struct gwnet_http_hdr_fields *ff)
{
	size_t i;

	if (!ff)
		return;

	for (i = 0; i < ff->nr; i++) {
		free(ff->ff[i].key);
		free(ff->ff[i].val);
	}

	free(ff->ff);
	memset(ff, 0, sizeof(*ff));
}

__hot
int gwnet_http_hdr_fields_add(struct gwnet_http_hdr_fields *ff, const char *k,
			      const char *v)
{
	return gwnet_http_hdr_fields_addl(ff, k, strlen(k), v, strlen(v));
}

__hot
int gwnet_http_hdr_fields_addf(struct gwnet_http_hdr_fields *ff,
			       const char *k, const char *fmt, ...)
{
	va_list args1, args2;
	size_t vlen;
	char *v;
	int r;

	va_start(args1, fmt);
	va_copy(args2, args1);
	r = vsnprintf(NULL, 0, fmt, args1);
	va_end(args1);

	v = malloc(r + 1);
	if (!v) {
		r = -ENOMEM;
		goto out;
	}

	vlen = (size_t)r;
	vsnprintf(v, vlen + 1, fmt, args2);
	r = gwnet_http_hdr_fields_addl(ff, k, strlen(k), v, vlen);
	free(v);
out:
	va_end(args2);
	return r;
}

static ssize_t find_hdr_field_idx(const struct gwnet_http_hdr_fields *ff,
				  const char *k, size_t klen)
{
	size_t i;

	for (i = 0; i < ff->nr; i++) {
		struct gwnet_http_hdr_field *f = &ff->ff[i];
		if (!strncasecmp(f->key, k, klen)) {
			if (strlen(f->key) == klen)
				return i;
		}
	}

	return -ENOENT;
}

__hot
int gwnet_http_hdr_fields_addl(struct gwnet_http_hdr_fields *ff,
			       const char *k, size_t klen,
			       const char *v, size_t vlen)
{
	ssize_t idx = find_hdr_field_idx(ff, k, klen);
	struct gwnet_http_hdr_field *f;
	char *new_val;

	if (idx < 0) {
		struct gwnet_http_hdr_field *new_fields;
		size_t new_size;
		char *kc, *vc;

		kc = malloc(klen + 1);
		if (!kc)
			return -ENOMEM;

		vc = malloc(vlen + 1);
		if (!vc) {
			free(kc);
			return -ENOMEM;
		}

		new_size = (ff->nr + 1) * sizeof(*ff->ff);
		new_fields = realloc(ff->ff, new_size);
		if (!new_fields) {
			free(kc);
			free(vc);
			return -ENOMEM;
		}

		memcpy(kc, k, klen);
		memcpy(vc, v, vlen);
		kc[klen] = '\0';
		vc[vlen] = '\0';
		ff->ff = new_fields;
		f = &ff->ff[ff->nr++];
		f->key = kc;
		f->val = vc;
		return 0;
	}

	f = &ff->ff[idx];
	if (is_field_allowed_to_be_duplicate(k, klen)) {
		size_t cur_len, new_val_len;

		if (!vlen)
			return 0;

		cur_len = strlen(f->val);
		new_val_len = cur_len + vlen + 3;
		new_val = realloc(f->val, new_val_len);
		if (!new_val)
			return -ENOMEM;

		if (!cur_len) {
			memcpy(new_val, v, vlen);
			new_val[vlen] = '\0';
		} else {
			memcpy(&new_val[cur_len], ", ", 2);
			memcpy(&new_val[cur_len + 2], v, vlen);
			new_val[cur_len + 2 + vlen] = '\0';
		}

		f->val = new_val;
		return 0;
	} else {
		new_val = realloc(f->val, vlen + 1);
		if (!new_val)
			return -ENOMEM;

		memcpy(new_val, v, vlen);
		new_val[vlen] = '\0';
		f->val = new_val;
		return EEXIST;
	}
}

const char *gwnet_http_hdr_fields_get(const struct gwnet_http_hdr_fields *ff,
				      const char *k)
{
	return gwnet_http_hdr_fields_getl(ff, k, strlen(k));
}

const char *gwnet_http_hdr_fields_getl(const struct gwnet_http_hdr_fields *ff,
				       const char *k, size_t klen)
{
	ssize_t idx = find_hdr_field_idx(ff, k, klen);
	if (idx < 0)
		return NULL;

	return ff->ff[idx].val;
}

int gwnet_http_body_pctx_init(struct gwnet_http_body_pctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->state = GWNET_HTTP_BODY_PARSE_ST_INIT;
	return 0;
}

void gwnet_http_body_pctx_free(struct gwnet_http_body_pctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
}

static int is_xdigit(int c)
{
	if (c >= '0' && c <= '9')
		return 1;
	if (c >= 'A' && c <= 'F')
		return 1;
	if (c >= 'a' && c <= 'f')
		return 1;
	return 0;
}

static int parse_chunked_len(struct gwnet_http_body_pctx *ctx)
{
	size_t len = ctx->len - ctx->off, off = 0, i = 0;
	const char *buf = &ctx->buf[ctx->off];
	uint64_t decoded_len = 0;
	char tmp_buf[17], *e, c;

	if (!len)
		return -EAGAIN;

	while (1) {
		if (off >= len)
			return -EAGAIN;

		if (i >= 16)
			return -EINVAL;

		c = buf[off];
		if (!is_xdigit(c))
			break;

		tmp_buf[i++] = c;
		off++;
	}

	/*
	 * Early exit if we haven't found any hex digits.
	 */
	if (!i)
		return -EINVAL;

	/*
	 * We have read the hex digits. Now, we skip any chunk extension.
	 * The extension is any character until we hit a CR or LF.
	 * We are lenient: we accept LF without CR.
	 */
	while (1) {
		if (off >= len)
			return -EAGAIN;

		if (ctx->tot_len_raw + off >= ctx->max_len)
			return -E2BIG;

		c = buf[off++];
		if (c == '\r') {
			if (off >= len)
				return -EAGAIN;
			if (ctx->tot_len_raw + off + 1 >= ctx->max_len)
				return -E2BIG;
			if (buf[off++] != '\n')
				return -EINVAL;
			break;
		} else if (c == '\n') {
			break;
		}
	}

	tmp_buf[i] = '\0';
	errno = 0;
	decoded_len = strtoull(tmp_buf, &e, 16);
	if (errno || e == tmp_buf || *e != '\0')
		return -EINVAL;

	ctx->off += off;
	ctx->tot_len_raw += off;
	ctx->rem_len = decoded_len;

	/*
	 * Predictive check for exceeding the maximum length.
	 */
	if (ctx->tot_len_raw + decoded_len >= ctx->max_len)
		return -E2BIG;

	if (decoded_len) {
		ctx->state = GWNET_HTTP_BODY_PARSE_ST_CHK_DATA;
		ctx->found_zero_len = false;
	} else {
		ctx->state = GWNET_HTTP_BODY_PARSE_ST_CHK_TR;
		ctx->found_zero_len = true;
	}

	return 0;
}

static int parse_chunked_data(struct gwnet_http_body_pctx *ctx, char **dst_p,
			      size_t *dst_len_p)
{
	size_t len = ctx->len - ctx->off, copy_len;
	const char *buf = &ctx->buf[ctx->off];

	if (!len)
		return -EAGAIN;

	copy_len = min_st(ctx->rem_len, len);

	if (*dst_p)
		copy_len = min_st(copy_len, *dst_len_p);

	if (!copy_len)
		return -ENOBUFS;

	if (ctx->tot_len_raw + copy_len >= ctx->max_len)
		return -E2BIG;

	if (*dst_p) {
		memcpy(*dst_p, buf, copy_len);
		*dst_len_p -= copy_len;
		*dst_p += copy_len;
	}

	ctx->off += copy_len;
	ctx->tot_len += copy_len;
	ctx->tot_len_raw += copy_len;
	ctx->rem_len -= copy_len;

	if (!ctx->rem_len)
		ctx->state = GWNET_HTTP_BODY_PARSE_ST_CHK_TR;

	return 0;
}

static int parse_chunked_tr(struct gwnet_http_body_pctx *ctx)
{
	size_t len = ctx->len - ctx->off, cmpl;
	const char *buf = &ctx->buf[ctx->off];

	if (!len)
		return -EAGAIN;

	if (ctx->tot_len_raw + 2 >= ctx->max_len)
		return -E2BIG;

	cmpl = min_st(len, 2);
	if (memcmp(buf, "\r\n", cmpl))
		return -EINVAL;
	if (cmpl < 2)
		return -EAGAIN;

	ctx->off += 2;
	ctx->tot_len_raw += 2;
	if (ctx->found_zero_len)
		ctx->state = GWNET_HTTP_BODY_PARSE_ST_CHK_DONE;
	else
		ctx->state = GWNET_HTTP_BODY_PARSE_ST_CHK_LEN;

	return 0;
}

__hot
int gwnet_http_body_parse_chunked(struct gwnet_http_body_pctx *ctx,
				  char *dst, size_t dst_len)
{
	int r = 0;

	/*
	 * If @dst is NULL, the @dst_len must be zero.
	 */
	if (!dst && dst_len)
		return -EINVAL;

	if (ctx->state == GWNET_HTTP_BODY_PARSE_ST_INIT) {
		ctx->state = GWNET_HTTP_BODY_PARSE_ST_CHK_LEN;
		if (!ctx->max_len)
			ctx->max_len = (1024ull*128ull) + 1ull;
		else
			ctx->max_len += 1ull;
		ctx->tot_len = 0;
		ctx->tot_len_raw = 0;
		ctx->err = GWNET_HTTP_BODY_ERR_NONE;
	}

	while (1) {
		if (ctx->state == GWNET_HTTP_BODY_PARSE_ST_CHK_LEN) {
			r = parse_chunked_len(ctx);
			if (r)
				break;
		}

		if (ctx->state == GWNET_HTTP_BODY_PARSE_ST_CHK_DATA) {
			r = parse_chunked_data(ctx, &dst, &dst_len);
			if (r)
				break;
		}

		if (ctx->state == GWNET_HTTP_BODY_PARSE_ST_CHK_TR) {
			r = parse_chunked_tr(ctx);
			if (r)
				break;
		}

		if (ctx->state == GWNET_HTTP_BODY_PARSE_ST_CHK_DONE) {
			r = 0;
			break;
		}
	}

	switch (r) {
	case 0:
		ctx->err = GWNET_HTTP_BODY_ERR_NONE;
		break;
	case -EAGAIN:
		ctx->err = GWNET_HTTP_BODY_ERR_INCOMPLETE;
		break;
	case -EINVAL:
		ctx->err = GWNET_HTTP_BODY_ERR_MALFORMED;
		break;
	case -E2BIG:
		/*
		 * The source is too long.
		 */
		ctx->err = GWNET_HTTP_BODY_ERR_TOO_LONG;
		break;
	case -ENOBUFS:
		/*
		 * The destination buffer is too small.
		 */
		ctx->err = GWNET_HTTP_BODY_ERR_DST_TOO_SMALL;
		break;
	default:
		ctx->err = GWNET_HTTP_BODY_ERR_INTERNAL;
		break;
	}

	return r;
}

#ifdef GWNET_HTTP1_TESTS
#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>
#define PRTEST_OK()					\
do {							\
	static bool __printed;				\
	if (!__printed) {				\
		printf("Test passed: %s\n", __func__);	\
		__printed = true;			\
	}						\
} while (0)

#define ASSERT_HDRF(f, k, v)			\
do {						\
	assert(!strcmp((f)->key, k));		\
	assert(!strcmp((f)->val, v));		\
} while (0)

static void test_req_hdr_simple(void)
{
	static const char buf[] =
		"GET /index.html HTTP/1.0\r\n"
		"Host: example.com\r\n"
		"User-Agent: gwhttp\r\n"
		"Accept: */*\r\n"
		"Connection: keep-alive\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_req_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_req_hdr_parse(&ctx, &hdr);
	assert(!r);
	assert(ctx.off == len);
	assert(ctx.state == GWNET_HTTP_HDR_PARSE_ST_DONE);
	assert(hdr.method == GWNET_HTTP_METHOD_GET);
	assert(hdr.version == GWNET_HTTP_VER_1_0);
	assert(!strcmp(hdr.uri, "/index.html"));
	assert(!hdr.qs);
	assert(hdr.fields.nr == 4);
	ASSERT_HDRF(&hdr.fields.ff[0], "Host", "example.com");
	ASSERT_HDRF(&hdr.fields.ff[1], "User-Agent", "gwhttp");
	ASSERT_HDRF(&hdr.fields.ff[2], "Accept", "*/*");
	ASSERT_HDRF(&hdr.fields.ff[3], "Connection", "keep-alive");
	gwnet_http_req_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_req_hdr_absolute_form(void)
{
	static const char buf[] =
		"GET http://example.com:8080/path?q=1 HTTP/1.1\r\n"
		"Host: example.com:8080\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_req_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_req_hdr_parse(&ctx, &hdr);
	assert(!r);
	assert(ctx.state == GWNET_HTTP_HDR_PARSE_ST_DONE);
	assert(hdr.method == GWNET_HTTP_METHOD_GET);
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	/* The full absolute-form target is preserved in uri. */
	assert(!strcmp(hdr.uri, "http://example.com:8080/path?q=1"));
	assert(hdr.fields.nr == 1);
	ASSERT_HDRF(&hdr.fields.ff[0], "Host", "example.com:8080");
	gwnet_http_req_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_req_hdr_bare_target_rejected(void)
{
	/* A target that is neither origin-form nor absolute-form is invalid. */
	static const char buf[] =
		"GET foo HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_req_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_req_hdr_parse(&ctx, &hdr);
	assert(r == -EINVAL);
	assert(ctx.err == GWNET_HTTP_HDR_ERR_MALFORMED);
	gwnet_http_req_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_res_hdr_simple(void)
{
	static const char buf[] =
		"HTTP/1.0 200 OK\r\n"
		"Server: gwhttpd\r\n"
		"Date: Mon, 01 Jan 1999 00:00:00 GMT\r\n"
		"Content-Type: text/html; charset=UTF-8\r\n"
		"Content-Length: 1234\r\n"
		"Connection: close\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_res_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_res_hdr_parse(&ctx, &hdr);
	assert(!r);
	assert(ctx.off == len);
	assert(ctx.state == GWNET_HTTP_HDR_PARSE_ST_DONE);
	assert(ctx.err == GWNET_HTTP_HDR_ERR_NONE);
	assert(hdr.code == 200);
	assert(!strcmp(hdr.reason, "OK"));
	assert(hdr.version == GWNET_HTTP_VER_1_0);
	assert(hdr.fields.nr == 5);
	ASSERT_HDRF(&hdr.fields.ff[0], "Server", "gwhttpd");
	ASSERT_HDRF(&hdr.fields.ff[1], "Date", "Mon, 01 Jan 1999 00:00:00 GMT");
	ASSERT_HDRF(&hdr.fields.ff[2], "Content-Type", "text/html; charset=UTF-8");
	ASSERT_HDRF(&hdr.fields.ff[3], "Content-Length", "1234");
	ASSERT_HDRF(&hdr.fields.ff[4], "Connection", "close");
	gwnet_http_res_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_req_hdr_query_string(void)
{
	static const char buf[] =
		"GET /index.html?foo=bar&baz=qux HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_req_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_req_hdr_parse(&ctx, &hdr);
	assert(!r);
	assert(ctx.off == len);
	assert(ctx.state == GWNET_HTTP_HDR_PARSE_ST_DONE);
	assert(hdr.method == GWNET_HTTP_METHOD_GET);
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(!strcmp(hdr.uri, "/index.html?foo=bar&baz=qux"));
	assert(!strcmp(hdr.qs, "foo=bar&baz=qux"));
	gwnet_http_req_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_req_hdr_query_string_empty(void)
{
	static const char buf[] =
		"GET /index.html? HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_req_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_req_hdr_parse(&ctx, &hdr);
	assert(!r);
	assert(ctx.off == len);
	assert(ctx.state == GWNET_HTTP_HDR_PARSE_ST_DONE);
	assert(hdr.method == GWNET_HTTP_METHOD_GET);
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(!strcmp(hdr.uri, "/index.html?"));
	assert(!hdr.qs);
	gwnet_http_req_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

/*
 * Only the first '?' delimits the query string; the rest are ordinary query
 * characters. Getting that wrong used to rewind the unsigned path length once
 * per '?' and underflow it, so these targets are the boundary: "/??" leaves it
 * at zero, "/???" is the first that wraps, and an empty path with a trailing
 * '?' wraps immediately.
 */
static void test_req_hdr_query_string_multi_qmark(void)
{
	static const struct {
		const char *req, *uri, *path, *qs;
	} cases[] = {
		{ "GET /?? HTTP/1.1\r\nHost: e\r\n\r\n",	"/??",	"/",	"?" },
		{ "GET /??? HTTP/1.1\r\nHost: e\r\n\r\n",	"/???",	"/",	"??" },
		{ "GET /a?b?c HTTP/1.1\r\nHost: e\r\n\r\n",	"/a?b?c", "/a",	"b?c" },
		{ "OPTIONS ?? HTTP/1.1\r\nHost: e\r\n\r\n",	"??",	"",	"?" },
	};
	static const size_t nr = sizeof(cases) / sizeof(cases[0]);
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_req_hdr hdr;
	size_t i;
	int r;

	for (i = 0; i < nr; i++) {
		r = gwnet_http_hdr_pctx_init(&ctx);
		assert(!r);
		ctx.buf = cases[i].req;
		ctx.len = strlen(cases[i].req);
		r = gwnet_http_req_hdr_parse(&ctx, &hdr);
		assert(!r);
		assert(ctx.state == GWNET_HTTP_HDR_PARSE_ST_DONE);
		assert(!strcmp(hdr.uri, cases[i].uri));
		assert(!strcmp(hdr.path, cases[i].path));
		assert(!strcmp(hdr.qs, cases[i].qs));
		gwnet_http_req_hdr_free(&hdr);
		gwnet_http_hdr_pctx_free(&ctx);
	}
	PRTEST_OK();
}

static void test_req_hdr_invalid_req_line_sp(void)
{
	static const char buf[] =
		"GET   /index.html         HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_req_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_req_hdr_parse(&ctx, &hdr);
	assert(r == -EINVAL);
	gwnet_http_req_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_req_hdr_invalid_res_status_line_sp(void)
{
	// Multiple spaces before the status code is not allowed.
	static const char buf[] =
		"HTTP/1.1     200 OK\r\n"
		"Server: gwhttpd\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_res_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_res_hdr_parse(&ctx, &hdr);
	assert(r == -EINVAL);
	gwnet_http_res_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_req_hdr_invalid_uri_chars(void)
{
	static const char buf[] =
		"GET AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_req_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_req_hdr_parse(&ctx, &hdr);
	assert(r == -EINVAL);
	assert(ctx.err == GWNET_HTTP_HDR_ERR_MALFORMED);
	gwnet_http_req_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_req_hdr_invalid_uri_chars2(void)
{
	static const char buf[] =
		"GET /\0\1\2\3\4\5\6\7 HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"Invalid-Header: \r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_req_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_req_hdr_parse(&ctx, &hdr);
	assert(r == -EINVAL);
	assert(ctx.err == GWNET_HTTP_HDR_ERR_MALFORMED);
	gwnet_http_req_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_req_hdr_invalid_method(void)
{
	static const char buf[] =
		"INVALID /index.html HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_req_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_req_hdr_parse(&ctx, &hdr);
	assert(r == -EINVAL);
	assert(ctx.err == GWNET_HTTP_HDR_ERR_MALFORMED);
	gwnet_http_req_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_req_hdr_invalid_version(void)
{
	static const char buf[] =
		"GET /index.html HTTP/2.0\r\n"
		"Host: example.com\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_req_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_req_hdr_parse(&ctx, &hdr);
	assert(r == -EINVAL);
	assert(ctx.err == GWNET_HTTP_HDR_ERR_MALFORMED);
	gwnet_http_req_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_res_hdr_invalid_version(void)
{
	static const char buf[] =
		"HTTP/2.0 200 OK\r\n"
		"Server: gwhttpd\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_res_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_res_hdr_parse(&ctx, &hdr);
	assert(r == -EINVAL);
	assert(ctx.err == GWNET_HTTP_HDR_ERR_MALFORMED);
	gwnet_http_res_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_req_hdr_trim_whitespaces(void)
{
	static const char buf[] =
		"GET /index.html HTTP/1.1\r\n"
		"Host:\t\t\t\t\t\t\t\t\texample.com\t\t\t\t\t\t\r\n"
		"User-Agent:        gwhttp \t \t \t \r\n"
		"Accept:*/*    \t\t\t          \t\r\n"
		"Connection: \t\t\t  \t\tkeep-alive\t\t \t \r\n"
		"X-Test-A:AAAA\r\n"
		"X-Test-B:      BBBB\r\n"
		"X-Test-C:CCCC     \t\t\t\t   \r\n"
		"X-Test-D: DDDD   \r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_req_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_req_hdr_parse(&ctx, &hdr);
	assert(!r);
	assert(ctx.off == len);
	assert(ctx.state == GWNET_HTTP_HDR_PARSE_ST_DONE);
	assert(hdr.method == GWNET_HTTP_METHOD_GET);
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(!strcmp(hdr.uri, "/index.html"));
	assert(!hdr.qs);
	assert(hdr.fields.nr == 8);
	ASSERT_HDRF(&hdr.fields.ff[0], "Host", "example.com");
	ASSERT_HDRF(&hdr.fields.ff[1], "User-Agent", "gwhttp");
	ASSERT_HDRF(&hdr.fields.ff[2], "Accept", "*/*");
	ASSERT_HDRF(&hdr.fields.ff[3], "Connection", "keep-alive");
	ASSERT_HDRF(&hdr.fields.ff[4], "X-Test-A", "AAAA");
	ASSERT_HDRF(&hdr.fields.ff[5], "X-Test-B", "BBBB");
	ASSERT_HDRF(&hdr.fields.ff[6], "X-Test-C", "CCCC");
	ASSERT_HDRF(&hdr.fields.ff[7], "X-Test-D", "DDDD");
	gwnet_http_req_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_res_hdr_trim_whitespaces(void)
{
	static const char buf[] =
		"HTTP/1.1 200 OK\r\n"
		"Server: \t\t\t\t\t\tgwhttpd\r\n"
		"Date: \t\t\t\tMon, 01 Jan 1999 00:00:00 GMT\r\n"
		"Content-Type: \ttext/html; charset=UTF-8\r\n"
		"Content-Length: \t1234\r\n"
		"Connection: \tclose\r\n"
		"X-Test-A:AAAA\r\n"
		"X-Test-B:      BBBB\r\n"
		"X-Test-C:CCCC     \r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_res_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_res_hdr_parse(&ctx, &hdr);
	assert(!r);
	assert(ctx.off == len);
	assert(ctx.state == GWNET_HTTP_HDR_PARSE_ST_DONE);
	assert(ctx.err == GWNET_HTTP_HDR_ERR_NONE);
	assert(hdr.code == 200);
	assert(!strcmp(hdr.reason, "OK"));
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(hdr.fields.nr == 8);
	ASSERT_HDRF(&hdr.fields.ff[0], "Server", "gwhttpd");
	ASSERT_HDRF(&hdr.fields.ff[1], "Date", "Mon, 01 Jan 1999 00:00:00 GMT");
	ASSERT_HDRF(&hdr.fields.ff[2], "Content-Type", "text/html; charset=UTF-8");
	ASSERT_HDRF(&hdr.fields.ff[3], "Content-Length", "1234");
	ASSERT_HDRF(&hdr.fields.ff[4], "Connection", "close");
	ASSERT_HDRF(&hdr.fields.ff[5], "X-Test-A", "AAAA");
	ASSERT_HDRF(&hdr.fields.ff[6], "X-Test-B", "BBBB");
	ASSERT_HDRF(&hdr.fields.ff[7], "X-Test-C", "CCCC");
	gwnet_http_res_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_req_hdr_invalid_duplicate_fields(void)
{
	static const char buf[] =
		"GET /index.html HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"Host: example.org\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_req_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_req_hdr_parse(&ctx, &hdr);
	assert(r == -EINVAL);
	assert(ctx.err == GWNET_HTTP_HDR_ERR_MALFORMED);
	gwnet_http_req_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_res_hdr_invalid_duplicate_fields(void)
{
	static const char buf[] =
		"HTTP/1.1 200 OK\r\n"
		"Server: gwhttpd\r\n"
		"Server: gwhttpd2\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_res_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_res_hdr_parse(&ctx, &hdr);
	assert(r == -EINVAL);
	assert(ctx.err == GWNET_HTTP_HDR_ERR_MALFORMED);
	gwnet_http_res_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_req_hdr_invalid_space_before_colon(void)
{
	static const char buf[] =
		"GET /index.html HTTP/1.1\r\n"
		"Host : example.com\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_req_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_req_hdr_parse(&ctx, &hdr);
	assert(r == -EINVAL);
	assert(ctx.err == GWNET_HTTP_HDR_ERR_MALFORMED);
	gwnet_http_req_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_res_hdr_invalid_space_before_colon(void)
{
	static const char buf[] =
		"HTTP/1.1 200 OK\r\n"
		"Server : gwhttpd\r\n"
		"Date    : Mon, 01 Jan 1999 00:00:00 GMT\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_res_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_res_hdr_parse(&ctx, &hdr);
	assert(r == -EINVAL);
	assert(ctx.err == GWNET_HTTP_HDR_ERR_MALFORMED);
	gwnet_http_res_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_req_hdr_duplicate_fields_merged_into_comma(void)
{
	static const char buf[] =
		"GET /index.html HTTP/1.1\r\n"
		"Host: example.com, example.org\r\n"
		"User-Agent: gwhttp\r\n"
		"Accept: application/json\r\n"
		"Accept: text/html\r\n"
		"Accept: plain/text\r\n"
		"Connection: keep-alive\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_req_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_req_hdr_parse(&ctx, &hdr);
	assert(!r);
	assert(ctx.off == len);
	assert(ctx.state == GWNET_HTTP_HDR_PARSE_ST_DONE);
	assert(hdr.method == GWNET_HTTP_METHOD_GET);
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(!strcmp(hdr.uri, "/index.html"));
	assert(!hdr.qs);
	assert(hdr.fields.nr == 4);
	ASSERT_HDRF(&hdr.fields.ff[0], "Host", "example.com, example.org");
	ASSERT_HDRF(&hdr.fields.ff[1], "User-Agent", "gwhttp");
	ASSERT_HDRF(&hdr.fields.ff[2], "Accept", "application/json, text/html, plain/text");
	ASSERT_HDRF(&hdr.fields.ff[3], "Connection", "keep-alive");
	gwnet_http_req_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_res_hdr_duplicate_fields_merged_into_comma(void)
{
	static const char buf[] =
		"HTTP/1.1 200 OK\r\n"
		"Server: gwhttpd, gwhttpd2\r\n"
		"Date: Mon, 01 Jan 1999 00:00:00 GMT\r\n"
		"Content-Type: text/html; charset=UTF-8\r\n"
		"Transfer-Encoding: gzip\r\n"
		"Transfer-Encoding: chunked\r\n"
		"Content-Length: 1234\r\n"
		"Connection: close\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_res_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_res_hdr_parse(&ctx, &hdr);
	assert(!r);
	assert(ctx.off == len);
	assert(ctx.state == GWNET_HTTP_HDR_PARSE_ST_DONE);
	assert(ctx.err == GWNET_HTTP_HDR_ERR_NONE);
	assert(hdr.code == 200);
	assert(!strcmp(hdr.reason, "OK"));
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(hdr.fields.nr == 6);
	ASSERT_HDRF(&hdr.fields.ff[0], "Server", "gwhttpd, gwhttpd2");
	ASSERT_HDRF(&hdr.fields.ff[1], "Date", "Mon, 01 Jan 1999 00:00:00 GMT");
	ASSERT_HDRF(&hdr.fields.ff[2], "Content-Type", "text/html; charset=UTF-8");
	ASSERT_HDRF(&hdr.fields.ff[3], "Transfer-Encoding", "gzip, chunked");
	ASSERT_HDRF(&hdr.fields.ff[4], "Content-Length", "1234");
	ASSERT_HDRF(&hdr.fields.ff[5], "Connection", "close");
	gwnet_http_res_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_req_hdr_duplicate_fields_empty_value(void)
{
	static const char buf[] =
		"GET /index.html HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"User-Agent: \r\n"
		"Accept: \r\n"
		"Accept:   \r\n"
		"Accept: text/html\r\n"
		"Accept:     \r\n"
		"Accept:     \r\n"
		"Accept: application/json\r\n"
		"Accept:     \r\n"
		"Accept:     \r\n"
		"Accept: plain/text\r\n"
		"Connection: keep-alive\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_req_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_req_hdr_parse(&ctx, &hdr);
	assert(!r);
	assert(ctx.off == len);
	assert(ctx.state == GWNET_HTTP_HDR_PARSE_ST_DONE);
	assert(ctx.err == GWNET_HTTP_HDR_ERR_NONE);
	assert(hdr.method == GWNET_HTTP_METHOD_GET);
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(!strcmp(hdr.uri, "/index.html"));
	assert(!hdr.qs);
	assert(hdr.fields.nr == 4);
	ASSERT_HDRF(&hdr.fields.ff[0], "Host", "example.com");
	ASSERT_HDRF(&hdr.fields.ff[1], "User-Agent","");
	ASSERT_HDRF(&hdr.fields.ff[2], "Accept", "text/html, application/json, plain/text");
	ASSERT_HDRF(&hdr.fields.ff[3], "Connection", "keep-alive");
	gwnet_http_req_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_res_hdr_duplicate_fields_empty_value(void)
{
	static const char buf[] =
		"HTTP/1.1 200 OK\r\n"
		"Server: gwhttpd\r\n"
		"Date: \r\n"
		"Content-Type: text/html; charset=UTF-8\r\n"
		"Transfer-Encoding: \r\n"
		"Transfer-Encoding: gzip\r\n"
		"Transfer-Encoding: chunked\r\n"
		"Content-Length: 1234\r\n"
		"Connection: close\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_res_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_res_hdr_parse(&ctx, &hdr);
	assert(!r);
	assert(ctx.off == len);
	assert(ctx.state == GWNET_HTTP_HDR_PARSE_ST_DONE);
	assert(ctx.err == GWNET_HTTP_HDR_ERR_NONE);
	assert(hdr.code == 200);
	assert(!strcmp(hdr.reason, "OK"));
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(hdr.fields.nr == 6);
	ASSERT_HDRF(&hdr.fields.ff[0], "Server", "gwhttpd");
	ASSERT_HDRF(&hdr.fields.ff[1], "Date", "");
	ASSERT_HDRF(&hdr.fields.ff[2], "Content-Type", "text/html; charset=UTF-8");
	ASSERT_HDRF(&hdr.fields.ff[3], "Transfer-Encoding", "gzip, chunked");
	ASSERT_HDRF(&hdr.fields.ff[4], "Content-Length", "1234");
	ASSERT_HDRF(&hdr.fields.ff[5], "Connection", "close");
	gwnet_http_res_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_req_hdr_invalid_field_val_chars(void)
{
	static const char buf[] =
		"GET /index.html HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"Invalid-Header: \x01\x02\x03\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_req_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_req_hdr_parse(&ctx, &hdr);
	assert(r == -EINVAL);
	assert(ctx.err == GWNET_HTTP_HDR_ERR_MALFORMED);
	gwnet_http_req_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_res_hdr_invalid_field_val_chars(void)
{
	static const char buf[] =
		"HTTP/1.1 200 OK\r\n"
		"Server: gwhttpd\r\n"
		"Invalid-Header: \x01\x02\x03\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_res_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_res_hdr_parse(&ctx, &hdr);
	assert(r == -EINVAL);
	assert(ctx.err == GWNET_HTTP_HDR_ERR_MALFORMED);
	gwnet_http_res_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_req_hdr_invalid_field_key_chars(void)
{
	static const char buf[] =
		"GET /index.html HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"Invalid-Header\x01\x02\x03: value\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_req_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_req_hdr_parse(&ctx, &hdr);
	assert(r == -EINVAL);
	assert(ctx.err == GWNET_HTTP_HDR_ERR_MALFORMED);
	gwnet_http_req_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_res_hdr_invalid_field_key_chars(void)
{
	static const char buf[] =
		"HTTP/1.1 200 OK\r\n"
		"Server: gwhttpd\r\n"
		"Invalid-Header\x01\x02\x03: value\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_res_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_res_hdr_parse(&ctx, &hdr);
	assert(r == -EINVAL);
	assert(ctx.err == GWNET_HTTP_HDR_ERR_MALFORMED);
	gwnet_http_res_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_req_hdr_handle_short_recv(void)
{
	static const char buf[] =
		"GET /aa?a=b&c=d HTTP/1.1\r\n"			// 26
		"Host: example.com\r\n"				// 26 + 19 = 45
		"User-Agent: gwhttp\r\n"			// 45 + 20 = 65
		"Referer: http://example.com/test.html\r\n"	// 65 + 39 = 104
		"\r\n";						// 104 + 2 = 106
	const char *bp = buf;
	size_t len = sizeof(buf) - 1, i;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_req_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);

	i = 0;
	while (bp < &buf[len]) {
		i++;
		ctx.buf = bp;
		ctx.len = i;
		r = gwnet_http_req_hdr_parse(&ctx, &hdr);
		if (!ctx.off) {
			assert(r == -EAGAIN);
			continue;
		}

		bp += ctx.off;
		i -= ctx.off;
		ctx.off = 0;

		if (bp < &buf[len])
			assert(r == -EAGAIN);

		if (bp == &buf[len])
			assert(!r);

		if (bp >= &buf[26]) {
			assert(hdr.method == GWNET_HTTP_METHOD_GET);
			assert(!strcmp(hdr.uri, "/aa?a=b&c=d"));
			assert(!strcmp(hdr.qs, "a=b&c=d"));
			assert(hdr.version == GWNET_HTTP_VER_1_1);
		}

		if (bp >= &buf[45]) {
			assert(hdr.fields.nr >= 1);
			ASSERT_HDRF(&hdr.fields.ff[0], "Host", "example.com");
		}

		if (bp >= &buf[65]) {
			assert(hdr.fields.nr >= 2);
			ASSERT_HDRF(&hdr.fields.ff[1], "User-Agent", "gwhttp");
		}

		if (bp >= &buf[104]) {
			assert(hdr.fields.nr >= 3);
			ASSERT_HDRF(&hdr.fields.ff[2], "Referer", "http://example.com/test.html");
		}
	}

	gwnet_http_req_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_res_hdr_handle_short_recv(void)
{
	static const char buf[] =
		"HTTP/1.1 404 Not Found\r\n"			// 24
		"Server: gwhttpd\r\n"				// 24 + 17 = 41
		"Date: Mon, 01 Jan 1999 00:00:00 GMT\r\n"	// 41 + 37 = 78
		"Content-Type: text/html; charset=UTF-8\r\n"	// 78 + 40 = 118
		"Content-Length: 1234\r\n"			// 118 + 22 = 140
		"Connection: close\r\n"				// 140 + 19 = 159
		"\r\n";						// 159 + 2 = 161
	const char *bp = buf;
	size_t len = sizeof(buf) - 1, i;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_res_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);

	i = 0;
	while (bp < &buf[len]) {
		i++;
		ctx.buf = bp;
		ctx.len = i;
		r = gwnet_http_res_hdr_parse(&ctx, &hdr);
		if (!ctx.off) {
			assert(r == -EAGAIN);
			continue;
		}

		bp += ctx.off;
		i -= ctx.off;
		ctx.off = 0;

		if (bp < &buf[len])
			assert(r == -EAGAIN);

		if (bp == &buf[len])
			assert(!r);

		if (bp >= &buf[24]) {
			assert(hdr.code == 404);
			assert(!strcmp(hdr.reason, "Not Found"));
			assert(hdr.version == GWNET_HTTP_VER_1_1);
		}

		if (bp >= &buf[41]) {
			assert(hdr.fields.nr >= 1);
			ASSERT_HDRF(&hdr.fields.ff[0], "Server", "gwhttpd");
		}

		if (bp >= &buf[78]) {
			assert(hdr.fields.nr >= 2);
			ASSERT_HDRF(&hdr.fields.ff[1], "Date", "Mon, 01 Jan 1999 00:00:00 GMT");
		}

		if (bp >= &buf[118]) {
			assert(hdr.fields.nr >= 3);
			ASSERT_HDRF(&hdr.fields.ff[2], "Content-Type", "text/html; charset=UTF-8");
		}

		if (bp >= &buf[140]) {
			assert(hdr.fields.nr >= 4);
			ASSERT_HDRF(&hdr.fields.ff[3], "Content-Length", "1234");
		}

		if (bp >= &buf[159]) {
			assert(hdr.fields.nr >= 5);
			ASSERT_HDRF(&hdr.fields.ff[4], "Connection", "close");
		}
	}

	gwnet_http_res_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_req_hdr_oversized(void)
{
	static const char buf[] =
		"GET /index.html HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"User-Agent: gwhttp\r\n"
		"Referer: http://example.com/test.html\r\n"
		"X-Test-Header: AAAAAAAAAAAAAAAAAAAAAAAA\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_req_hdr hdr;
	size_t i;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	ctx.max_len = sizeof(buf) - 1;
	r = gwnet_http_req_hdr_parse(&ctx, &hdr);
	assert(!r);
	assert(ctx.err == GWNET_HTTP_HDR_ERR_NONE);
	assert(ctx.off == len);
	assert(!strcmp(hdr.uri, "/index.html"));
	assert(hdr.method == GWNET_HTTP_METHOD_GET);
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(!hdr.qs);
	assert(hdr.fields.nr == 4);
	ASSERT_HDRF(&hdr.fields.ff[0], "Host", "example.com");
	ASSERT_HDRF(&hdr.fields.ff[1], "User-Agent", "gwhttp");
	ASSERT_HDRF(&hdr.fields.ff[2], "Referer", "http://example.com/test.html");
	ASSERT_HDRF(&hdr.fields.ff[3], "X-Test-Header", "AAAAAAAAAAAAAAAAAAAAAAAA");
	gwnet_http_req_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);

	for (i = 1; i <= (sizeof(buf) - 2); i++) {
		r = gwnet_http_hdr_pctx_init(&ctx);
		assert(!r);
		ctx.buf = buf;
		ctx.len = len;
		ctx.max_len = i;
		r = gwnet_http_req_hdr_parse(&ctx, &hdr);
		assert(r == -E2BIG);
		assert(ctx.err == GWNET_HTTP_HDR_ERR_TOO_LONG);
		gwnet_http_req_hdr_free(&hdr);
		gwnet_http_hdr_pctx_free(&ctx);
	}

	PRTEST_OK();
}

static void test_res_hdr_oversized(void)
{
	static const char buf[] =
		"HTTP/1.1 200 OK\r\n"
		"Server: gwhttpd\r\n"
		"Date: Mon, 01 Jan 1999 00:00:00 GMT\r\n"
		"Content-Type: text/html; charset=UTF-8\r\n"
		"Content-Length: 1234\r\n"
		"X-Test-Header: AAAAAAAAAAAAAAAAAAAAAAAA\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_res_hdr hdr;
	size_t i;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	ctx.max_len = sizeof(buf) - 1;
	r = gwnet_http_res_hdr_parse(&ctx, &hdr);
	assert(!r);
	assert(ctx.err == GWNET_HTTP_HDR_ERR_NONE);
	assert(ctx.off == len);
	assert(hdr.code == 200);
	assert(!strcmp(hdr.reason, "OK"));
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(hdr.fields.nr == 5);
	ASSERT_HDRF(&hdr.fields.ff[0], "Server", "gwhttpd");
	ASSERT_HDRF(&hdr.fields.ff[1], "Date", "Mon, 01 Jan 1999 00:00:00 GMT");
	ASSERT_HDRF(&hdr.fields.ff[2], "Content-Type", "text/html; charset=UTF-8");
	ASSERT_HDRF(&hdr.fields.ff[3], "Content-Length", "1234");
	ASSERT_HDRF(&hdr.fields.ff[4], "X-Test-Header", "AAAAAAAAAAAAAAAAAAAAAAAA");
	gwnet_http_res_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);

	for (i = 1; i <= (sizeof(buf) - 2); i++) {
		r = gwnet_http_hdr_pctx_init(&ctx);
		assert(!r);
		ctx.buf = buf;
		ctx.len = len;
		ctx.max_len = i;
		r = gwnet_http_res_hdr_parse(&ctx, &hdr);
		assert(r == -E2BIG);
		assert(ctx.err == GWNET_HTTP_HDR_ERR_TOO_LONG);
		gwnet_http_res_hdr_free(&hdr);
		gwnet_http_hdr_pctx_free(&ctx);
	}

	PRTEST_OK();
}

static void test_body_chunked_simple(void)
{
	static const char buf[] =
		"5\r\n"
		"Hello\r\n"
		"0\r\n"
		"\r\n";
	const size_t len = sizeof(buf) - 1;
	struct gwnet_http_body_pctx ctx;
	int r;

	r = gwnet_http_body_pctx_init(&ctx);
	assert(!r);

	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_body_parse_chunked(&ctx, NULL, 0);
	assert(!r);
	assert(ctx.state == GWNET_HTTP_BODY_PARSE_ST_CHK_DONE);
	assert(ctx.tot_len == strlen("Hello"));
	assert(ctx.err == GWNET_HTTP_BODY_ERR_NONE);
	gwnet_http_body_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_body_chunked_multiple_chunks(void)
{
	static const char buf[] =
		"5\r\n"
		"Hello\r\n"
		"6\r\n"
		" World\r\n"
		"0\r\n"
		"\r\n";
	const size_t len = sizeof(buf) - 1;
	struct gwnet_http_body_pctx ctx;
	char dst[sizeof(buf)] = { 0 };
	size_t dst_len = sizeof(dst);
	int r;

	r = gwnet_http_body_pctx_init(&ctx);
	assert(!r);

	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_body_parse_chunked(&ctx, dst, dst_len);
	assert(!r);
	assert(ctx.state == GWNET_HTTP_BODY_PARSE_ST_CHK_DONE);
	assert(ctx.tot_len == strlen("Hello World"));
	assert(!strcmp(dst, "Hello World"));
	assert(ctx.err == GWNET_HTTP_BODY_ERR_NONE);
	gwnet_http_body_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_body_chunked_empty(void)
{
	static const char buf[] =
		"0\r\n"
		"\r\n";
	const size_t len = sizeof(buf) - 1;
	struct gwnet_http_body_pctx ctx;
	int r;

	r = gwnet_http_body_pctx_init(&ctx);
	assert(!r);

	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_body_parse_chunked(&ctx, NULL, 0);
	assert(!r);
	assert(ctx.state == GWNET_HTTP_BODY_PARSE_ST_CHK_DONE);
	assert(ctx.tot_len == 0);
	assert(ctx.err == GWNET_HTTP_BODY_ERR_NONE);
	gwnet_http_body_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_body_chunked_multiple_various_lengths(void)
{
	static const char buf[] =
		"a\r\n"
		"1234567890\r\n"
		"5\r\n"
		"Hello\r\n"
		"a\r\n"
		"ABCDEFGHIJ\r\n"
		"5\r\n"
		"World\r\n"
		"0\r\n"
		"\r\n";
	const size_t len = sizeof(buf) - 1;
	struct gwnet_http_body_pctx ctx;
	char dst[sizeof(buf)] = { 0 };
	size_t dst_len = sizeof(dst) - 1;
	int r;

	r = gwnet_http_body_pctx_init(&ctx);
	assert(!r);

	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_body_parse_chunked(&ctx, dst, dst_len);
	assert(!r);
	assert(ctx.state == GWNET_HTTP_BODY_PARSE_ST_CHK_DONE);
	assert(ctx.tot_len == strlen("1234567890HelloABCDEFGHIJWorld"));
	assert(!strcmp(dst, "1234567890HelloABCDEFGHIJWorld"));
	assert(ctx.err == GWNET_HTTP_BODY_ERR_NONE);
	gwnet_http_body_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_body_chunked_dst_buffer_too_small(void)
{
	static const char buf[] =
		"5\r\n"
		"Hello\r\n"
		"6\r\n"
		" World\r\n"
		"0\r\n"
		"\r\n";
	const size_t len = sizeof(buf) - 1;
	struct gwnet_http_body_pctx ctx;
	char dst[3] = { 0 };
	size_t dst_len = sizeof(dst) - 1;
	int r;

	r = gwnet_http_body_pctx_init(&ctx);
	assert(!r);

	ctx.buf = buf;
	ctx.len = len;

	r = gwnet_http_body_parse_chunked(&ctx, dst, dst_len);
	assert(r == -ENOBUFS);
	assert(ctx.state == GWNET_HTTP_BODY_PARSE_ST_CHK_DATA);
	assert(ctx.tot_len == 2);
	assert(ctx.err == GWNET_HTTP_BODY_ERR_DST_TOO_SMALL);
	assert(!strcmp(dst, "He"));

	r = gwnet_http_body_parse_chunked(&ctx, dst, dst_len);
	assert(r == -ENOBUFS);
	assert(ctx.state == GWNET_HTTP_BODY_PARSE_ST_CHK_DATA);
	assert(ctx.tot_len == 4);
	assert(ctx.err == GWNET_HTTP_BODY_ERR_DST_TOO_SMALL);
	assert(!strcmp(dst, "ll"));

	r = gwnet_http_body_parse_chunked(&ctx, dst, dst_len);
	assert(r == -ENOBUFS);
	assert(ctx.state == GWNET_HTTP_BODY_PARSE_ST_CHK_DATA);
	assert(ctx.tot_len == 6);
	assert(ctx.err == GWNET_HTTP_BODY_ERR_DST_TOO_SMALL);
	assert(!strcmp(dst, "o "));

	r = gwnet_http_body_parse_chunked(&ctx, dst, dst_len);
	assert(r == -ENOBUFS);
	assert(ctx.state == GWNET_HTTP_BODY_PARSE_ST_CHK_DATA);
	assert(ctx.tot_len == 8);
	assert(ctx.err == GWNET_HTTP_BODY_ERR_DST_TOO_SMALL);
	assert(!strcmp(dst, "Wo"));

	r = gwnet_http_body_parse_chunked(&ctx, dst, dst_len);
	assert(r == -ENOBUFS);
	assert(ctx.state == GWNET_HTTP_BODY_PARSE_ST_CHK_DATA);
	assert(ctx.tot_len == 10);
	assert(ctx.err == GWNET_HTTP_BODY_ERR_DST_TOO_SMALL);
	assert(!strcmp(dst, "rl"));

	r = gwnet_http_body_parse_chunked(&ctx, dst, dst_len);
	assert(!r);
	assert(ctx.state == GWNET_HTTP_BODY_PARSE_ST_CHK_DONE);
	assert(ctx.tot_len == 11);
	assert(ctx.err == GWNET_HTTP_BODY_ERR_NONE);
	assert(dst[0] == 'd');

	gwnet_http_body_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_body_chunked_short_recv(void)
{
	static const char src[] =
		"5\r\n"		// 3
		"Hello\r\n"	// 3 + 7 = 10
		"6\r\n"		// 10 + 3 = 13
		" World\r\n"	// 13 + 8 = 21
		"0\r\n"		// 21 + 3 = 24
		"\r\n";		// 24 + 2 = 26
	static const size_t src_len = sizeof(src) - 1;
	const char *src_p = src;
	char dst[sizeof(src)] = { 0 };
	char *dst_p = dst;
	size_t dst_len = sizeof(dst);
	size_t dst_rem_len = dst_len;
	struct gwnet_http_body_pctx ctx;
	size_t i;
	int r;

	r = gwnet_http_body_pctx_init(&ctx);
	assert(!r);

	i = 0;
	while (src_p < &src[src_len]) {
		ctx.buf = src_p;
		ctx.len = i++;
		r = gwnet_http_body_parse_chunked(&ctx, dst_p, dst_rem_len);
		if (!ctx.off) {
			assert(r == -EAGAIN);
			continue;
		}

		src_p += ctx.off;
		i -= ctx.off;
		ctx.off = 0;
		dst_rem_len = dst_len - ctx.tot_len;
		dst_p = &dst[ctx.tot_len];

		if (src_p < &src[src_len])
			assert(r == -EAGAIN);

		if (src_p == &src[src_len])
			assert(!r);

		if (src_p >= &src[10]) {
			assert(strlen(dst) >= 5);
			assert(!strncmp(dst, "Hello", 5));
			assert(ctx.tot_len >= 5);
		}

		if (src_p >= &src[21]) {
			assert(strlen(dst) >= 11);
			assert(!strncmp(dst, "Hello World", 11));
			assert(ctx.tot_len >= 11);
		}

		if (src_p >= &src[24]) {
			assert(strlen(dst) >= 11);
			assert(!strncmp(dst, "Hello World", 11));
			assert(ctx.tot_len == 11);
		}
	}

	assert(ctx.state == GWNET_HTTP_BODY_PARSE_ST_CHK_DONE);
	gwnet_http_body_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_body_chunked_oversized(void)
{
	static const char buf[] =
		"5\r\n"
		"Hello\r\n"
		"6\r\n"
		" World\r\n"
		"0\r\n"
		"\r\n";
	const size_t len = sizeof(buf) - 1;
	struct gwnet_http_body_pctx ctx;
	char dst[sizeof(buf)] = { 0 };
	size_t dst_len = sizeof(dst) - 1;
	size_t i;
	int r;

	r = gwnet_http_body_pctx_init(&ctx);
	assert(!r);

	ctx.buf = buf;
	ctx.len = len;
	ctx.max_len = sizeof(buf) - 1;
	r = gwnet_http_body_parse_chunked(&ctx, dst, dst_len);
	assert(!r);
	assert(ctx.state == GWNET_HTTP_BODY_PARSE_ST_CHK_DONE);
	assert(ctx.tot_len == strlen("Hello World"));
	assert(!strcmp(dst, "Hello World"));
	assert(ctx.err == GWNET_HTTP_BODY_ERR_NONE);
	gwnet_http_body_pctx_free(&ctx);

	for (i = 1; i <= (sizeof(buf) - 2); i++) {
		r = gwnet_http_body_pctx_init(&ctx);
		assert(!r);
		ctx.buf = buf;
		ctx.len = len;
		ctx.max_len = i;
		r = gwnet_http_body_parse_chunked(&ctx, dst, dst_len);
		assert(r == -E2BIG);
		assert(ctx.err == GWNET_HTTP_BODY_ERR_TOO_LONG);
		gwnet_http_body_pctx_free(&ctx);
	}

	PRTEST_OK();
}

void gwnet_http_run_tests(void)
{
	size_t i;
	for (i = 0; i < 5000; i++) {
		test_req_hdr_simple();
		test_req_hdr_absolute_form();
		test_req_hdr_bare_target_rejected();
		test_res_hdr_simple();
		test_req_hdr_query_string();
		test_req_hdr_query_string_empty();
		test_req_hdr_query_string_multi_qmark();
		test_req_hdr_invalid_req_line_sp();
		test_req_hdr_invalid_res_status_line_sp();
		test_req_hdr_invalid_uri_chars();
		test_req_hdr_invalid_uri_chars2();
		test_req_hdr_invalid_method();
		test_req_hdr_invalid_version();
		test_res_hdr_invalid_version();
		test_req_hdr_trim_whitespaces();
		test_res_hdr_trim_whitespaces();
		test_req_hdr_invalid_duplicate_fields();
		test_res_hdr_invalid_duplicate_fields();
		test_req_hdr_invalid_space_before_colon();
		test_res_hdr_invalid_space_before_colon();
		test_req_hdr_duplicate_fields_merged_into_comma();
		test_res_hdr_duplicate_fields_merged_into_comma();
		test_req_hdr_duplicate_fields_empty_value();
		test_res_hdr_duplicate_fields_empty_value();
		test_req_hdr_invalid_field_val_chars();
		test_res_hdr_invalid_field_val_chars();
		test_req_hdr_invalid_field_key_chars();
		test_res_hdr_invalid_field_key_chars();
		test_req_hdr_handle_short_recv();
		test_res_hdr_handle_short_recv();
		test_req_hdr_oversized();
		test_res_hdr_oversized();
		test_body_chunked_simple();
		test_body_chunked_multiple_chunks();
		test_body_chunked_empty();
		test_body_chunked_multiple_various_lengths();
		test_body_chunked_dst_buffer_too_small();
		test_body_chunked_short_recv();
		test_body_chunked_oversized();
	}
	printf("All tests passed!\n");
}

#ifdef GWNET_HTTP1_RUN_TESTS
int main(void)
{
	gwnet_http_run_tests();
	return 0;
}
#endif /* #ifdef GWNET_HTTP1_RUN_TESTS */
#endif /* #ifdef GWNET_HTTP1_TESTS */
