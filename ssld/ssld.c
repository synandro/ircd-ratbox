/*
 *  ssld.c: The ircd-ratbox ssl/zlib helper daemon thingy
 *  Copyright (C) 2007 Aaron Sethman <androsyn@ratbox.org>
 *  Copyright (C) 2007-2026 ircd-ratbox development team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 *  USA
 */


#include "stdinc.h"

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

#define MAXPASSFD 4
#ifndef READBUF_SIZE
#define READBUF_SIZE 16384
#endif

static void setup_signals(void);
static pid_t ppid;

static inline uint32_t buf_to_uint32(void *);
static inline void uint32_to_buf(void *buf, uint32_t x);


typedef struct _mod_ctl_buf
{
	rb_dlink_node node;
	uint8_t *buf;
	size_t buflen;
	rb_fde_t *F[MAXPASSFD];
	int nfds;
} mod_ctl_buf_t;

typedef struct _mod_ctl
{
	rb_dlink_node node;
	int cli_count;
	rb_fde_t *F;
	rb_fde_t *F_pipe;
	rb_dlink_list readq;
	rb_dlink_list writeq;
} mod_ctl_t;



#ifdef HAVE_ZLIB
typedef struct _zlib_stream
{
	z_stream instream;
	z_stream outstream;
} zlib_stream_t;
#endif

typedef struct _conn
{
	rb_dlink_node node;
	mod_ctl_t *ctl;
	rb_rawbuf_head_t *modbuf_out;
	rb_rawbuf_head_t *plainbuf_out;
	rb_fde_t *mod_fd;
	rb_fde_t *plain_fd;
	void *stream;
	uint64_t mod_out;
	uint64_t mod_in;
	uint64_t plain_in;
	uint64_t plain_out;
	uint32_t id;
	uint8_t flags;
} conn_t;

#define FLAG_SSL	0x01
#define FLAG_ZIP	0x02
#define FLAG_CORK	0x04
#define FLAG_DEAD	0x08
#define FLAG_SSL_W_WANTS_R 0x10	/* output needs to wait until input possible */
#define FLAG_SSL_R_WANTS_W 0x20	/* input needs to wait until output possible */
#define FLAG_ZIPSSL	0x40

#define IsSSL(x) ((x)->flags & FLAG_SSL)
#define IsZip(x) ((x)->flags & FLAG_ZIP)
#define IsCork(x) ((x)->flags & FLAG_CORK)
#define IsDead(x) ((x)->flags & FLAG_DEAD)
#define IsSSLWWantsR(x) ((x)->flags & FLAG_SSL_W_WANTS_R)
#define IsSSLRWantsW(x) ((x)->flags & FLAG_SSL_R_WANTS_W)
#define IsZipSSL(x)	((x)->flags & FLAG_ZIPSSL)

#define SetSSL(x) ((x)->flags |= FLAG_SSL)
#define SetZip(x) ((x)->flags |= FLAG_ZIP)
#define SetCork(x) ((x)->flags |= FLAG_CORK)
#define SetDead(x) ((x)->flags |= FLAG_DEAD)
#define SetSSLWWantsR(x) ((x)->flags |= FLAG_SSL_W_WANTS_R)
#define SetSSLRWantsW(x) ((x)->flags |= FLAG_SSL_R_WANTS_W)
#define SetZipSSL(x)	((x)->flags |= FLAG_ZIPSSL)

#define ClearSSL(x) ((x)->flags &= ~FLAG_SSL)
#define ClearZip(x) ((x)->flags &= ~FLAG_ZIP)
#define ClearCork(x) ((x)->flags &= ~FLAG_CORK)
#define ClearDead(x) ((x)->flags &= ~FLAG_DEAD)
#define ClearSSLWWantsR(x) ((x)->flags &= ~FLAG_SSL_W_WANTS_R)
#define ClearSSLRWantsW(x) ((x)->flags &= ~FLAG_SSL_R_WANTS_W)
#define ClearZipSSL(x)	((x)->flags &= ~FLAG_ZIPSSL)

#define NO_WAIT 0x0
#define WAIT_PLAIN 0x1

#define HASH_WALK_SAFE(i, max, ptr, next, table) for(i = 0; i < max; i++) { RB_DLINK_FOREACH_SAFE(ptr, next, table[i].head)
#define HASH_WALK_END }
#define CONN_HASH_SIZE 2000
#define connid_hash(x)	(&connid_hash_table[(x % CONN_HASH_SIZE)])


static rb_ssl_ctx *ssl_server_ctx;
static rb_ssl_ctx *ssl_client_ctx;

static rb_dlink_list connid_hash_table[CONN_HASH_SIZE];
static rb_dlink_list dead_list;

static void conn_mod_read_cb(rb_fde_t *fd, void *data);
static void conn_mod_write_sendq(rb_fde_t *, void *data);
static void conn_plain_write_sendq(rb_fde_t *, void *data);
static void mod_write_ctl(rb_fde_t *, void *data);
static void conn_plain_read_cb(rb_fde_t *fd, void *data);
static void conn_plain_read_shutdown_cb(rb_fde_t *fd, void *data);
static void mod_cmd_write_queue(mod_ctl_t * ctl, const void *data, size_t len);
static const char *remote_closed = "Remote host closed the connection";
static bool ssl_ok = false;
#ifdef HAVE_ZLIB
static bool zlib_ok = true;
#else
static bool zlib_ok = false;
#endif

static inline uint32_t
buf_to_uint32(void *buf)
{
	uint32_t x;
	memcpy(&x, buf, sizeof(x));
	return x;
}

static inline void
uint32_to_buf(void *buf, uint32_t x)
{
	memcpy(buf, &x, sizeof(x));
	return;
}

#ifdef HAVE_ZLIB
static void *
ssld_alloc(void *unused, unsigned int count, unsigned int size)
{
	return rb_malloc(count * size);
}

static void
ssld_free(void *unused, void *ptr)
{
	rb_free(ptr);
}
#endif

static conn_t *
conn_find_by_id(uint32_t id)
{
	rb_dlink_node *ptr;
	conn_t *conn;

	RB_DLINK_FOREACH(ptr, (connid_hash(id))->head)
	{
		conn = (conn_t *)ptr->data;
		if(conn->id == id && !IsDead(conn))
			return conn;
	}
	return NULL;
}

static void
conn_add_id_hash(conn_t * conn, uint32_t id)
{
	conn->id = id;
	rb_dlinkAdd(conn, &conn->node, connid_hash(id));
}

static void
free_conn(conn_t * conn)
{
	rb_free_rawbuffer(conn->modbuf_out);
	rb_free_rawbuffer(conn->plainbuf_out);
#ifdef HAVE_ZLIB
	if(IsZip(conn))
	{
		zlib_stream_t *stream = conn->stream;
		inflateEnd(&stream->instream);
		deflateEnd(&stream->outstream);
		rb_free(stream);
	}
#endif
	rb_free(conn);
}

static void
clean_dead_conns(void *unused)
{
	conn_t *conn;
	rb_dlink_node *ptr, *next;
	RB_DLINK_FOREACH_SAFE(ptr, next, dead_list.head)
	{
		conn = ptr->data;
		free_conn(conn);
	}
	dead_list.tail = dead_list.head = NULL;
}
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#if (((__GNUC__ * 100) + __GNUC_MINOR__) >= 406)
#pragma GCC diagnostic push
#endif
static void
close_conn(conn_t * conn, int wait_plain, const char *fmt, ...)
{
	va_list ap;
	char reason[128];	/* must always be under 250 bytes */
	char buf[256];
	size_t len;
	if(IsDead(conn))
		return;

	rb_rawbuf_flush(conn->modbuf_out, conn->mod_fd);
	rb_rawbuf_flush(conn->plainbuf_out, conn->plain_fd);
	rb_close(conn->mod_fd);
	SetDead(conn);

	if(conn->id > 0 && !IsZipSSL(conn))
		rb_dlinkDelete(&conn->node, connid_hash(conn->id));

	if(!wait_plain || fmt == NULL)
	{
		rb_close(conn->plain_fd);
		rb_dlinkAdd(conn, &conn->node, &dead_list);
		return;
	}
	rb_setselect(conn->plain_fd, RB_SELECT_READ, conn_plain_read_shutdown_cb, conn);
	rb_setselect(conn->plain_fd, RB_SELECT_WRITE, NULL, NULL);
	va_start(ap, fmt);
	vsnprintf(reason, sizeof(reason), fmt, ap);
	va_end(ap);

	buf[0] = 'D';
	uint32_to_buf(&buf[1], conn->id);
	strcpy(&buf[5], reason);
	len = (strlen(reason) + 1) + 5;
	mod_cmd_write_queue(conn->ctl, buf, len);
}
#if (((__GNUC__ * 100) + __GNUC_MINOR__) >= 406)
#pragma GCC diagnostic pop
#endif

static conn_t *
make_conn(mod_ctl_t * ctl, rb_fde_t *mod_fd, rb_fde_t *plain_fd)
{
	conn_t *conn; 

	/* we need all three, not just one..bail if any are NULL */
	if(ctl == NULL || mod_fd == NULL || plain_fd == NULL)
		return NULL;
	
	conn = rb_malloc(sizeof(conn_t));
	conn->ctl = ctl;
	conn->modbuf_out = rb_new_rawbuffer();
	conn->plainbuf_out = rb_new_rawbuffer();
	conn->mod_fd = mod_fd;
	conn->plain_fd = plain_fd;
	conn->id = -1;
	conn->stream = NULL;
	rb_set_nb(mod_fd);
	rb_set_nb(plain_fd);
	return conn;
}

static void
conn_mod_write_sendq(rb_fde_t *fd, void *data)
{
	conn_t *conn = data;
	const char *err;
	ssize_t retlen;
	if(IsDead(conn))
		return;

	if(IsSSLWWantsR(conn))
	{
		ClearSSLWWantsR(conn);
		conn_mod_read_cb(conn->mod_fd, conn);
		if(IsDead(conn))
			return;
	}

	while((retlen = rb_rawbuf_flush(conn->modbuf_out, fd)) > 0)
		conn->mod_out += retlen;
		
	if(retlen == 0 || (retlen < 0 && !rb_ignore_errno(errno)))
	{
		if(retlen == 0)
			close_conn(conn, WAIT_PLAIN, "%s", remote_closed);
		if(IsSSL(conn) && retlen == RB_RW_SSL_ERROR)
			err = rb_ssl_get_strerror(conn->mod_fd);
		else
			err = strerror(errno);
		close_conn(conn, WAIT_PLAIN, "Write error: %s", err);
		return;
	}

	if(rb_rawbuf_length(conn->modbuf_out) > 0)
	{
		if(retlen != RB_RW_SSL_NEED_READ)
			rb_setselect(conn->mod_fd, RB_SELECT_WRITE, conn_mod_write_sendq, conn);
		else
		{
			rb_setselect(conn->mod_fd, RB_SELECT_READ, conn_mod_write_sendq, conn);
			rb_setselect(conn->mod_fd, RB_SELECT_WRITE, NULL, NULL);
			SetSSLWWantsR(conn);
		}
	}
	else
		rb_setselect(conn->mod_fd, RB_SELECT_WRITE, NULL, NULL);

	if(IsCork(conn) && rb_rawbuf_length(conn->modbuf_out) == 0)
	{
		ClearCork(conn);
		conn_plain_read_cb(conn->plain_fd, conn);
	}
	

}

static void
conn_mod_write(conn_t * conn, void *data, size_t len)
{
	if(IsDead(conn))	/* no point in queueing to a dead man */
		return;
	rb_rawbuf_append(conn->modbuf_out, data, len);
}

static void
conn_plain_write(conn_t * conn, void *data, size_t len)
{
	if(IsDead(conn))	/* again no point in queueing to dead men */
		return;
	rb_rawbuf_append(conn->plainbuf_out, data, len);
}

static void
mod_cmd_write_queue(mod_ctl_t * ctl, const void *data, size_t len)
{
	mod_ctl_buf_t *ctl_buf;
	ctl_buf = rb_malloc(sizeof(mod_ctl_buf_t));
	ctl_buf->buf = rb_malloc(len);
	ctl_buf->buflen = len;
	memcpy(ctl_buf->buf, data, len);
	ctl_buf->nfds = 0;
	rb_dlinkAddTail(ctl_buf, &ctl_buf->node, &ctl->writeq);
	mod_write_ctl(ctl->F, ctl);
}

#ifdef HAVE_ZLIB
static void
common_zlib_deflate(conn_t * conn, void *buf, size_t len)
{
	char outbuf[READBUF_SIZE];
	int ret;
	ptrdiff_t have;
	z_stream *outstream = &((zlib_stream_t *) conn->stream)->outstream;
	outstream->next_in = buf;
	outstream->avail_in = (unsigned int)len;
	outstream->next_out = (Bytef *) outbuf;
	outstream->avail_out = sizeof(outbuf);

	ret = deflate(outstream, Z_SYNC_FLUSH);
	if(ret != Z_OK)
	{
		/* deflate error */
		close_conn(conn, WAIT_PLAIN, "Deflate failed: %s", zError(ret));
		return;
	}
	if(outstream->avail_out == 0)
	{
		/* avail_out empty */
		close_conn(conn, WAIT_PLAIN, "error compressing data, avail_out == 0");
		return;
	}
	if(outstream->avail_in != 0)
	{
		/* avail_in isn't empty... */
		close_conn(conn, WAIT_PLAIN, "error compressing data, avail_in != 0");
		return;
	}
	have = sizeof(outbuf) - outstream->avail_out;
	conn_mod_write(conn, outbuf, have);
}

static void
common_zlib_inflate(conn_t * conn, void *buf, size_t len)
{
	char outbuf[READBUF_SIZE];
	int ret;
	ptrdiff_t have = 0;
	((zlib_stream_t *) conn->stream)->instream.next_in = buf;
	((zlib_stream_t *) conn->stream)->instream.avail_in = (unsigned int)len;
	((zlib_stream_t *) conn->stream)->instream.next_out = (Bytef *) outbuf;
	((zlib_stream_t *) conn->stream)->instream.avail_out = sizeof(outbuf);

	while(((zlib_stream_t *) conn->stream)->instream.avail_in)
	{
		ret = inflate(&((zlib_stream_t *) conn->stream)->instream, Z_NO_FLUSH);
		if(ret != Z_OK)
		{
			if(!strncmp("ERROR ", buf, 6))
			{
				close_conn(conn, WAIT_PLAIN, "Received uncompressed ERROR");
				return;
			}
			close_conn(conn, WAIT_PLAIN, "Inflate failed: %s", zError(ret));
			return;
		}
		have = sizeof(outbuf) - ((zlib_stream_t *) conn->stream)->instream.avail_out;

		if(((zlib_stream_t *) conn->stream)->instream.avail_in)
		{
			conn_plain_write(conn, outbuf, have);
			have = 0;
			((zlib_stream_t *) conn->stream)->instream.next_out = (Bytef *) outbuf;
			((zlib_stream_t *) conn->stream)->instream.avail_out = sizeof(outbuf);
		}
	}
	if(have == 0)
		return;

	conn_plain_write(conn, outbuf, have);
}
#endif

static int
plain_check_cork(conn_t * conn)
{
	if(rb_rawbuf_length(conn->modbuf_out) >= 4096)
	{
		/* if we have over 4k pending outbound, don't read until 
		 * we've cleared the queue */
		SetCork(conn);
		rb_setselect(conn->plain_fd, RB_SELECT_READ, NULL, NULL);
		/* try to write */
		conn_mod_write_sendq(conn->mod_fd, conn);
		return 1;
	}
	return 0;
}


static void
conn_plain_read_cb(rb_fde_t *fd, void *data)
{
	char inbuf[READBUF_SIZE];
	conn_t *conn = data;
	ssize_t length = 0;
	if(conn == NULL)
		return;

	if(IsDead(conn))
		return;

	if(plain_check_cork(conn))
		return;

	while(1)
	{
		if(IsDead(conn))
			return;

		length = rb_read(conn->plain_fd, inbuf, sizeof(inbuf));

		if(length == 0 || (length < 0 && !rb_ignore_errno(errno)))
		{
			close_conn(conn, NO_WAIT, NULL);
			return;
		}

		if(length < 0)
		{
			rb_setselect(conn->plain_fd, RB_SELECT_READ, conn_plain_read_cb, conn);
			conn_mod_write_sendq(conn->mod_fd, conn);
			return;
		}
		conn->plain_in += length;
#ifdef HAVE_ZLIB
		if(IsZip(conn))
			common_zlib_deflate(conn, inbuf, length);
		else
#endif
			conn_mod_write(conn, inbuf, length);
		if(IsDead(conn))
			return;
		if(plain_check_cork(conn))
			return;
	}
}

static void
conn_plain_read_shutdown_cb(rb_fde_t *fd, void *data)
{
	char inbuf[READBUF_SIZE];
	conn_t *conn = data;
	ssize_t length = 0;

	if(conn == NULL)
		return;

	while(1)
	{
		length = rb_read(conn->plain_fd, inbuf, sizeof(inbuf));

		if(length == 0 || (length < 0 && !rb_ignore_errno(errno)))
		{
			rb_close(conn->plain_fd);
			rb_dlinkAdd(conn, &conn->node, &dead_list);
			return;
		}

		if(length < 0)
		{
			rb_setselect(conn->plain_fd, RB_SELECT_READ, conn_plain_read_shutdown_cb, conn);
			return;
		}
	}
}

static void
conn_mod_read_cb(rb_fde_t *fd, void *data)
{
	char inbuf[READBUF_SIZE];
	conn_t *conn = data;
	const char *err;
	ssize_t length;
	if(conn == NULL)
		return;
	if(IsDead(conn))
		return;

	if(IsSSLRWantsW(conn))
	{
		ClearSSLRWantsW(conn);
		conn_mod_write_sendq(conn->mod_fd, conn);
		if(IsDead(conn))
			return;
	}

	while(1)
	{
		if(IsDead(conn))
			return;

		length = rb_read(conn->mod_fd, inbuf, sizeof(inbuf));

		if(length == 0 || (length < 0 && !rb_ignore_errno(errno)))
		{
			if(length == 0)
			{
				close_conn(conn, WAIT_PLAIN, "%s", remote_closed);
				return;
			}

			if(IsSSL(conn) && length == RB_RW_SSL_ERROR)
				err = rb_ssl_get_strerror(conn->mod_fd);
			else
				err = strerror(errno);
			close_conn(conn, WAIT_PLAIN, "Read error: %s", err);
			return;
		}


		/* renegotiation is disabled in libratbox unconditionally, so this code isn't needed anymore  */
#if 0
		if((rb_ssl_handshake_count(conn->mod_fd) > 1) && (rb_current_time() - rb_ssl_last_handshake(conn->mod_fd)) < 1200)
		{
			close_conn(conn, WAIT_PLAIN, "TLS error: Enjoying shaking my hand off?");
			return;	
		}
#endif

		if(length < 0)
		{
		
			if(length != RB_RW_SSL_NEED_WRITE)
				rb_setselect(conn->mod_fd, RB_SELECT_READ, conn_mod_read_cb, conn);
			else
			{
				rb_setselect(conn->mod_fd, RB_SELECT_READ, NULL, NULL);
				rb_setselect(conn->mod_fd, RB_SELECT_WRITE, conn_mod_read_cb, conn);
				SetSSLRWantsW(conn);
			}
			conn_plain_write_sendq(conn->plain_fd, conn);
			return;
		}
		conn->mod_in += length;
#ifdef HAVE_ZLIB
		if(IsZip(conn))
			common_zlib_inflate(conn, inbuf, length);
		else
#endif
			conn_plain_write(conn, inbuf, length);
	}
}

static void
conn_plain_write_sendq(rb_fde_t *fd, void *data)
{
	conn_t *conn = data;
	ssize_t retlen;

	if(IsDead(conn))
		return;

	while((retlen = rb_rawbuf_flush(conn->plainbuf_out, fd)) > 0)
	{
		conn->plain_out += retlen;
	}
	if(retlen == 0 || (retlen < 0 && !rb_ignore_errno(errno)))
	{
		close_conn(data, NO_WAIT, NULL);
		return;
	}

	if(rb_rawbuf_length(conn->plainbuf_out) > 0)
		rb_setselect(conn->plain_fd, RB_SELECT_WRITE, conn_plain_write_sendq, conn);
	else
		rb_setselect(conn->plain_fd, RB_SELECT_WRITE, NULL, NULL);
}

static int
maxconn(void)
{
#if defined(RLIMIT_NOFILE) && defined(HAVE_SYS_RESOURCE_H)
	struct rlimit limit;

	if(!getrlimit(RLIMIT_NOFILE, &limit))
	{
		return (int)limit.rlim_cur;
	}
#endif /* RLIMIT_FD_MAX */
	return MAXCONNECTIONS;
}

static void
ssl_send_cipher(conn_t *conn)
{
	size_t len;
	char buf[512];
	char cstring[256];
	const char *p;
	if(!IsSSL(conn))
		return;

	p = rb_ssl_get_cipher(conn->mod_fd);

	if(p == NULL)
		return;
	
	rb_strlcpy(cstring, p, sizeof(cstring));		

	buf[0] = 'C';
	uint32_to_buf(&buf[1], conn->id);
	strcpy(&buf[5], cstring);
	len = (strlen(cstring) + 1) + 5;
	mod_cmd_write_queue(conn->ctl, buf, len);
}

static void
ssl_send_certfp(conn_t *conn)
{
	uint8_t buf[5 + RB_SSL_CERTFP_LEN];
	if(!rb_ssl_get_certfp(conn->mod_fd, &buf[5]))
		return;
	buf[0] = 'F';
	uint32_to_buf(&buf[1], conn->id);
	mod_cmd_write_queue(conn->ctl, buf, sizeof(buf));
}


static void
ssl_process_accept_cb(rb_fde_t *F, int status, struct sockaddr *addr, rb_socklen_t len, void *data)
{
	conn_t *conn = data;
	if(status == RB_OK)
	{
		rb_ssl_clear_handshake_count(conn->mod_fd);
		conn_mod_read_cb(conn->mod_fd, conn);
		conn_plain_read_cb(conn->plain_fd, conn);
		ssl_send_cipher(conn);
		ssl_send_certfp(conn);
		return;
	}
	/* ircd doesn't care about the reason for this */
	close_conn(conn, NO_WAIT, NULL);
	return;
}

static void
ssl_process_connect_cb(rb_fde_t *F, int status, void *data)
{
	conn_t *conn = data;
	if(status == RB_OK)
	{
		rb_ssl_clear_handshake_count(conn->mod_fd);
		conn_mod_read_cb(conn->mod_fd, conn);
		conn_plain_read_cb(conn->plain_fd, conn);
		ssl_send_cipher(conn);
		ssl_send_certfp(conn);

	}
	else if(status == RB_ERR_TIMEOUT)
		close_conn(conn, WAIT_PLAIN, "SSL handshake timed out");
	else if(status == RB_ERROR_SSL)
		close_conn(conn, WAIT_PLAIN, "%s", rb_ssl_get_strerror(conn->mod_fd));
	else
		close_conn(conn, WAIT_PLAIN, "SSL handshake failed");
}


static void
cleanup_bad_message(mod_ctl_t * ctl, mod_ctl_buf_t * ctlb)
{
	int i;

	/* XXX should log this somehow */
	for (i = 0; i < ctlb->nfds; i++)
		rb_close(ctlb->F[i]);
}

static void
ssl_process_accept(mod_ctl_t * ctl, mod_ctl_buf_t * ctlb)
{
	conn_t *conn;
	uint32_t id;

	conn = make_conn(ctl, ctlb->F[0], ctlb->F[1]);
	if(conn == NULL)
	{
		/* give up.. */
		rb_close(ctlb->F[0]);
		rb_close(ctlb->F[1]);
		return;
	}
	id = buf_to_uint32(&ctlb->buf[1]);

	conn_add_id_hash(conn, id);
	SetSSL(conn);

	rb_ssl_attach_ctx_to_fde(ssl_server_ctx, conn->mod_fd);

	if(rb_get_type(conn->mod_fd) & RB_FD_UNKNOWN)
		rb_set_type(conn->mod_fd, RB_FD_SOCKET);

	if(rb_get_type(conn->plain_fd) & RB_FD_UNKNOWN)
		rb_set_type(conn->plain_fd, RB_FD_SOCKET);

	rb_ssl_start_accepted(ctlb->F[0], ssl_process_accept_cb, conn, 10);
}

static void
ssl_process_connect(mod_ctl_t * ctl, mod_ctl_buf_t * ctlb)
{
	conn_t *conn;
	uint32_t id;
	conn = make_conn(ctl, ctlb->F[0], ctlb->F[1]);

	if(conn == NULL)
	{
		/* give up.. */
		rb_close(ctlb->F[0]);
		rb_close(ctlb->F[1]);
		return;
	}

	id = buf_to_uint32(&ctlb->buf[1]);
	conn_add_id_hash(conn, id);
	
	SetSSL(conn);

	rb_ssl_attach_ctx_to_fde(ssl_client_ctx, conn->mod_fd);
	if(rb_get_type(conn->mod_fd) & RB_FD_UNKNOWN)
		rb_set_type(conn->mod_fd, RB_FD_SOCKET);

	if(rb_get_type(conn->plain_fd) & RB_FD_UNKNOWN)
		rb_set_type(conn->plain_fd, RB_FD_SOCKET);

	rb_ssl_start_connected(ctlb->F[0], ssl_process_connect_cb, conn, 10);
}


static void
process_stats(mod_ctl_t * ctl, mod_ctl_buf_t * ctlb)
{
	char outstat[512];
	conn_t *conn;
	const uint8_t *odata;
	uint32_t id;

	id = buf_to_uint32(&ctlb->buf[1]);

	odata = &ctlb->buf[5];
	conn = conn_find_by_id(id);

	if(conn == NULL)
		return;

	snprintf(outstat, sizeof(outstat), "S %s %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64, odata,
		    conn->plain_out, conn->mod_in, conn->plain_in, conn->mod_out);
	conn->plain_out = 0;
	conn->plain_in = 0;
	conn->mod_in = 0;
	conn->mod_out = 0;
	mod_cmd_write_queue(ctl, outstat, strlen(outstat) + 1);	/* +1 is so we send the \0 as well */
}


#ifdef HAVE_ZLIB

static void
zlib_process(mod_ctl_t * ctl, mod_ctl_buf_t * ctlb)
{
	int8_t level;
	size_t recvqlen;
	size_t hdr = (sizeof(uint8_t) * 2) + sizeof(uint32_t);
	void *recvq_start;
	z_stream *instream, *outstream;
	conn_t *conn;
	uint32_t id;

	conn = make_conn(ctl, ctlb->F[0], ctlb->F[1]);

	if(conn == NULL)
	{
		rb_close(ctlb->F[0]);
		rb_close(ctlb->F[1]);
		return;
	}

	if(rb_get_type(conn->mod_fd) == RB_FD_UNKNOWN)
		rb_set_type(conn->mod_fd, RB_FD_SOCKET);

	if(rb_get_type(conn->plain_fd) == RB_FD_UNKNOWN)
		rb_set_type(conn->plain_fd, RB_FD_SOCKET);

	id = buf_to_uint32(&ctlb->buf[1]);
	conn_add_id_hash(conn, id);

	level = (int8_t)ctlb->buf[5];

	recvqlen = ctlb->buflen - hdr;
	recvq_start = &ctlb->buf[6];

	SetZip(conn);
	conn->stream = rb_malloc(sizeof(zlib_stream_t));
	instream = &((zlib_stream_t *) conn->stream)->instream;
	outstream = &((zlib_stream_t *) conn->stream)->outstream;

	instream->total_in = 0;
	instream->total_out = 0;
	instream->zalloc = (alloc_func) ssld_alloc;
	instream->zfree = (free_func) ssld_free;
	instream->data_type = Z_ASCII;
	inflateInit(&((zlib_stream_t *) conn->stream)->instream);

	outstream->total_in = 0;
	outstream->total_out = 0;
	outstream->zalloc = (alloc_func) ssld_alloc;
	outstream->zfree = (free_func) ssld_free;
	outstream->data_type = Z_ASCII;

	if(level > 9)
		level = Z_DEFAULT_COMPRESSION;

	deflateInit(&((zlib_stream_t *) conn->stream)->outstream, level);
	if(recvqlen > 0)
		common_zlib_inflate(conn, recvq_start, recvqlen);

	conn_mod_read_cb(conn->mod_fd, conn);
	conn_plain_read_cb(conn->plain_fd, conn);
	return;

}
#endif

static char *advance_zstring(uint8_t **p)
{
	rb_zstring_t *zs;
	ssize_t l;
	char *r;
	
	zs = rb_zstring_alloc();
	
	if(zs == NULL) 
		return NULL;

	l = rb_zstring_deserialize(zs, *p); 

	if(l == -1 || l > (INT16_MAX - 1))
	{
		rb_zstring_free(zs);
		return NULL;
	}
	

	*p += l;
	if(rb_zstring_len(zs) == 0)
	{
		rb_zstring_free(zs);
		return NULL;
	}
	r = rb_zstring_to_c_alloc(zs);
	rb_zstring_free(zs);
	return r;
}

static void
ssl_new_keys(mod_ctl_t * ctl, mod_ctl_buf_t * ctl_buf)
{
	static const char *inv = "I";

	char *cacert = NULL, *cert = NULL, *key = NULL, *dhparam = NULL, *ssl_cipher_list = NULL, *ssl_ecdh_named_curve = NULL, *tls_ver = NULL;
	uint8_t *p;
	int tls_min_ver = 0;
	rb_ssl_ctx *sctx = NULL, *cctx = NULL;
	uint8_t argcnt;
	
	p = (uint8_t *)&ctl_buf->buf[1];
	argcnt = *(uint8_t *)p;
	p++;
	if(argcnt != 7) 
		goto invalid;

	cacert = advance_zstring(&p);
	cert = advance_zstring(&p);
	if(cert == NULL)
		goto invalid;

	key = advance_zstring(&p);

	if(key == NULL)
		goto invalid;

	dhparam = advance_zstring(&p);
	ssl_cipher_list = advance_zstring(&p);
	ssl_ecdh_named_curve = advance_zstring(&p);
	tls_ver = advance_zstring(&p);
		
	if(tls_ver != NULL)
		tls_min_ver = atoi(tls_ver);

	sctx = rb_setup_ssl_server(cacert, cert, key, dhparam, ssl_cipher_list, ssl_ecdh_named_curve, tls_min_ver);

	if(sctx == NULL)
		goto invalid;
	
	cctx = rb_setup_ssl_client(ssl_cipher_list, cert, key);
	
	if(cctx == NULL)
		goto invalid;
	
	/* we've got useful ssl contexts now..
	 * we can release our reference to the contexts
	 * existing connections will survive this experience
	 */ 
	rb_ssl_ctx_free(ssl_client_ctx);
	rb_ssl_ctx_free(ssl_server_ctx);

	ssl_server_ctx = sctx;
	ssl_client_ctx = cctx;
	goto freeall;
	
invalid:
	mod_cmd_write_queue(ctl, inv, strlen(inv));
	rb_ssl_ctx_free(sctx); /* rb_ssl_ctx_free doesn't care if its null */
	rb_ssl_ctx_free(cctx);
freeall:
	rb_free(cacert);
	rb_free(cert);
	rb_free(key);
	rb_free(dhparam);
	rb_free(ssl_cipher_list);
	rb_free(ssl_ecdh_named_curve);
	rb_free(tls_ver);

	return;
}



static void
send_nossl_support(mod_ctl_t * ctl, mod_ctl_buf_t * ctlb)
{
	static const char *nossl_cmd = "N";
	conn_t *conn;
	uint32_t id;

	if(ctlb != NULL)
	{
		conn = make_conn(ctl, ctlb->F[0], ctlb->F[1]);
		if(conn == NULL)
		{
			rb_close(ctlb->F[0]);
			rb_close(ctlb->F[1]);
		}
		id = buf_to_uint32(&ctlb->buf[1]);

		conn_add_id_hash(conn, id);
		close_conn(conn, WAIT_PLAIN, "libratbox reports no SSL/TLS support");
	}
	mod_cmd_write_queue(ctl, nossl_cmd, strlen(nossl_cmd));
}

static void
send_i_am_useless(mod_ctl_t * ctl)
{
	static const char *useless = "U";
	mod_cmd_write_queue(ctl, useless, strlen(useless));
}

static void
send_nozlib_support(mod_ctl_t * ctl, mod_ctl_buf_t * ctlb)
{
	static const char *nozlib_cmd = "z";
	conn_t *conn;
	uint32_t id;
	if(ctlb != NULL)
	{
		conn = make_conn(ctl, ctlb->F[0], ctlb->F[1]);
		if(conn == NULL)
		{
			rb_close(ctlb->F[0]);
			rb_close(ctlb->F[1]);
		}
		id = buf_to_uint32(&ctlb->buf[1]);

		conn_add_id_hash(conn, id);
		close_conn(conn, WAIT_PLAIN, "libratbox reports no zlib support");
	}
	mod_cmd_write_queue(ctl, nozlib_cmd, strlen(nozlib_cmd));
}

static void
mod_process_cmd_recv(mod_ctl_t * ctl)
{
	rb_dlink_node *ptr, *next;
	mod_ctl_buf_t *ctl_buf;

	RB_DLINK_FOREACH_SAFE(ptr, next, ctl->readq.head)
	{
		ctl_buf = ptr->data;

		switch (*ctl_buf->buf)
		{
		case 'A':
			{
				if (ctl_buf->nfds != 2 || ctl_buf->buflen != 5)
				{
					cleanup_bad_message(ctl, ctl_buf);
					break;
				}

				if(ssl_ok == false)
				{
					send_nossl_support(ctl, ctl_buf);
					break;
				}
				ssl_process_accept(ctl, ctl_buf);
				break;
			}
		case 'C':
			{
				if (ctl_buf->nfds != 2 || ctl_buf->buflen != 5)
				{
					cleanup_bad_message(ctl, ctl_buf);
					break;
				}

				if(ssl_ok == false)
				{
					send_nossl_support(ctl, ctl_buf);
					break;
				}
				ssl_process_connect(ctl, ctl_buf);
				break;
			}

		case 'K':
			{
				if(ssl_ok == false)
				{
					send_nossl_support(ctl, ctl_buf);
					break;
				}
				ssl_new_keys(ctl, ctl_buf);
				break;
			}
		case 'S':
			{
				process_stats(ctl, ctl_buf);
				break;
			}
#ifdef HAVE_ZLIB
		case 'Z':
			{
				if (ctl_buf->nfds != 2 || ctl_buf->buflen < 6)
				{
					cleanup_bad_message(ctl, ctl_buf);
					break;
				}

				/* just zlib only */
				zlib_process(ctl, ctl_buf);
				break;
			}
#else
			
		case 'Z':
			send_nozlib_support(ctl, ctl_buf);
			break;

#endif
		default:
			break;
			/* Log unknown commands */
		}
		rb_dlinkDelete(ptr, &ctl->readq);
		rb_free(ctl_buf->buf);
		rb_free(ctl_buf);
	}
}



static void
mod_read_ctl(rb_fde_t *F, void *data)
{
	mod_ctl_buf_t *ctl_buf;
	mod_ctl_t *ctl = data;
	ssize_t retlen;
	int i;

	do
	{
		/* these get freed in mod_process_cmd_recv */
		ctl_buf = rb_malloc(sizeof(mod_ctl_buf_t));
		ctl_buf->buflen = READBUF_SIZE*4;
		ctl_buf->buf = rb_malloc(ctl_buf->buflen);
		retlen = rb_recv_fd_buf(ctl->F, ctl_buf->buf, ctl_buf->buflen, ctl_buf->F,
					MAXPASSFD);
		if(retlen <= 0)
		{
			rb_free(ctl_buf->buf);
			rb_free(ctl_buf);
		}
		else
		{
			ctl_buf->buflen = retlen;
			rb_dlinkAddTail(ctl_buf, &ctl_buf->node, &ctl->readq);
			for (i = 0; i < MAXPASSFD && ctl_buf->F[i] != NULL; i++)
				;
			ctl_buf->nfds = i;
		}
	}
	while(retlen > 0);

	if(retlen == 0 || (retlen < 0 && !rb_ignore_errno(errno)))
		exit(0);

	mod_process_cmd_recv(ctl);
	rb_setselect(ctl->F, RB_SELECT_READ, mod_read_ctl, ctl);
}

static void
mod_write_ctl(rb_fde_t *F, void *data)
{
	mod_ctl_t *ctl = data;
	mod_ctl_buf_t *ctl_buf;
	rb_dlink_node *ptr, *next;
	ssize_t retlen;
	int x;

	RB_DLINK_FOREACH_SAFE(ptr, next, ctl->writeq.head)
	{
		ctl_buf = ptr->data;
		retlen = rb_send_fd_buf(ctl->F, ctl_buf->F, ctl_buf->nfds, ctl_buf->buf,
					ctl_buf->buflen, ppid);
		if(retlen > 0)
		{
			rb_dlinkDelete(ptr, &ctl->writeq);
			for(x = 0; x < ctl_buf->nfds; x++)
				rb_close(ctl_buf->F[x]);
			rb_free(ctl_buf->buf);
			rb_free(ctl_buf);

		}
		if(retlen == 0 || (retlen < 0 && !rb_ignore_errno(errno)))
			exit(0);

	}
	if(rb_dlink_list_length(&ctl->writeq) > 0)
		rb_setselect(ctl->F, RB_SELECT_WRITE, mod_write_ctl, ctl);
}


static void
read_pipe_ctl(rb_fde_t *F, void *data)
{
	char inbuf[READBUF_SIZE];
	ssize_t retlen;
	while((retlen = rb_read(F, inbuf, sizeof(inbuf))) > 0)
	{
		;;		/* we don't do anything with the pipe really, just care if the other process dies.. */
	}
	if(retlen == 0 || (retlen < 0 && !rb_ignore_errno(errno)))
		exit(0);
	rb_setselect(F, RB_SELECT_READ, read_pipe_ctl, NULL);
}

int
main(int argc, char **argv)
{
	const char *s_ctlfd, *s_pipe, *s_pid;
	int ctlfd, pipefd, maxfd;
	mod_ctl_t *mod_ctl;

	maxfd = maxconn();
	s_ctlfd = getenv("CTL_FD");
	s_pipe = getenv("CTL_PIPE");
	s_pid = getenv("CTL_PPID");

	if(s_ctlfd == NULL || s_pipe == NULL || s_pid == NULL)
	{
		fprintf(stderr,
			"This is ircd-ratbox ssld.  You know you aren't supposed to run me directly?\n");
		fprintf(stderr, "We're sorry all circuits are busy now, will you please try your call again later? Code:1D Message:10-T \n");
		exit(1);
	}

	ctlfd = atoi(s_ctlfd);
	pipefd = atoi(s_pipe);
	ppid = atoi(s_pid);

	int x;

	for(x = 0; x < maxfd; x++)
	{
		if(x != ctlfd && x != pipefd && x > 2)
			close(x);
	}
#if 0
	x = open("/dev/null", O_RDWR);
	if(x >= 0)
	{
		if(ctlfd != 0 && pipefd != 0)
			dup2(x, 0);
		if(ctlfd != 1 && pipefd != 1)
			dup2(x, 1);
		if(ctlfd != 2 && pipefd != 2)
			dup2(x, 2);
		if(x > 2)
			close(x);
	}
#endif
	setup_signals();
	rb_lib_init(NULL, NULL, NULL, 0, maxfd);
	ssl_ok = rb_supports_ssl();
	mod_ctl = rb_malloc(sizeof(mod_ctl_t));
	mod_ctl->F = rb_open(ctlfd, RB_FD_SOCKET, "ircd control socket");
	rb_set_buffers(mod_ctl->F, READBUF_SIZE * 32);
	mod_ctl->F_pipe = rb_open(pipefd, RB_FD_PIPE, "ircd pipe");
	rb_set_nb(mod_ctl->F);
	rb_set_nb(mod_ctl->F_pipe);
	rb_event_add("clean_dead_conns", clean_dead_conns, NULL, 10);
	read_pipe_ctl(mod_ctl->F_pipe, NULL);
	mod_read_ctl(mod_ctl->F, mod_ctl);
	if(zlib_ok == false && ssl_ok == false)
	{
		/* this is really useless... */
		send_i_am_useless(mod_ctl);
		/* sleep until the ircd kills us */
		rb_sleep(INT_MAX-1, 0);
		exit(1);
	}

	if(zlib_ok == false)
		send_nozlib_support(mod_ctl, NULL);
	if(ssl_ok == false)
		send_nossl_support(mod_ctl, NULL);
	rb_lib_loop(0);
}


static void
dummy_handler(int sig)
{
	return;
}

static void
setup_signals(void)
{
	struct sigaction act;

	act.sa_flags = 0;
	act.sa_handler = SIG_IGN;
	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, SIGPIPE);
	sigaction(SIGPIPE, &act, NULL);
	sigaddset(&act.sa_mask, SIGALRM);
	sigaction(SIGALRM, &act, NULL);
	sigaddset(&act.sa_mask, SIGINT);
	sigaction(SIGINT, &act, NULL); 
#ifdef SIGTRAP
	sigaddset(&act.sa_mask, SIGTRAP);
	sigaction(SIGTRAP, &act, NULL);
#endif

#ifdef SIGWINCH
	sigaddset(&act.sa_mask, SIGWINCH);
	sigaction(SIGWINCH, &act, NULL);
#endif
	sigaction(SIGPIPE, &act, NULL);
#ifdef SIGTRAP
	sigaction(SIGTRAP, &act, NULL);
#endif

	act.sa_handler = dummy_handler;
	sigaction(SIGALRM, &act, NULL);
}
