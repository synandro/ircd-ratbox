/*
 *  ircd-ratbox:  A slight useful ircd
 *  rawbuf.c: raw buffer (non-line oriented buffering)
 *  
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
#include "libratbox_config.h"
#include "ratbox_lib.h"
#include "commio-int.h"
#define RAWBUF_SIZE 1024

struct _rb_rawbuf
{
	rb_dlink_node node;
	uint8_t data[RAWBUF_SIZE];
	size_t len;
	bool flushing;
};

struct _rb_rawbuf_head
{
	rb_dlink_list list;
	size_t len;
	size_t written;
};



static rb_rawbuf_t *
rb_rawbuf_newbuf(rb_rawbuf_head_t * rb)
{
	rb_rawbuf_t *buf;
	buf = rb_malloc(sizeof(rb_rawbuf_t));
	rb_dlinkAddTail(buf, &buf->node, &rb->list);
	return buf;
}

static void
rb_rawbuf_done(rb_rawbuf_head_t * rb, rb_rawbuf_t * buf)
{
	rb_rawbuf_t *ptr = buf;
	rb_dlinkDelete(&buf->node, &rb->list);
	rb_free(ptr);
}

static ssize_t
rb_rawbuf_flush_writev(rb_rawbuf_head_t * rb, rb_fde_t *F)
{
	rb_dlink_node *ptr, *next;
	rb_rawbuf_t *buf;
	int x = 0, y = 0;
	ssize_t xret, retval;
	struct rb_iovec vec[RB_UIO_MAXIOV];
	memset(vec, 0, sizeof(vec));

	if(rb->list.head == NULL)
	{
		errno = EAGAIN;
		return -1;
	}

	RB_DLINK_FOREACH(ptr, rb->list.head)
	{
		if(x >= RB_UIO_MAXIOV)
			break;

		buf = ptr->data;
		if(buf->flushing == true)
		{
			vec[x].iov_base = buf->data + rb->written;
			vec[x++].iov_len = buf->len - rb->written;
			continue;
		}
		vec[x].iov_base = buf->data;
		vec[x++].iov_len = buf->len;

	}

	if(x == 0)
	{
		errno = EAGAIN;
		return -1;
	}
	xret = retval = rb_writev(F, vec, x);
	if(retval <= 0)
		return retval;

	RB_DLINK_FOREACH_SAFE(ptr, next, rb->list.head)
	{
		buf = ptr->data;
		if(y++ >= x)
			break;
		if(buf->flushing == true)
		{
			if(xret >= (ssize_t)(buf->len - rb->written))
			{
				xret -= buf->len - rb->written;
				rb->len -= buf->len - rb->written;
				rb_rawbuf_done(rb, buf);
				continue;
			}
		}

		if(xret >= (ssize_t)buf->len)
		{
			xret -= buf->len;
			rb->len -= buf->len;
			rb_rawbuf_done(rb, buf);
		}
		else
		{
			buf->flushing = true;
			rb->written = (size_t)xret;
			rb->len -= (size_t)xret;
			break;
		}

	}
	return retval;
}

ssize_t
rb_rawbuf_flush(rb_rawbuf_head_t * rb, rb_fde_t *F)
{
	rb_rawbuf_t *buf;
	ssize_t retval;
	if(rb->list.head == NULL)
	{
		errno = EAGAIN;
		return -1;
	}

	if(!rb_fd_ssl(F))
		return rb_rawbuf_flush_writev(rb, F);

	buf = rb->list.head->data;
	if(buf->flushing == false)
	{
		buf->flushing = true;
		rb->written = 0;
	}

	retval = rb_write(F, buf->data + rb->written, buf->len - rb->written);
	if(retval <= 0)
		return retval;

	rb->written += (size_t)retval;
	if(rb->written == buf->len)
	{
		rb->written = 0;
		rb_dlinkDelete(&buf->node, &rb->list);
		rb_free(buf);
	}
	rb->len -= (size_t)retval;
	return retval;
}

#ifndef IRCD_MIN
#define IRCD_MIN(a, b)	((a) < (b) ? (a) : (b))
#endif

void
rb_rawbuf_append(rb_rawbuf_head_t * rb, void *in, size_t len)
{
	rb_rawbuf_t *buf = NULL;
	size_t clen;
	void *ptr;
	uint8_t *data = in;

	if(rb->list.tail != NULL)
		buf = rb->list.tail->data;

	if(buf != NULL && buf->len < sizeof(buf->data) && buf->flushing == false)
	{
		ptr = (void *)((uintptr_t)buf->data + buf->len);
		clen = IRCD_MIN((sizeof(buf->data) - buf->len), len);
		memcpy(ptr, data, clen);
		buf->len += clen;
		rb->len += clen;
		len -= clen;
		data = (data + clen);
	}

	while(len > 0)
	{
		buf = rb_rawbuf_newbuf(rb);
		clen = IRCD_MIN(sizeof(buf->data), len);
		memcpy(buf->data, data, clen);
		buf->len += clen;
		rb->len += clen;
		len -= clen;
		data = (data + clen);
	}
}


size_t
rb_rawbuf_get(rb_rawbuf_head_t * rb, void *data, size_t len)
{
	rb_rawbuf_t *buf;
	size_t cpylen;
	void *ptr;
	if(rb->list.head == NULL)
		return 0;

	buf = rb->list.head->data;

	if(buf->flushing == true)
		ptr = (void *)(buf->data + rb->written);
	else
		ptr = buf->data;

	if(len > buf->len)
		cpylen = buf->len;
	else
		cpylen = len;

	memcpy(data, ptr, cpylen);

	if(cpylen == buf->len)
	{
		rb->written = 0;
		rb_rawbuf_done(rb, buf);
		rb->len -= len;
		return cpylen;
	}

	buf->flushing = true;
	buf->len -= cpylen;
	rb->len -= cpylen;
	rb->written += cpylen;
	return cpylen;
}

size_t
rb_rawbuf_length(rb_rawbuf_head_t * rb)
{
	if(rb_dlink_list_length(&rb->list) == 0 && rb->len != 0)
		lrb_assert(1 == 0);
	return rb->len;
}

rb_rawbuf_head_t *
rb_new_rawbuffer(void)
{
	return rb_malloc(sizeof(rb_rawbuf_head_t));

}

void
rb_free_rawbuffer(rb_rawbuf_head_t * rb)
{
	rb_dlink_node *ptr, *next;
	RB_DLINK_FOREACH_SAFE(ptr, next, rb->list.head)
	{
		rb_rawbuf_done(rb, ptr->data);
	}
	rb_free(rb);
}


