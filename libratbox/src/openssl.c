/*
 *  libratbox: a library used by ircd-ratbox and other things
 *  openssl.c: openssl related code
 *
 *  Copyright (C) 2007-2026 ircd-ratbox development team
 *  Copyright (C) 2007-2008 Aaron Sethman <androsyn@ratbox.org>
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

#ifdef HAVE_OPENSSL

#include "commio-int.h"
#include "commio-ssl.h"
#include <openssl/ssl.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/rand.h>

typedef struct _ssl_connect
{
	CNCB *callback;
	void *data;
	int timeout;
} ssl_connect_t;

struct _rb_ssl_ctx
{
	SSL_CTX *ssl_ctx;  
	int refcount;
};
        
        
static int libratbox_index = -1;

static unsigned long
get_last_err(void)
{
	unsigned long t_err, err = 0;
	err = ERR_get_error();
	if(err == 0)
		return 0;

	while((t_err = ERR_get_error()) > 0)
		err = t_err;

	return err;
}

void
rb_ssl_shutdown(rb_fde_t *F)
{
	int i;
	
	rb_ssl_ctx_free(F->sctx);
	F->sctx = NULL;	
	
	if(F == NULL || F->ssl == NULL)
		return;
	SSL_set_shutdown((SSL *) F->ssl, SSL_RECEIVED_SHUTDOWN);

	for(i = 0; i < 4; i++)
	{
		if(SSL_shutdown((SSL *) F->ssl))
			break;
	}
	get_last_err();
	SSL_free((SSL *) F->ssl);

}



const char *
rb_ssl_get_cipher(rb_fde_t *F)
{
	const SSL_CIPHER *sslciph; 

	if(F == NULL || F->ssl == NULL)
		return NULL;

	if((sslciph = SSL_get_current_cipher(F->ssl)) == NULL)
		return NULL;

	return SSL_CIPHER_get_name(sslciph);
}

unsigned int
rb_ssl_handshake_count(rb_fde_t *F)
{
	return F->handshake_count;
}

time_t
rb_ssl_last_handshake(rb_fde_t *F)
{
	return F->last_handshake;
}

void
rb_ssl_clear_handshake_count(rb_fde_t *F)
{
	F->handshake_count = 0;
	F->last_handshake = 0;
}

static void
rb_ssl_timeout(rb_fde_t *F, void *notused)
{
	lrb_assert(F->accept != NULL);
	F->accept->callback(F, RB_ERR_TIMEOUT, NULL, 0, F->accept->data);
}


static void
rb_ssl_info_callback(SSL * ssl, int where, int ret)
{
	/* this shouldn't happen anymore with renegotiation disabled */
	if(where & SSL_CB_HANDSHAKE_START)
	{
		rb_fde_t *F = SSL_get_ex_data(ssl, libratbox_index);
		if(F == NULL)
			return;
		F->handshake_count++;
		F->last_handshake = rb_current_time();
	}
}

static void
rb_setup_ssl_cb(rb_fde_t *F)
{
	SSL_set_ex_data(F->ssl, libratbox_index, (char *)F);
	SSL_set_info_callback((SSL *) F->ssl,
			      (void (*)(const SSL *, int, int))rb_ssl_info_callback);
}

static void
rb_ssl_tryaccept(rb_fde_t *F, void *data)
{
	int ssl_err;
	lrb_assert(F->accept != NULL);
	unsigned int flags;
	struct acceptdata *ad;

	if(!SSL_is_init_finished((SSL *) F->ssl))
	{
		if((ssl_err = SSL_accept((SSL *) F->ssl)) <= 0)
		{
			switch (ssl_err = SSL_get_error((SSL *) F->ssl, ssl_err))
			{
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				if(ssl_err == SSL_ERROR_WANT_WRITE)
					flags = RB_SELECT_WRITE;
				else
					flags = RB_SELECT_READ;
				F->sslerr.ssl_errno = get_last_err();
				rb_setselect(F, flags, rb_ssl_tryaccept, NULL);
				break;
			case SSL_ERROR_SYSCALL:
				F->accept->callback(F, RB_ERROR, NULL, 0, F->accept->data);
				break;
			default:
				F->sslerr.ssl_errno = get_last_err();
				F->accept->callback(F, RB_ERROR_SSL, NULL, 0, F->accept->data);
				break;
			}
			return;
		}
	}
	rb_settimeout(F, 0, NULL, NULL);
	rb_setselect(F, RB_SELECT_READ | RB_SELECT_WRITE, NULL, NULL);

	ad = F->accept;
	F->accept = NULL;
	ad->callback(F, RB_OK, (struct sockaddr *)&ad->S, ad->addrlen, ad->data);
	rb_free(ad);

}


static void
rb_ssl_accept_common(rb_fde_t *new_F)
{
	int ssl_err;
	if((ssl_err = SSL_accept((SSL *) new_F->ssl)) <= 0)
	{
		switch (ssl_err = SSL_get_error((SSL *) new_F->ssl, ssl_err))
		{
		case SSL_ERROR_SYSCALL:
			if(rb_ignore_errno(errno))
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
				{
					new_F->sslerr.ssl_errno = get_last_err();
					rb_setselect(new_F, RB_SELECT_READ | RB_SELECT_WRITE,
						     rb_ssl_tryaccept, NULL);
					return;
				}
		default:
			new_F->sslerr.ssl_errno = get_last_err();
			new_F->accept->callback(new_F, RB_ERROR_SSL, NULL, 0, new_F->accept->data);
			return;
		}
	}
	else
	{
		rb_ssl_tryaccept(new_F, NULL);
	}
}

void
rb_ssl_start_accepted(rb_fde_t *new_F, ACCB * cb, void *data, int timeout)
{
	if(new_F->sctx == NULL)
		return;

	new_F->type |= RB_FD_SSL;
	new_F->ssl = SSL_new(new_F->sctx->ssl_ctx);
	if(new_F->ssl == NULL)
	{
		new_F->sslerr.ssl_errno = get_last_err();
		rb_lib_log("rb_ssl_start_accepted: SSL_new() fails: %s", ERR_error_string(new_F->sslerr.ssl_errno, NULL));
		cb(new_F, RB_ERROR_SSL, NULL, 0, data); 
		return;
	}

	new_F->accept = rb_malloc(sizeof(struct acceptdata));

	new_F->accept->callback = cb;
	new_F->accept->data = data;
	rb_settimeout(new_F, timeout, rb_ssl_timeout, NULL);

	new_F->accept->addrlen = 0;
	SSL_set_fd((SSL *) new_F->ssl, rb_get_fd(new_F));
	rb_setup_ssl_cb(new_F);
	rb_ssl_accept_common(new_F);
}




void
rb_ssl_accept_setup(rb_fde_t *F, rb_fde_t *new_F, struct sockaddr *st, rb_socklen_t addrlen)
{
	if(new_F->sctx == NULL)
		return;

	new_F->type |= RB_FD_SSL;
	new_F->accept = rb_malloc(sizeof(struct acceptdata));

	new_F->accept->callback = F->accept->callback;
	new_F->accept->data = F->accept->data;
	rb_settimeout(new_F, 10, rb_ssl_timeout, NULL);
	memcpy(&new_F->accept->S, st, addrlen);
	new_F->accept->addrlen = addrlen;

	new_F->ssl = SSL_new(new_F->sctx->ssl_ctx);

	if(new_F->ssl == NULL)
	{
		new_F->sslerr.ssl_errno = get_last_err();
		rb_lib_log("rb_ssl_accept_setup: SSL_new() fails: %s", ERR_error_string(new_F->sslerr.ssl_errno, NULL));
		new_F->accept->callback(new_F, RB_ERROR_SSL, NULL, 0, new_F->accept->data);
		rb_free(new_F->accept);
		new_F->accept = NULL;
		return;
	}

	SSL_set_fd((SSL *) new_F->ssl, rb_get_fd(new_F));
	rb_setup_ssl_cb(new_F);
	rb_ssl_accept_common(new_F);
}

typedef enum {
        DOREAD,
        DOWRITE
} rw_t;

static ssize_t
rb_ssl_read_or_write(rw_t r_or_w, rb_fde_t *F, void *rbuf, const void *wbuf, size_t count)
{
	int ret;
	unsigned long err;
	SSL *ssl = F->ssl;

	if(r_or_w == DOREAD)
		ret = SSL_read(ssl, rbuf, (int)count);
	else
		ret = SSL_write(ssl, wbuf, (int)count);

	if(ret < 0)
	{
		switch (SSL_get_error(ssl, ret))
		{
		case SSL_ERROR_WANT_READ:
			errno = EAGAIN;
			return RB_RW_SSL_NEED_READ;
		case SSL_ERROR_WANT_WRITE:
			errno = EAGAIN;
			return RB_RW_SSL_NEED_WRITE;
		case SSL_ERROR_ZERO_RETURN:
			return 0;
		case SSL_ERROR_SYSCALL:
			err = get_last_err();
			if(err == 0)
			{
				F->sslerr.ssl_errno = 0;
				return RB_RW_IO_ERROR;
			}
			break;
		default:
			err = get_last_err();
			break;
		}
		F->sslerr.ssl_errno = err;
		if(err > 0)
		{
			errno = EIO;	/* not great but... */
			return RB_RW_SSL_ERROR;
		}
		return RB_RW_IO_ERROR;
	}
	return (ssize_t)ret;
}

ssize_t
rb_ssl_read(rb_fde_t *F, void *buf, size_t count)
{
	return rb_ssl_read_or_write(DOREAD, F, buf, NULL, count);
}

ssize_t
rb_ssl_write(rb_fde_t *F, const void *buf, size_t count)
{
	return rb_ssl_read_or_write(DOWRITE, F, NULL, buf, count);
}

static int
verify_accept_all_cb(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
	return 1;
}
        

int
rb_init_ssl(void)
{
	int ret = 1;
	char libratbox_data[] = "libratbox data";
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	SSL_load_error_strings();
	SSL_library_init();
#else
	OPENSSL_init_ssl(0, NULL);
#endif
	libratbox_index = SSL_get_ex_new_index(0, libratbox_data, NULL, NULL, NULL);

	return ret;
}

void
rb_ssl_attach_ctx_to_fde(rb_ssl_ctx *sctx, rb_fde_t *F)
{
	F->sctx = sctx;
	sctx->refcount++;
}


void 
rb_ssl_ctx_free(rb_ssl_ctx *sctx)
{
	if(sctx == NULL)
		return;
	sctx->refcount--;
	if(sctx->refcount == 0)
	{
		SSL_CTX_free(sctx->ssl_ctx);
		rb_free(sctx);
	}
}

rb_ssl_ctx *
rb_setup_ssl_client(const char *ssl_cipher_list, const char *cert, const char *keyfile)
{
	/* this needs to have more customizations etc...client certificates perhaps as well */
	rb_ssl_ctx *sctx;
	
	sctx = rb_malloc(sizeof(rb_ssl_ctx));	
	sctx->refcount = 1;
        sctx->ssl_ctx = SSL_CTX_new(TLS_client_method());
        
        SSL_CTX_set_options(sctx->ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
        if(sctx->ssl_ctx == NULL)
        {
		rb_lib_log("rb_init_openssl: Unable to initialize OpenSSL client context: %s",
			    ERR_error_string(ERR_get_error(), NULL));
		rb_free(sctx);
		return NULL;
	}
	
	if(ssl_cipher_list != NULL)
	{
		if(!SSL_CTX_set_cipher_list(sctx->ssl_ctx, ssl_cipher_list))
		{
			rb_lib_log("rb_setup_ssl_client: Error setting ssl_cipher_list=\"%s\": %s",
				   ssl_cipher_list, ERR_error_string(ERR_get_error(), NULL));
                        goto cleanup;
		}
	}
	
	if(cert != NULL && keyfile != NULL)
	{
	        if(!SSL_CTX_use_PrivateKey_file(sctx->ssl_ctx, keyfile, SSL_FILETYPE_PEM))
	        {
	                rb_lib_log("rb_setup_ssl_client: Error loading keyfile :%s", ERR_error_string(ERR_get_error(), NULL));
	                goto cleanup;
	        }
	        if(!SSL_CTX_use_certificate_chain_file(sctx->ssl_ctx, cert))
	        {
	                rb_lib_log("rb_setup_ssl_client: Error loading certificate :%s", ERR_error_string(ERR_get_error(), NULL));
	                goto cleanup;
	        }
	}
	return sctx;

cleanup:
        SSL_CTX_free(sctx->ssl_ctx);
        rb_free(sctx);
        return NULL;        
}

rb_ssl_ctx *
rb_setup_ssl_server(const char *cacert, const char *cert, const char *keyfile, const char *dhfile,
		    const char *ssl_cipher_list, const char *named_curve, rb_tls_ver_t tls_min_ver)
{
        const char *libratbox_data = "libratbox tls session";
	const char *ciphers = "kEECDH+HIGH:kEDH+HIGH:HIGH:!RC4:!aNULL";
	unsigned long err;
	rb_ssl_ctx *sctx; 
	long tls_opts;
	sctx = rb_malloc(sizeof(rb_ssl_ctx));
	sctx->refcount = 1;
	sctx->ssl_ctx = SSL_CTX_new(TLS_server_method());
	if(sctx->ssl_ctx == NULL)
	{
		rb_lib_log("rb_init_openssl: Unable to initialize OpenSSL server context: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		rb_free(sctx);
		return NULL;
	}

	tls_opts = SSL_CTX_get_options(sctx->ssl_ctx);

	/* Disable SSLv2, make the client use our settings */
	tls_opts |= SSL_OP_NO_SSLv2 | SSL_OP_NO_COMPRESSION | SSL_OP_CIPHER_SERVER_PREFERENCE | SSL_OP_NO_RENEGOTIATION;
	switch(tls_min_ver)
	{
		case RB_TLS_VER_SSL3: /* we default to SSLv3..sadly */
			break;
			
		case RB_TLS_VER_TLS1:
#ifdef SSL_OP_NO_SSLv3
			tls_opts |= SSL_OP_NO_SSLv3;
#endif
			break;
		case RB_TLS_VER_TLS1_1:
#ifdef SSL_OP_NO_TLSv1
			tls_opts |= SSL_OP_NO_TLSv1;
#endif
			break;

		case RB_TLS_VER_TLS1_2:
#ifdef SSL_OP_NO_TLSv1
			tls_opts |= SSL_OP_NO_TLSv1;
#endif
#ifdef SSL_OP_NO_TLSv1_1
			tls_opts |= SSL_OP_NO_TLSv1_1;
#endif
			break;
		case RB_TLS_VER_LAST:
			break;
	}

#ifdef SSL_OP_NO_TICKET
	tls_opts |= SSL_OP_NO_TICKET;
#endif

	SSL_CTX_set_options(sctx->ssl_ctx, tls_opts);


	if(ssl_cipher_list != NULL)
		ciphers = ssl_cipher_list;

	if(!SSL_CTX_set_cipher_list(sctx->ssl_ctx, ciphers))
	{
		rb_lib_log("rb_setup_ssl_server: Error setting ssl_cipher_list=\"%s\": %s",
			   ciphers, ERR_error_string(ERR_get_error(), NULL));
		goto cleanup;;
	}


	if(cert == NULL)
	{
		rb_lib_log("rb_setup_ssl_server: No certificate file");
		goto cleanup;
	}
	if(!SSL_CTX_use_certificate_chain_file(sctx->ssl_ctx, cert))
	{
		err = ERR_get_error();
		rb_lib_log("rb_setup_ssl_server: Error loading certificate file [%s]: %s", cert,
			   ERR_error_string(err, NULL));
		goto cleanup;
	}
	
	if(cacert != NULL)
	{
		if (!SSL_CTX_load_verify_locations(sctx->ssl_ctx, cacert, NULL)) 
		{
			err = ERR_get_error();
			rb_lib_log("rb_setup_ssl_server: Error loading CA file [%s]: %s", cacert, ERR_error_string(err, NULL));
			goto cleanup;
		}
	}

	if(keyfile == NULL)
	{
		rb_lib_log("rb_setup_ssl_server: No key file");
		goto cleanup;
	}


	if(!SSL_CTX_use_PrivateKey_file(sctx->ssl_ctx, keyfile, SSL_FILETYPE_PEM))
	{
		err = ERR_get_error();
		rb_lib_log("rb_setup_ssl_server: Error loading keyfile [%s]: %s", keyfile,
			   ERR_error_string(err, NULL));
		goto cleanup;;
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if(dhfile != NULL)
	{
		/* DH parameters aren't necessary, but they are nice..if they didn't pass one..that is their problem */
		BIO *bio = BIO_new_file(dhfile, "r");
		if(bio != NULL)
		{
			DH *dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
			if(dh == NULL)
			{
				err = ERR_get_error();
				rb_lib_log
					("rb_setup_ssl_server: Error loading DH params file [%s]: %s",
					 dhfile, ERR_error_string(err, NULL));
				BIO_free(bio);
				goto cleanup;
			}
			BIO_free(bio);
			SSL_CTX_set_tmp_dh(sctx->ssl_ctx, dh);
			DH_free(dh);
			tls_opts = SSL_CTX_get_options(sctx->ssl_ctx);
#ifdef SSL_OP_SINGLE_DH_USE
                	tls_opts |= SSL_OP_SINGLE_DH_USE;
#endif
                	SSL_CTX_set_options(sctx->ssl_ctx, tls_opts);
		}
		else
		{
			err = ERR_get_error();
			rb_lib_log("rb_setup_ssl_server: Error loading DH params file [%s]: %s",
				   dhfile, ERR_error_string(err, NULL));
			goto cleanup;	  
		}
	} 
#else
	SSL_CTX_set_dh_auto(sctx->ssl_ctx, 1);
#endif
	

#if (OPENSSL_VERSION_NUMBER >= 0x0090800fL) && (OPENSSL_VERSION_NUMBER < 0x30000000L)
#ifndef OPENSSL_NO_ECDH
	
	if(named_curve != NULL)
	{
		int nid;
		EC_KEY *ecdh;
		
		nid = OBJ_sn2nid(named_curve);
		if(nid == 0)
		{
			err = ERR_get_error();
			rb_lib_log("rb_setup_ssl_server: Unknown curve named [%s]: %s", named_curve, ERR_error_string(err, NULL));
			goto cleanup;
		}
		
		ecdh = EC_KEY_new_by_curve_name(nid);
		if(ecdh == NULL)
		{
			err = ERR_get_error();
			rb_lib_log("rb_setup_ssl_server: Curve creation failed for [%s]: %s", named_curve, ERR_error_string(err, NULL));
			goto cleanup;
		}
		tls_opts = SSL_CTX_get_options(sctx->ssl_ctx);
		tls_opts |= SSL_OP_SINGLE_ECDH_USE;
		SSL_CTX_set_options(sctx->ssl_ctx, tls_opts);
		SSL_CTX_set_tmp_ecdh(sctx->ssl_ctx, ecdh);
		EC_KEY_free(ecdh);
	}
#endif
#endif
	SSL_CTX_set_verify(sctx->ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, verify_accept_all_cb);
	SSL_CTX_set_session_id_context(sctx->ssl_ctx, (const unsigned char *)libratbox_data, strlen(libratbox_data));
	return sctx;

cleanup:
	SSL_CTX_free(sctx->ssl_ctx);
	rb_free(sctx);
	return NULL;
		
	
}

int
rb_ssl_listen(rb_fde_t *F, int backlog, bool defer_accept)
{
        int result;
        result = rb_listen(F, backlog, defer_accept);
	F->type = RB_FD_SOCKET | RB_FD_LISTEN | RB_FD_SSL;
	return result;
}


static void
rb_ssl_connect_realcb(rb_fde_t *F, int status, ssl_connect_t *sconn)
{
	F->connect->callback = sconn->callback;
	F->connect->data = sconn->data;
	rb_free(sconn);
	rb_connect_callback(F, status);
}

static void
rb_ssl_tryconn_timeout_cb(rb_fde_t *F, void *data)
{
	rb_ssl_connect_realcb(F, RB_ERR_TIMEOUT, data);
}

static void
rb_ssl_tryconn_cb(rb_fde_t *F, void *data)
{
	ssl_connect_t *sconn = data;
	int ssl_err;
	if(!SSL_is_init_finished((SSL *) F->ssl))
	{
		if((ssl_err = SSL_connect((SSL *) F->ssl)) <= 0)
		{
			switch (ssl_err = SSL_get_error((SSL *) F->ssl, ssl_err))
			{
			case SSL_ERROR_SYSCALL:
				if(rb_ignore_errno(errno))
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
					{
						F->sslerr.ssl_errno = get_last_err();
						rb_setselect(F, RB_SELECT_READ | RB_SELECT_WRITE,
							     rb_ssl_tryconn_cb, sconn);
						return;
					}
			default:
				F->sslerr.ssl_errno = get_last_err();
				rb_ssl_connect_realcb(F, RB_ERROR_SSL, sconn);
				return;
			}
		}
		else
		{
			rb_ssl_connect_realcb(F, RB_OK, sconn);
		}
	}
}

static void
rb_ssl_tryconn(rb_fde_t *F, int status, void *data)
{
	ssl_connect_t *sconn = data;
	int ssl_err;
	if(status != RB_OK)
	{
		rb_ssl_connect_realcb(F, status, sconn);
		return;
	}

	F->type |= RB_FD_SSL;
	F->ssl = SSL_new(F->sctx->ssl_ctx);

	if(F->ssl == NULL)
	{
		F->sslerr.ssl_errno = get_last_err();
		rb_lib_log("rb_ssl_tryconn: SSL_new() fails: %s", ERR_error_string(F->sslerr.ssl_errno, NULL));
		rb_ssl_connect_realcb(F, RB_ERROR_SSL, sconn);
		return;
	}
	
	SSL_set_fd((SSL *) F->ssl, F->fd);
	rb_setup_ssl_cb(F);
	rb_settimeout(F, sconn->timeout, rb_ssl_tryconn_timeout_cb, sconn);
	if((ssl_err = SSL_connect((SSL *) F->ssl)) <= 0)
	{
		switch (ssl_err = SSL_get_error((SSL *) F->ssl, ssl_err))
		{
		case SSL_ERROR_SYSCALL:
			if(rb_ignore_errno(errno))
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
				{
					F->sslerr.ssl_errno = get_last_err();
					rb_setselect(F, RB_SELECT_READ | RB_SELECT_WRITE,
						     rb_ssl_tryconn_cb, sconn);
					return;
				}
		default:
			F->sslerr.ssl_errno = get_last_err();
			rb_ssl_connect_realcb(F, RB_ERROR_SSL, sconn);
			return;
		}
	}
	else
	{
		rb_ssl_connect_realcb(F, RB_OK, sconn);
	}
}

void
rb_connect_tcp_ssl(rb_fde_t *F, struct sockaddr *dest,
		   struct sockaddr *clocal, rb_socklen_t socklen, CNCB * callback, void *data, int timeout)
{
	ssl_connect_t *sconn;
	if(F == NULL)
		return;

	sconn = rb_malloc(sizeof(ssl_connect_t));
	sconn->data = data;
	sconn->callback = callback;
	sconn->timeout = timeout;
	rb_connect_tcp(F, dest, clocal, socklen, rb_ssl_tryconn, sconn, timeout);

}

void
rb_ssl_start_connected(rb_fde_t *F, CNCB * callback, void *data, int timeout)
{
	ssl_connect_t *sconn;
	int ssl_err;
	if(F == NULL)
		return;

	sconn = rb_malloc(sizeof(ssl_connect_t));
	sconn->data = data;
	sconn->callback = callback;
	sconn->timeout = timeout;
	F->ssl = SSL_new(F->sctx->ssl_ctx);

        if(F->ssl == NULL)
        {
                F->sslerr.ssl_errno = get_last_err();
                rb_lib_log("rb_ssl_start_Connected: SSL_new() fails: %s", ERR_error_string(F->sslerr.ssl_errno, NULL));
                
                rb_ssl_connect_realcb(F, RB_ERROR_SSL, sconn);
                return;
        }

	F->connect = rb_malloc(sizeof(struct conndata));
	F->connect->callback = callback;
	F->connect->data = data;
	F->type |= RB_FD_SSL;

	SSL_set_fd((SSL *) F->ssl, F->fd);
	rb_setup_ssl_cb(F);
	rb_settimeout(F, sconn->timeout, rb_ssl_tryconn_timeout_cb, sconn);
	if((ssl_err = SSL_connect((SSL *) F->ssl)) <= 0)
	{
		switch (ssl_err = SSL_get_error((SSL *) F->ssl, ssl_err))
		{
		case SSL_ERROR_SYSCALL:
			if(rb_ignore_errno(errno))
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
				{
					F->sslerr.ssl_errno = get_last_err();
					rb_setselect(F, RB_SELECT_READ | RB_SELECT_WRITE,
						     rb_ssl_tryconn_cb, sconn);
					return;
				}
		default:
			F->sslerr.ssl_errno = get_last_err();
			rb_ssl_connect_realcb(F, RB_ERROR_SSL, sconn);
			return;
		}
	}
	else
	{
		rb_ssl_connect_realcb(F, RB_OK, sconn);
	}
}

int
rb_init_prng(const char *path, prng_seed_t seed_type)
{
	switch (seed_type)
	{
	case RB_PRNG_FILE:
		if(path == NULL)
			return -1;
		if(RAND_load_file(path, -1) == -1)
			return -1;
		break;
	case RB_PRNG_DEFAULT:
		break;
	}
	return RAND_status();
}

int
rb_get_random(void *buf, size_t length)
{
	int ret;

	if((ret = RAND_bytes(buf, (int)length)) == 0)
	{
		/* remove the error from the queue */
		ERR_get_error();
	}
	return ret;
}

int
rb_get_pseudo_random(void *buf, size_t length)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	int ret;
	ret = RAND_pseudo_bytes(buf, (int)length);
	
	if(ret < 0)
		return 0;
	return 1;
#else
	return rb_get_random(buf, length);
#endif
}

const char *
rb_ssl_get_strerror(rb_fde_t *F)
{
	return ERR_error_string(F->sslerr.ssl_errno, NULL);
}

int
rb_ssl_get_certfp(rb_fde_t *F, uint8_t certfp[RB_SSL_CERTFP_LEN])
{
        X509 *cert;
        long res;

        if (F->ssl == NULL)
                return 0;
	
        cert = SSL_get_peer_certificate((SSL *) F->ssl);
        if(cert != NULL)
        {
                res = SSL_get_verify_result((SSL *) F->ssl);
                if(
                        res == X509_V_OK ||
                        res == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN ||
                        res == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE ||
                        res == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
                        res == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
                {   
                        unsigned int certfp_length = RB_SSL_CERTFP_LEN;
                        X509_digest(cert, EVP_sha256(), certfp, &certfp_length);
                        X509_free(cert);
                        return 1;
                }
                X509_free(cert);
        }
        return 0;
}




bool
rb_supports_ssl(void)
{
	return true;
}


#if OPENSSL_VERSION_NUMBER < 0x10100000L
# define rb_ssl_version_num() (long)SSLeay()
# define rb_ssl_version_str() SSLeay_version(SSLEAY_VERSION)
#else
# define rb_ssl_version_num() (long)OpenSSL_version_num()
# define rb_ssl_version_str() OpenSSL_version(OPENSSL_VERSION)
#endif

void
rb_get_ssl_info(char *buf, size_t len)
{
	snprintf(buf, len, "Using SSL: %s compiled: 0x%lx, library 0x%lx",
		 rb_ssl_version_str(), (long)OPENSSL_VERSION_NUMBER, rb_ssl_version_num());
}

#endif /* HAVE_OPESSL */
