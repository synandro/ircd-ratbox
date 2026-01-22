/*
 *  libratbox: a library used by ircd-ratbox and other things
 *  mbedtls.c: mbedtls related code
 *
 *  Copyright (C) 2007-2026 ircd-ratbox development team
 *  Copyright (C) 2007-2008 Aaron Sethman <androsyn@ratbox.org>
 *  Copyright (C) 2015 William Pitcock <nenolod@dereferenced.org>
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
#include "commio-ssl.h"

#ifdef HAVE_MBEDTLS
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/dhm.h"
#include "mbedtls/version.h"

typedef struct _ssl_connect
{
        CNCB *callback;
        void *data;
        int timeout;
} ssl_connect_t;

struct _rb_ssl_ctx
{
//	mbedtls_ssl_ctx *ctx;
	mbedtls_x509_crt x509;
	mbedtls_x509_crt cacert;
	mbedtls_pk_context serv_pk;
	mbedtls_dhm_context dh_params;
//	mbedtls_ctr_drbg_context ctr_drbg;
	//mbedtls_entropy_context entropy;
	mbedtls_ssl_config config;
        int refcount;
};


/*
static mbedtls_x509_crt x509;
static mbedtls_pk_context serv_pk;
static mbedtls_dhm_context dh_params;
static mbedtls_ssl_config serv_config;
static mbedtls_ssl_config client_config;
*/
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_entropy_context entropy;


#define SSL_P(x) ((mbedtls_ssl_context *)F->ssl)

void
rb_ssl_shutdown(rb_fde_t *F)
{
	int i;
	if(F == NULL || F->ssl == NULL)
		return;
	for(i = 0; i < 4; i++)
	{
		int r = mbedtls_ssl_close_notify(SSL_P(F));
		if(r != MBEDTLS_ERR_SSL_WANT_READ && r != MBEDTLS_ERR_SSL_WANT_WRITE)
			break;
	}
	mbedtls_ssl_free(SSL_P(F));
	rb_free(F->ssl);
}

unsigned int
rb_ssl_handshake_count(rb_fde_t *F)
{
	return F->handshake_count;
}

void
rb_ssl_clear_handshake_count(rb_fde_t *F)
{
	F->handshake_count = 0;
}

static void
rb_ssl_timeout(rb_fde_t *F, void *notused)
{
	lrb_assert(F->accept != NULL);
	F->accept->callback(F, RB_ERR_TIMEOUT, NULL, 0, F->accept->data);
}


static int
do_ssl_handshake(rb_fde_t *F, PF * callback, void *data)
{
	int ret;
	int flags;

	ret = mbedtls_ssl_handshake(SSL_P(F));
	if(ret < 0)
	{
		if (ret == -1 && rb_ignore_errno(errno))
			ret = MBEDTLS_ERR_SSL_WANT_READ;

		if((ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE))
		{
			if(ret == MBEDTLS_ERR_SSL_WANT_READ)
				flags = RB_SELECT_READ;
			else
				flags = RB_SELECT_WRITE;
			rb_setselect(F, flags, callback, data);
			return 0;
		}

		F->sslerr.ssl_errno = ret;
		return -1;
	}
	return 1;		/* handshake is finished..go about life */
}

static void
rb_ssl_tryaccept(rb_fde_t *F, void *data)
{
	int ret;
	struct acceptdata *ad;

	lrb_assert(F->accept != NULL);

	ret = do_ssl_handshake(F, rb_ssl_tryaccept, NULL);

	/* do_ssl_handshake does the rb_setselect */
	if(ret == 0)
		return;

	ad = F->accept;
	F->accept = NULL;
	rb_settimeout(F, 0, NULL, NULL);
	rb_setselect(F, RB_SELECT_READ | RB_SELECT_WRITE, NULL, NULL);

	if(ret > 0)
		ad->callback(F, RB_OK, (struct sockaddr *)&ad->S, ad->addrlen, ad->data);
	else
		ad->callback(F, RB_ERROR_SSL, NULL, 0, ad->data);

	rb_free(ad);
}

static int
rb_ssl_read_cb(void *opaque, unsigned char *buf, size_t size)
{
	int ret;
	rb_fde_t *F = opaque;

	ret = read(F->fd, buf, size);
	if (ret < 0 && rb_ignore_errno(errno))
		return MBEDTLS_ERR_SSL_WANT_READ;

	return ret;
}

static int
rb_ssl_write_cb(void *opaque, const unsigned char *buf, size_t size)
{
	rb_fde_t *F = opaque;
	int ret;

	ret = write(F->fd, buf, size);
	if (ret < 0 && rb_ignore_errno(errno))
		return MBEDTLS_ERR_SSL_WANT_WRITE;

	return ret;
}

static void
rb_ssl_setup_srv_context(rb_fde_t *F)
{
	int ret;
	
	mbedtls_ssl_init(SSL_P(F));
	if ((ret = mbedtls_ssl_setup(SSL_P(F), &F->sctx->config)) != 0)
	{
		rb_lib_log("rb_ssl_setup_srv_context: failed to set up ssl context: -0x%x", -ret);
		rb_close(F);
		return;
	}

	mbedtls_ssl_set_bio(SSL_P(F), F, rb_ssl_write_cb, rb_ssl_read_cb, NULL);
}

void
rb_ssl_start_accepted(rb_fde_t *new_F, ACCB * cb, void *data, int timeout)
{
	mbedtls_ssl_context *ssl;
	new_F->type |= RB_FD_SSL;
	ssl = new_F->ssl = rb_malloc(sizeof(mbedtls_ssl_context));
	new_F->accept = rb_malloc(sizeof(struct acceptdata));

	new_F->accept->callback = cb;
	new_F->accept->data = data;
	rb_settimeout(new_F, timeout, rb_ssl_timeout, NULL);

	new_F->accept->addrlen = 0;

	rb_ssl_setup_srv_context(new_F);
	if(do_ssl_handshake(new_F, rb_ssl_tryaccept, NULL))
	{
		struct acceptdata *ad = new_F->accept;
		new_F->accept = NULL;

		ad->callback(new_F, RB_OK, (struct sockaddr *)&ad->S, ad->addrlen, ad->data);
		rb_free(ad);
	}
}

void
rb_ssl_accept_setup(rb_fde_t *F, rb_fde_t *new_F, struct sockaddr *st, rb_socklen_t addrlen)
{
	new_F->type |= RB_FD_SSL;
	new_F->ssl = rb_malloc(sizeof(mbedtls_ssl_context));
	new_F->accept = rb_malloc(sizeof(struct acceptdata));

	new_F->accept->callback = F->accept->callback;
	new_F->accept->data = F->accept->data;
	rb_settimeout(new_F, 10, rb_ssl_timeout, NULL);
	memcpy(&new_F->accept->S, st, addrlen);
	new_F->accept->addrlen = addrlen;

	rb_ssl_setup_srv_context(new_F);
	if(do_ssl_handshake(new_F, rb_ssl_tryaccept, NULL))
	{
		struct acceptdata *ad = new_F->accept;
		new_F->accept = NULL;

		ad->callback(new_F, RB_OK, (struct sockaddr *)&ad->S, ad->addrlen, ad->data);
		rb_free(ad);
	}
}

static ssize_t
rb_ssl_read_or_write(int r_or_w, rb_fde_t *F, void *rbuf, const void *wbuf, size_t count)
{
	ssize_t ret;

	if(r_or_w == 0)
		ret = mbedtls_ssl_read(F->ssl, rbuf, count);
	else
		ret = mbedtls_ssl_write(F->ssl, wbuf, count);

	if(ret < 0)
	{
		switch (ret)
		{
		case MBEDTLS_ERR_SSL_WANT_READ:
			return RB_RW_SSL_NEED_READ;
		case MBEDTLS_ERR_SSL_WANT_WRITE:
			return RB_RW_SSL_NEED_WRITE;
		default:
			F->sslerr.ssl_errno = ret;
			errno = EIO;
			return RB_RW_IO_ERROR;
		}
	}

	return ret;
}

ssize_t
rb_ssl_read(rb_fde_t *F, void *buf, size_t count)
{
	return rb_ssl_read_or_write(0, F, buf, NULL, count);
}

ssize_t
rb_ssl_write(rb_fde_t *F, const void *buf, size_t count)
{
	return rb_ssl_read_or_write(1, F, NULL, buf, count);
}

int
rb_init_ssl(void)
{
	int ret;
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);


	if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0)
	{
		rb_lib_log("rb_init_prng: unable to initialize PRNG, mbedtls_ctr_drbg_seed() returned -0x%x", -ret);
		return 0;
	}
#if 0
	mbedtls_ssl_config_init(&serv_config);

	if ((ret = mbedtls_ssl_config_defaults(&serv_config,
		MBEDTLS_SSL_IS_SERVER,
		MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
	{
		rb_lib_log("rb_init_ssl: unable to initialize default SSL parameters for server context: -0x%x", -ret);
		return 0;
	}
#endif
//	mbedtls_ssl_conf_rng(&serv_config, mbedtls_ctr_drbg_random, &ctr_drbg);

	/***************************************************************************************************************/
#if 0
	mbedtls_ssl_config_init(&client_config);

	if ((ret = mbedtls_ssl_config_defaults(&client_config,
		MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
	{
		rb_lib_log("rb_init_ssl: unable to initialize default SSL parameters for client context: -0x%x", -ret);
		return 0;
	}

	mbedtls_ssl_conf_rng(&client_config, mbedtls_ctr_drbg_random, &ctr_drbg);
#endif
	return 1;
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
	        /* XXX mbedtls_ctx_free??? */
//		SSL_CTX_free(sctx->ssl_ctx);
		rb_free(sctx);
	}
}

rb_ssl_ctx *
rb_setup_ssl_client(const char *ssl_cipher_list, const char *cert, const char *keyfile)
{	
	int ret;
	rb_ssl_ctx *sctx;
	
	sctx = rb_malloc(sizeof(rb_ssl_ctx));

	mbedtls_ssl_config_init(&sctx->config);

	if ((ret = mbedtls_ssl_config_defaults(&sctx->config,
		MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
	{
		rb_lib_log("rb_init_ssl: unable to initialize default SSL parameters for client context: -0x%x", -ret);
		return 0;
	}
	
	mbedtls_ssl_conf_rng(&sctx->config, mbedtls_ctr_drbg_random, &ctr_drbg);

	mbedtls_ssl_conf_authmode(&sctx->config, MBEDTLS_SSL_VERIFY_NONE);

	if(cert != NULL && keyfile != NULL)
	{
		mbedtls_x509_crt_init(&sctx->x509);
		ret = mbedtls_x509_crt_parse_file(&sctx->x509, cert);
		if (ret != 0)
		{
			rb_lib_log("rb_setup_ssl_client: failed to parse certificate '%s': -0x%x", cert, -ret);
			return 0;
		}

		mbedtls_pk_init(&sctx->serv_pk);
		ret = mbedtls_pk_parse_keyfile(&sctx->serv_pk, keyfile, NULL);
		if (ret != 0)
		{
			rb_lib_log("rb_setup_ssl_client: failed to parse private key '%s': -0x%x", keyfile, -ret);
			return 0;
		}

		if (&sctx->x509.next)
			mbedtls_ssl_conf_ca_chain(&sctx->config, sctx->x509.next, NULL);

		if ((ret = mbedtls_ssl_conf_own_cert(&sctx->config, &sctx->x509, &sctx->serv_pk)) != 0)
		{
			rb_lib_log("rb_setup_ssl_client: failed to set up own certificate: -0x%x", -ret);
			return 0;
		}
	}
	return sctx;



}


rb_ssl_ctx *
rb_setup_ssl_server(const char *cacert, const char *cert, const char *keyfile, const char *dhfile, const char *ssl_cipher_list, const char *named_curve, rb_tls_ver_t tls_min_ver)
{
	int ret;
	rb_ssl_ctx *sctx;
	
	sctx = rb_malloc(sizeof(rb_ssl_ctx));

	mbedtls_ssl_config_init(&sctx->config);
//	mbedtls_entropy_init(&sctx->entropy);
//	mbedtls_ctr_drbg_init(&sctx->ctr_drbg);
	mbedtls_ssl_conf_rng(&sctx->config, mbedtls_ctr_drbg_random, &ctr_drbg);


	if ((ret = mbedtls_ssl_config_defaults(&sctx->config,
		MBEDTLS_SSL_IS_SERVER,
		MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
	{
		rb_lib_log("rb_init_ssl: unable to initialize default SSL parameters for server context: -0x%x", -ret);
		return 0;
	}

	mbedtls_ssl_conf_rng(&sctx->config, mbedtls_ctr_drbg_random, &ctr_drbg);


	if(cacert != NULL)
	{
        	mbedtls_x509_crt_init(&sctx->cacert);
        	ret = mbedtls_x509_crt_parse_file(&sctx->cacert, cacert);
        	if(ret != 0)
        	{
        		rb_lib_log("rb_setup_ssl_server: failed to parse CA certificate '%s': -0x%x", cert, -ret);
        		return 0;
        	}
	}
	
	mbedtls_x509_crt_init(&sctx->x509);
	ret = mbedtls_x509_crt_parse_file(&sctx->x509, cert);
	if (ret != 0)
	{
		rb_lib_log("rb_setup_ssl_server: failed to parse certificate '%s': -0x%x", cert, -ret);
		return 0;
	}

	mbedtls_pk_init(&sctx->serv_pk);
	ret = mbedtls_pk_parse_keyfile(&sctx->serv_pk, keyfile, NULL);
	if (ret != 0)
	{
		rb_lib_log("rb_setup_ssl_server: failed to parse private key '%s': -0x%x", keyfile, -ret);
		return 0;
	}

	mbedtls_dhm_init(&sctx->dh_params);
	ret = mbedtls_dhm_parse_dhmfile(&sctx->dh_params, dhfile);
	if (ret != 0)
	{
		rb_lib_log("rb_setup_ssl_server: failed to parse DH parameters '%s': -0x%x", dhfile, -ret);
		return 0;
	}

	ret = mbedtls_ssl_conf_dh_param_ctx(&sctx->config, &sctx->dh_params);
	if (ret != 0)
	{
		rb_lib_log("rb_setup_ssl_server: failed to set DH parameters on SSL config context: -0x%x", -ret);
		return 0;
	}

	if (&sctx->x509.next)
		mbedtls_ssl_conf_ca_chain(&sctx->config, sctx->x509.next, NULL);
	
	mbedtls_ssl_conf_ca_chain(&sctx->config, &sctx->cacert, NULL);

	if ((ret = mbedtls_ssl_conf_own_cert(&sctx->config, &sctx->x509, &sctx->serv_pk)) != 0)
	{
		rb_lib_log("rb_setup_ssl_server: failed to set up own certificate: -0x%x", -ret);
		return 0;
	}

	return sctx;
}

int
rb_ssl_listen(rb_fde_t *F, int backlog, bool defer_accept)
{
	int result;
	result = rb_listen(F, backlog, defer_accept);
	F->type = RB_FD_SOCKET | RB_FD_LISTEN | RB_FD_SSL;
	return result;
}

struct ssl_connect
{
	CNCB *callback;
	void *data;
	int timeout;
};

static void
rb_ssl_connect_realcb(rb_fde_t *F, int status, struct ssl_connect *sconn)
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
	struct ssl_connect *sconn = data;
	int ret;

	ret = do_ssl_handshake(F, rb_ssl_tryconn_cb, (void *)sconn);

	switch (ret)
	{
	case -1:
		rb_ssl_connect_realcb(F, RB_ERROR_SSL, sconn);
		break;
	case 0:
		/* do_ssl_handshake does the rb_setselect stuff */
		return;
	default:
		break;


	}
	rb_ssl_connect_realcb(F, RB_OK, sconn);
}

static void
rb_ssl_setup_client_context(rb_fde_t *F)
{
	int ret;

	mbedtls_ssl_init(SSL_P(ssl));
	if ((ret = mbedtls_ssl_setup(SSL_P(F), &F->sctx->config)) != 0)
	{
		rb_lib_log("rb_ssl_setup_client_context: failed to set up ssl context: -0x%x", -ret);
		rb_close(F);
		return;
	}

	mbedtls_ssl_set_bio(SSL_P(ssl), F, rb_ssl_write_cb, rb_ssl_read_cb, NULL);
}

static void
rb_ssl_tryconn(rb_fde_t *F, int status, void *data)
{
	struct ssl_connect *sconn = data;
	if(status != RB_OK)
	{
		rb_ssl_connect_realcb(F, status, sconn);
		return;
	}

	F->type |= RB_FD_SSL;


	rb_settimeout(F, sconn->timeout, rb_ssl_tryconn_timeout_cb, sconn);
	F->ssl = rb_malloc(sizeof(mbedtls_ssl_context));
	rb_ssl_setup_client_context(F);

	do_ssl_handshake(F, rb_ssl_tryconn_cb, (void *)sconn);
}

void
rb_connect_tcp_ssl(rb_fde_t *F, struct sockaddr *dest,
		   struct sockaddr *clocal, rb_socklen_t socklen, CNCB * callback, void *data, int timeout)
{
	struct ssl_connect *sconn;
	if(F == NULL)
		return;

	sconn = rb_malloc(sizeof(struct ssl_connect));
	sconn->data = data;
	sconn->callback = callback;
	sconn->timeout = timeout;
	rb_connect_tcp(F, dest, clocal, socklen, rb_ssl_tryconn, sconn, timeout);
}

void
rb_ssl_start_connected(rb_fde_t *F, CNCB * callback, void *data, int timeout)
{
	struct ssl_connect *sconn;
	if(F == NULL)
		return;

	sconn = rb_malloc(sizeof(struct ssl_connect));
	sconn->data = data;
	sconn->callback = callback;
	sconn->timeout = timeout;
	F->connect = rb_malloc(sizeof(struct conndata));
	F->connect->callback = callback;
	F->connect->data = data;
	F->type |= RB_FD_SSL;
	F->ssl = rb_malloc(sizeof(mbedtls_ssl_context));

	rb_ssl_setup_client_context(F);
	rb_settimeout(F, sconn->timeout, rb_ssl_tryconn_timeout_cb, sconn);

	do_ssl_handshake(F, rb_ssl_tryconn_cb, (void *)sconn);
}

int
rb_init_prng(const char *path, prng_seed_t seed_type)
{
	return 1;
}

int
rb_get_random(void *buf, size_t length)
{
	if (mbedtls_ctr_drbg_random(&ctr_drbg, buf, length))
		return 0;

	return 1;
}

int
rb_get_pseudo_random(void *buf, size_t length)
{
	return rb_get_random(buf, length);
}

const char *
rb_ssl_get_strerror(rb_fde_t *F)
{
#ifdef MBEDTLS_ERROR_C
	static char errbuf[512];
	mbedtls_strerror(F->sslerr.ssl_errno, errbuf, sizeof errbuf);
	return errbuf;
#else
	return "???";
#endif
}

int
rb_ssl_get_certfp(rb_fde_t *F, uint8_t certfp[RB_SSL_CERTFP_LEN])
{
	const mbedtls_x509_crt *peer_cert;
	uint8_t hash[RB_SSL_CERTFP_LEN];
	const mbedtls_md_info_t *md_info;
	int ret;

	peer_cert = mbedtls_ssl_get_peer_cert(SSL_P(F));
	if (peer_cert == NULL)
		return 0;

	md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (md_info == NULL)
		return 0;

	if ((ret = mbedtls_md(md_info, peer_cert->raw.p, peer_cert->raw.len, hash)) != 0)
	{
		rb_lib_log("rb_get_ssl_certfp: unable to get certfp for F: %p, %d", F, ret);
		return 0;
	}

	memcpy(certfp, hash, RB_SSL_CERTFP_LEN);

	return 1;
}

bool
rb_supports_ssl(void)
{
	return 1;
}

void
rb_get_ssl_info(char *buf, size_t len)
{
	char version_str[512];
	mbedtls_version_get_string(version_str);

	snprintf(buf, len, "MBEDTLS: compiled (%s), library(%s)",
		    MBEDTLS_VERSION_STRING, version_str);
}

const char *
rb_ssl_get_cipher(rb_fde_t *F)
{
	if(F == NULL || F->ssl == NULL)
		return NULL;
	return mbedtls_ssl_get_ciphersuite(SSL_P(F));
}


time_t rb_ssl_last_handshake(rb_fde_t *F)
{
	errno = ENOSYS;
	return -1;
}



#endif /* HAVE_GNUTLS */
