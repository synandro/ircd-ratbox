/*
 *  dns.c: An interface to the resolver daemon
 *  Copyright (C) 2005 Aaron Sethman <androsyn@ratbox.org>
 *  Copyright (C) 2005-2026 ircd-ratbox development team
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
#include "ratbox_lib.h"
#include "struct.h"
#include "ircd_defs.h"
#include "parse.h"
#include "dns.h"
#include "match.h"
#include "s_log.h"
#include "s_conf.h"
#include "client.h"
#include "send.h"
#include "numeric.h"


#define DNS_HOST	((char)'H')
#define DNS_REVERSE	((char)'I')

static void submit_dns(const char, uint32_t id, int aftype, const char *addr);
static int start_resolver(void);
static void parse_dns_reply(rb_helper * helper);
static void restart_resolver_cb(rb_helper * helper);

static rb_helper *dns_helper;

struct dnsreq
{
	rb_dlink_node node;
	DNSCB *callback;
	void *data;
	uint32_t id;
	uint32_t hashv;
};


#define RB_DNS_HASH_BITS 12
#define RB_DNS_HASH_SIZE (1UL << RB_DNS_HASH_BITS)
#define RB_DNS_HASH_MASK (RB_DNS_HASH_SIZE-1)


#define rb_hash_dns(x) (((unsigned long)x ^ ((unsigned long)x >> RB_DNS_HASH_BITS) ^ ((unsigned long)x >> (RB_DNS_HASH_BITS * 2))) & RB_DNS_HASH_MASK)


static rb_dlink_list query_hash[RB_DNS_HASH_SIZE];


static __rb_must_check struct dnsreq *
get_request_from_id(uint32_t id)
{
	struct dnsreq *req;
        rb_dlink_list *hlist;
        rb_dlink_node *ptr;

        hlist = &query_hash[rb_hash_dns(id)];

        if(hlist->head == NULL)
                return NULL;

        RB_DLINK_FOREACH(ptr, hlist->head)
        {
                req = ptr->data;
                if(req->id == id)
                        return req;
        }
        return NULL;
}



static struct dnsreq *
allocate_dns_request(DNSCB *cb, void *data)
{
	struct dnsreq *req;
	static uint32_t id = 0;

	id++;
	if(id == 0)
		id++;
	
	req = rb_malloc(sizeof(struct dnsreq));
	req->id = id;
	req->hashv = rb_hash_dns(id);
	req->callback = cb;
	req->data = data;	
	rb_dlinkAdd(req, &req->node, &query_hash[req->hashv]);
	return req;
}


static inline void
check_resolver(void)
{
	if(dns_helper == NULL)
		restart_resolver();
}

static void
failed_resolver(uint32_t xid)
{
	struct dnsreq *req;
	DNSCB *cb;
	void *data;
	uint32_t hashv;

	req = get_request_from_id(xid);

	if(req == NULL)
		return;

	cb = req->callback;
	data = req->data;
	hashv = req->hashv;	
	
	rb_dlinkDelete(&req->node, &query_hash[hashv]);
	rb_free(req);

	if(cb != NULL)
		cb("FAILED", 0, 0, data);
	
}

void
cancel_lookup(uint32_t xid)
{
	struct dnsreq *req;
	req = get_request_from_id(xid);
	if(req == NULL)
		return;
	rb_dlinkDelete(&req->node, &query_hash[req->hashv]);
	rb_free(req);
}

uint32_t
lookup_hostname(const char *hostname, int aftype, DNSCB * callback, void *data)
{
	struct dnsreq *req;
	int aft;
	check_resolver();

	req = allocate_dns_request(callback, data);

#ifdef RB_IPV6
	if(aftype == AF_INET6)
		aft = 6;
	else
#endif
		aft = 4;

	submit_dns(DNS_HOST, req->id, aft, hostname);
	return (req->id);
}

uint32_t
lookup_ip(const char *addr, int aftype, DNSCB * callback, void *data)
{
	struct dnsreq *req;
	int aft;
	check_resolver();

	req = allocate_dns_request(callback, data);

#ifdef RB_IPV6
	if(aftype == AF_INET6)
		aft = 6;
	else
#endif
		aft = 4;

	submit_dns(DNS_REVERSE, req->id, aft, addr);
	return (req->id);
}

static void
results_callback(const char *callid, const char *status, const char *aftype, const char *results)
{
	DNSCB *cb;
	void *data;
	struct dnsreq *req;
	uint32_t nid;
	int st;
	int aft;

	nid = strtoul(callid, 0, 16);

	req = get_request_from_id(nid);
	if(req == NULL)
		return;
		
	st = atoi(status);
	aft = atoi(aftype);

#ifdef RB_IPV6
	if(aft == 6)
		aft = AF_INET6;
	else
#endif
		aft = AF_INET;
	
	cb = req->callback;
	data = req->data;

	rb_dlinkDelete(&req->node, &query_hash[req->hashv]);
	rb_free(req);

	if(cb != NULL)
		cb(results, st, aft, data);
}


static char *resolver_path;

static int
start_resolver(void)
{
	char fullpath[PATH_MAX + 1];

	if(resolver_path == NULL)
	{
		snprintf(fullpath, sizeof(fullpath), "%s/resolver", LIBEXEC_DIR);

		if(access(fullpath, X_OK) == -1)
		{
			snprintf(fullpath, sizeof(fullpath), "%s/libexec/ircd-ratbox/resolver",
				 ConfigFileEntry.dpath);
			if(access(fullpath, X_OK) == -1)
			{
				ilog(L_MAIN,
				     "Unable to execute resolver in %s or %s/libexec/ircd-ratbox",
				     LIBEXEC_DIR, ConfigFileEntry.dpath);
				sendto_realops_flags(UMODE_ALL, L_ALL,
						     "Unable to execute resolver in %s or %s/libexec/ircd-ratbox",
						     LIBEXEC_DIR, ConfigFileEntry.dpath);
				return 1;
			}

		}

		resolver_path = rb_strdup(fullpath);
	}

	dns_helper = rb_helper_start("ircd-ratbox resolver daemon", resolver_path, parse_dns_reply, restart_resolver_cb);

	if(dns_helper == NULL)
	{
		ilog(L_MAIN, "Unable to start resolver helper: %s", strerror(errno));
		sendto_realops_flags(UMODE_ALL, L_ALL, "Unable to start resolver helper: %s", strerror(errno));
		return 1;
	}
	ilog(L_MAIN, "resolver helper started");
	sendto_realops_flags(UMODE_ALL, L_ALL, "resolver helper started");
	rb_helper_run(dns_helper);
	return 0;
}

static rb_dlink_list nameservers;

static void
parse_nameservers(char **parv, int parc)
{
	rb_dlink_node *ptr, *next;
	char *server;
	int i;

	RB_DLINK_FOREACH_SAFE(ptr, next, nameservers.head)
	{
		rb_free(ptr->data);
		rb_dlinkDestroy(ptr, &nameservers);
	}

	for(i = 2; i < parc; i++)
	{
		server = rb_strdup(parv[i]);
		rb_dlinkAddTailAlloc(server, &nameservers);
	}
}

void
report_dns_servers(struct Client *source_p)
{
	rb_dlink_node *ptr;
	RB_DLINK_FOREACH(ptr, nameservers.head)
	{
		sendto_one_numeric(source_p, RPL_STATSDEBUG, "A %s", (char *)ptr->data);
	}
}


static void
parse_dns_reply(rb_helper * helper)
{
	ssize_t len;
	int parc;
	char dnsBuf[READBUF_SIZE];

	char *parv[MAXPARA + 1];
	while((len = rb_helper_read(helper, dnsBuf, sizeof(dnsBuf))) > 0)
	{
		parc = rb_string_to_array(dnsBuf, parv, MAXPARA+1); 

		if(parc == 0 || parv[0] == NULL)
			continue;

		if(*parv[0] == 'R')
		{
			if(parc != 5)
			{
				ilog(L_MAIN, "Resolver sent a result with wrong number of arguments: got %d", parc);
				restart_resolver();
				return;
			}
			results_callback(parv[1], parv[2], parv[3], parv[4]);
		}
		else if(*parv[0] == 'A')
		{
			parse_nameservers(parv, parc);
		}
		else
		{
			ilog(L_MAIN, "Resolver sent an unknown command..restarting resolver");
			restart_resolver();
			return;
		}
	}
}

static void
submit_dns(char type, uint32_t nid, int aftype, const char *addr)
{
	if(dns_helper == NULL)
	{
		failed_resolver(nid);
		return;
	}
	rb_helper_write(dns_helper, "%c %x %d %s", type, nid, aftype, addr);
}

void
rehash_dns_vhost(void)
{
	const char *v6 = "0";
	const char *v4 = "0";
#ifdef RB_IPV6
	if(!EmptyString(ServerInfo.vhost6_dns))
		v6 = ServerInfo.vhost6_dns;
#endif
	if(!EmptyString(ServerInfo.vhost_dns))
		v4 = ServerInfo.vhost_dns;
	rb_helper_write(dns_helper, "B 0 %s %s", v4, v6);
}

void
init_resolver(void)
{
	if(start_resolver())
	{
		ilog(L_MAIN, "Unable to start resolver helper: %s", strerror(errno));
		exit(0);
	}
}


static void
restart_resolver_cb(rb_helper * helper)
{
	ilog(L_MAIN, "resolver - restart_resolver_cb called, resolver helper died?");
	sendto_realops_flags(UMODE_ALL, L_ALL, "resolver - restart_resolver_cb called, resolver helper died?");
	if(helper != NULL)
	{
		rb_helper_close(helper);
		dns_helper = NULL;
	}
	start_resolver();
	rehash_dns_vhost();
}

void
restart_resolver(void)
{
	restart_resolver_cb(dns_helper);
}

void
rehash_resolver(void)
{
	rb_helper_write(dns_helper, "R");
}
