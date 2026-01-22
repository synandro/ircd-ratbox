/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_links.c: Shows what servers are currently connected.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2026 ircd-ratbox development team
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
#include "struct.h"
#include "client.h"
#include "match.h"
#include "ircd.h"
#include "numeric.h"
#include "s_serv.h"
#include "send.h"
#include "s_conf.h"
#include "parse.h"
#include "hook.h"
#include "modules.h"
#include "cache.h"
#include "s_log.h"


static int m_links(struct Client *, struct Client *, int, const char **);
static int mo_links(struct Client *, struct Client *, int, const char **);
static char *clean_string(char *dest, const unsigned char *src, size_t len);

struct Message links_msgtab = {
	.cmd = "LINKS", 

	.handlers[UNREGISTERED_HANDLER] =	{ mm_unreg },
	.handlers[CLIENT_HANDLER] =		{ .handler = m_links },
	.handlers[RCLIENT_HANDLER] =		{ .handler = mo_links },
	.handlers[SERVER_HANDLER] =		{  mm_ignore },
	.handlers[ENCAP_HANDLER] =		{  mm_ignore },
	.handlers[OPER_HANDLER] =		{ .handler = mo_links },
};

int doing_links_hook;

mapi_clist_av1 links_clist[] = { &links_msgtab, NULL };

mapi_hlist_av1 links_hlist[] = {
	{"doing_links", &doing_links_hook},
	{NULL, NULL}
};

DECLARE_MODULE_AV1(links, NULL, NULL, links_clist, links_hlist, NULL, "$Revision$");

/*
 * m_links - LINKS message handler
 *	parv[0] = sender prefix
 *	parv[1] = servername mask
 * or
 *	parv[0] = sender prefix
 *	parv[1] = server to query 
 *	parv[2] = servername mask
 */
static int
m_links(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	if(ConfigServerHide.flatten_links && !IsExemptShide(source_p))
		send_links_cache(source_p);
	else
		mo_links(client_p, source_p, parc, parv);

	return 0;
}

static int
mo_links(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	const char *mask = "";
	char clean_mask[2 * HOSTLEN + 4];
	hook_data hd;

	rb_dlink_node *ptr;

	if(parc > 2)
	{
		if(strlen(parv[2]) > HOSTLEN)
			return 0;
		if(hunt_server(client_p, source_p, ":%s LINKS %s :%s", 1, parc, parv)
		   != HUNTED_ISME)
			return 0;

		mask = parv[2];
	}
	else if(parc == 2)
		mask = parv[1];

	if(*mask)		/* only necessary if there is a mask */
		mask = collapse(clean_string
				(clean_mask, (const unsigned char *) mask, 2 * HOSTLEN));

	hd.client = source_p;
	hd.arg1 = mask;
	hd.arg2 = NULL;

	call_hook(doing_links_hook, &hd);
	SetCork(source_p);
	RB_DLINK_FOREACH(ptr, global_serv_list.head)
	{
		struct Client *target_p = ptr->data;

		if(*mask && !match(mask, target_p->name))
			continue;

		/* We just send the reply, as if theyre here theres either no SHIDE,
		 * or theyre an oper..	
		 */
		sendto_one_numeric(source_p, s_RPL(RPL_LINKS),
				   target_p->name, target_p->servptr->name,
				   target_p->hopcount,
				   target_p->info[0] ? target_p->info : "(Unknown Location)");
	}
	ClearCork(source_p);
	sendto_one_numeric(source_p, s_RPL(RPL_ENDOFLINKS), EmptyString(mask) ? "*" : mask);

	return 0;
}

static char *
clean_string(char *dest, const unsigned char *src, size_t len)
{
	char *d = dest;
	s_assert(NULL != dest);
	s_assert(NULL != src);

	if(dest == NULL || src == NULL)
		return NULL;

	while(*src && (len > 1))
	{
		if(*src & 0x80)	/* if high bit is set */
		{
			*d++ = '.';
			--len;
			if(len <= 1)
				break;
		}
		else if(!IsPrint(*src))	/* if NOT printable */
		{
			*d++ = '^';
			--len;
			if(len <= 1)
				break;
			*d++ = 0x40 + *src;	/* turn it into a printable */
		}
		else
			*d++ = *src;
		++src;
		--len;
	}
	*d = '\0';
	return dest;
}
