/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_whois.c: Shows who a user was.
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
#include "hash.h"
#include "whowas.h"
#include "client.h"
#include "match.h"
#include "ircd.h"
#include "numeric.h"
#include "send.h"
#include "s_conf.h"
#include "parse.h"
#include "modules.h"

static int m_whowas(struct Client *, struct Client *, int, const char **);

struct Message whowas_msgtab = {
	.cmd = "WHOWAS", 
	.handlers[UNREGISTERED_HANDLER] =	{ mm_unreg },
	.handlers[CLIENT_HANDLER] =		{ .handler = m_whowas, .min_para = 2 },
	.handlers[RCLIENT_HANDLER] =		{ mm_ignore },
	.handlers[SERVER_HANDLER] =		{ mm_ignore },
	.handlers[ENCAP_HANDLER] =		{ mm_ignore },
	.handlers[OPER_HANDLER] =		{ .handler = m_whowas, .min_para = 2 },
};

mapi_clist_av1 whowas_clist[] = { &whowas_msgtab, NULL };

DECLARE_MODULE_AV1(whowas, NULL, NULL, whowas_clist, NULL, NULL, "$Revision$");

/*
** m_whowas
**	parv[0] = sender prefix
**	parv[1] = nickname queried
*/
static int
m_whowas(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	int cur = 0;
	int max = -1;
	char *p;
	const char *nick;
	char tbuf[26];
	rb_dlink_list *whowas_list;
	rb_dlink_node *ptr;
	static time_t last_used = 0L;

	if(!IsOper(source_p))
	{
		if((last_used + ConfigFileEntry.pace_wait_simple) > rb_current_time())
		{
			sendto_one_numeric(source_p, s_RPL(RPL_LOAD2HI), "WHOWAS");
			sendto_one_numeric(source_p, s_RPL(RPL_ENDOFWHOWAS), parv[1]);
			return 0;
		}
		else
			last_used = rb_current_time();
	}


	if(parc > 2)
		max = atoi(parv[2]);

#if 0
	if(parc > 3)
		if(hunt_server(client_p, source_p, ":%s WHOWAS %s %s :%s", 3, parc, parv))
			return 0;
#endif

	if((p = strchr(parv[1], ',')))
		*p = '\0';

	nick = parv[1];


	whowas_list = whowas_get_list(nick);

	if(whowas_list == NULL)
	{
		sendto_one_numeric(source_p, s_RPL(ERR_WASNOSUCHNICK), nick);
		sendto_one_numeric(source_p, s_RPL(RPL_ENDOFWHOWAS), parv[1]);
		return 0;
	
	}
	
	RB_DLINK_FOREACH(ptr, whowas_list->head)
	{
		whowas_t *temp = ptr->data;

		sendto_one_numeric(source_p, s_RPL(RPL_WHOWASUSER), temp->name,
				   temp->username, temp->hostname, temp->realname);

		if(ConfigFileEntry.use_whois_actually && !EmptyString(temp->sockhost))
		{
			if(!temp->spoof
			   || (temp->spoof && !ConfigFileEntry.hide_spoof_ips
			       && MyOper(source_p)))
				sendto_one_numeric(source_p, s_RPL(RPL_WHOISACTUALLY),
						   temp->name, temp->sockhost);
		}

		sendto_one_numeric(source_p, s_RPL(RPL_WHOISSERVER),
					   temp->name, temp->servername,
					   rb_ctime(temp->logoff, tbuf, sizeof(tbuf)));
		
		cur++;
		if(max > 0 && cur >= max)
			break;
	}
	sendto_one_numeric(source_p, s_RPL(RPL_ENDOFWHOWAS), parv[1]);
	return 0;
}
