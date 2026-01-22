/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_userhost.c: Shows a user's host.
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
#include "ircd.h"
#include "numeric.h"
#include "send.h"
#include "match.h"
#include "parse.h"
#include "modules.h"

static int m_userhost(struct Client *, struct Client *, int, const char **);

struct Message userhost_msgtab = {
	.cmd = "USERHOST",
	.handlers[UNREGISTERED_HANDLER] =	{ mm_unreg },
	.handlers[CLIENT_HANDLER] =		{ .handler = m_userhost, .min_para = 2 },
	.handlers[RCLIENT_HANDLER] =		{ mm_ignore },
	.handlers[SERVER_HANDLER] =		{ mm_ignore },
	.handlers[ENCAP_HANDLER] =		{ mm_ignore },
	.handlers[OPER_HANDLER] =		{ .handler = m_userhost, .min_para = 2 },
};

mapi_clist_av1 userhost_clist[] = { &userhost_msgtab, NULL };

DECLARE_MODULE_AV1(userhost, NULL, NULL, userhost_clist, NULL, NULL, "$Revision$");

/*
 * m_userhost added by Darren Reed 13/8/91 to aid clients and reduce
 * the need for complicated requests like WHOIS. It returns user/host
 * information only (no spurious AWAY labels or channels).
 */
static int
m_userhost(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;
	char response[IRCD_BUFSIZE];
	int i;

	memset(response, 0, sizeof(response));

	/* XXX why 5 here? */
	for(i = 1; i <= 5; i++)
	{
		if(parc < i + 1)
			break;

		if((target_p = find_person(parv[i])) != NULL)
		{
			/*
			 * Show real IP for USERHOST on yourself.
			 * This is needed for things like mIRC, which do a server-based
			 * lookup (USERHOST) to figure out what the clients' local IP
			 * is.	Useful for things like NAT, and dynamic dial-up users.
			 */
			if(MyClient(target_p) && (target_p == source_p))
			{
				rb_snprintf_append(response, sizeof(response), "%s%s=%c%s@%s ",
						   target_p->name,
						   IsOper(target_p) ? "*" : "",
						   (target_p->user->away) ? '-' : '+',
						   target_p->username, target_p->sockhost);
			}
			else
			{
				rb_snprintf_append(response, sizeof(response), "%s%s=%c%s@%s ",
						   target_p->name,
						   IsOper(target_p) ? "*" : "",
						   (target_p->user->away) ? '-' : '+',
						   target_p->username, target_p->host);
			}

		}
	}
	sendto_one_numeric(source_p, s_RPL(RPL_USERHOST), response);
	return 0;
}
