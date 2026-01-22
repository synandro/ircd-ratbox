/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_close.c: Closes all unregistered connections.
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
#include "parse.h"
#include "modules.h"

static int mo_close(struct Client *, struct Client *, int, const char **);

struct Message close_msgtab = {
	.cmd = "CLOSE",
	.handlers[UNREGISTERED_HANDLER] =	{ mm_unreg },			     
	.handlers[CLIENT_HANDLER] =		{ mm_not_oper },
	.handlers[RCLIENT_HANDLER] =		{ mm_ignore },
	.handlers[SERVER_HANDLER] =		{ mm_ignore },
	.handlers[ENCAP_HANDLER] =		{ mm_ignore },
	.handlers[OPER_HANDLER] =		{ .handler = mo_close },
};

mapi_clist_av1 close_clist[] = { &close_msgtab, NULL };

DECLARE_MODULE_AV1(close, NULL, NULL, close_clist, NULL, NULL, "$Revision$");

/*
 * mo_close - CLOSE message handler
 *  - added by Darren Reed Jul 13 1992.
 */
static int
mo_close(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	rb_dlink_node *ptr;
	rb_dlink_node *ptr_next;
	int closed = 0;

	RB_DLINK_FOREACH_SAFE(ptr, ptr_next, unknown_list.head)
	{
		struct Client *target_p = ptr->data;

		sendto_one_numeric(source_p, s_RPL(RPL_CLOSING),
			   get_client_name(target_p, SHOW_IP), target_p->status);

		exit_client(target_p, target_p, target_p, "Oper Closing");
		closed++;
	}

	sendto_one_numeric(source_p, s_RPL(RPL_CLOSEEND), closed);
	return 0;
}
