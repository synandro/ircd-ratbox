/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_admin.c: Sends administrative information to a user.
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
#include "s_conf.h"
#include "s_serv.h"
#include "send.h"
#include "parse.h"
#include "hook.h"
#include "modules.h"
#include "match.h"

static int m_admin(struct Client *, struct Client *, int, const char **);
static int mr_admin(struct Client *, struct Client *, int, const char **);
static int ms_admin(struct Client *, struct Client *, int, const char **);
static void do_admin(struct Client *source_p);

static void admin_spy(struct Client *);

struct Message admin_msgtab = {
	.cmd = "ADMIN", 
	.handlers[UNREGISTERED_HANDLER] =	{ .handler = mr_admin},
	.handlers[CLIENT_HANDLER] =		{ .handler = m_admin },
	.handlers[RCLIENT_HANDLER] =		{ .handler = ms_admin },
	.handlers[SERVER_HANDLER] =		{  mm_ignore },
	.handlers[ENCAP_HANDLER] =		{  mm_ignore },
	.handlers[OPER_HANDLER] =		{ .handler = ms_admin },
};

int doing_admin_hook;

mapi_clist_av1 admin_clist[] = { &admin_msgtab, NULL };

mapi_hlist_av1 admin_hlist[] = {
	{"doing_admin", &doing_admin_hook},
	{NULL, NULL}
};

DECLARE_MODULE_AV1(admin, NULL, NULL, admin_clist, admin_hlist, NULL, "$Revision$");

/*
 * mr_admin - ADMIN command handler
 *	parv[0] = sender prefix	  
 *	parv[1] = servername   
 */
static int
mr_admin(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	static time_t last_used = 0L;

	if((last_used + ConfigFileEntry.pace_wait) > rb_current_time())
	{
		sendto_one_numeric(source_p, s_RPL(RPL_LOAD2HI), "ADMIN");
		return 0;
	}
	else
		last_used = rb_current_time();

	do_admin(source_p);

	return 0;
}

/*
 * m_admin - ADMIN command handler
 *	parv[0] = sender prefix
 *	parv[1] = servername
 */
static int
m_admin(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	static time_t last_used = 0L;

	if(parc > 1)
	{
		if((last_used + ConfigFileEntry.pace_wait) > rb_current_time())
		{
			sendto_one_numeric(source_p, s_RPL(RPL_LOAD2HI), "ADMIN");
			return 0;
		}
		else
			last_used = rb_current_time();

		if(hunt_server(client_p, source_p, ":%s ADMIN :%s", 1, parc, parv) != HUNTED_ISME)
			return 0;
	}

	do_admin(source_p);

	return 0;
}


/*
 * ms_admin - ADMIN command handler, used for OPERS as well
 *	parv[0] = sender prefix
 *	parv[1] = servername
 */
static int
ms_admin(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	if(hunt_server(client_p, source_p, ":%s ADMIN :%s", 1, parc, parv) != HUNTED_ISME)
		return 0;

	do_admin(source_p);

	return 0;
}


/*
 * do_admin
 *
 * inputs	- pointer to client to report to
 * output	- none
 * side effects	- admin info is sent to client given
 */
static void
do_admin(struct Client *source_p)
{
	if(IsClient(source_p))
		admin_spy(source_p);

	SetCork(source_p);
	sendto_one_numeric(source_p, s_RPL(RPL_ADMINME), me.name);
	if(AdminInfo.name != NULL)
		sendto_one_numeric(source_p, s_RPL(RPL_ADMINLOC1), AdminInfo.name);
	if(AdminInfo.description != NULL)
		sendto_one_numeric(source_p, s_RPL(RPL_ADMINLOC2), AdminInfo.description);
	if(AdminInfo.email != NULL)
		sendto_one_numeric(source_p, s_RPL(RPL_ADMINEMAIL), AdminInfo.email);
	ClearCork(source_p);
	send_pop_queue(source_p);
}

/* admin_spy()
 *
 * input	- pointer to client
 * output	- none
 * side effects - event doing_admin is called
 */
static void
admin_spy(struct Client *source_p)
{
	hook_data hd;

	hd.client = source_p;
	hd.arg1 = hd.arg2 = NULL;

	call_hook(doing_admin_hook, &hd);
}
