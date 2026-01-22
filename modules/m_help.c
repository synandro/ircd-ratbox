/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_help.c: Provides help information to a user/operator.
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
#include "ircd.h"
#include "numeric.h"
#include "send.h"
#include "s_conf.h"
#include "parse.h"
#include "modules.h"
#include "hash.h"
#include "cache.h"
#include "match.h"
#include "client.h"

static int m_help(struct Client *, struct Client *, int, const char **);
static int mo_help(struct Client *, struct Client *, int, const char **);
static int mo_uhelp(struct Client *, struct Client *, int, const char **);
static void dohelp(struct Client *, int, const char *);

struct Message help_msgtab = {
	.cmd = "HELP",

	.handlers[UNREGISTERED_HANDLER] =	{ mm_unreg },
	.handlers[CLIENT_HANDLER] =		{ .handler = m_help },
	.handlers[RCLIENT_HANDLER] =		{ mm_ignore },	
	.handlers[SERVER_HANDLER] =		{ mm_ignore },	
	.handlers[ENCAP_HANDLER] =		{ mm_ignore },	
	.handlers[OPER_HANDLER] =		{ .handler = mo_help },
};

struct Message uhelp_msgtab = {
	.cmd = "UHELP",

	.handlers[UNREGISTERED_HANDLER] =	{ mm_unreg },
	.handlers[CLIENT_HANDLER] =		{ .handler = m_help },
	.handlers[RCLIENT_HANDLER] =		{ mm_ignore },	
	.handlers[SERVER_HANDLER] =		{ mm_ignore },	
	.handlers[ENCAP_HANDLER] =		{ mm_ignore },	
	.handlers[OPER_HANDLER] =		{ .handler = mo_uhelp },
};

mapi_clist_av1 help_clist[] = { &help_msgtab, &uhelp_msgtab, NULL };

DECLARE_MODULE_AV1(help, NULL, NULL, help_clist, NULL, NULL, "$Revision$");

/*
 * m_help - HELP message handler
 *	parv[0] = sender prefix
 */
static int
m_help(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	static time_t last_used = 0;

	/* HELP is always local */
	if((last_used + ConfigFileEntry.pace_wait_simple) > rb_current_time())
	{
		/* safe enough to give this on a local connect only */
		sendto_one_numeric(source_p, s_RPL(RPL_LOAD2HI), "HELP");
		sendto_one_numeric(source_p, s_RPL(RPL_ENDOFHELP), "index");
		return 0;
	}
	else
	{
		last_used = rb_current_time();
	}

	dohelp(source_p, HELP_USER, parc > 1 ? parv[1] : NULL);

	return 0;
}

/*
 * mo_help - HELP message handler
 *	parv[0] = sender prefix
 */
static int
mo_help(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	dohelp(source_p, HELP_OPER, parc > 1 ? parv[1] : NULL);
	return 0;
}

/*
 * mo_uhelp - HELP message handler
 * This is used so that opers can view the user help file without deopering
 *	parv[0] = sender prefix
 */
static int
mo_uhelp(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	dohelp(source_p, HELP_USER, parc > 1 ? parv[1] : NULL);
	return 0;
}

static void
dohelp(struct Client *source_p, int flags, const char *topic)
{
	static const char ntopic[] = "index";
	struct cachefile *hptr;
	struct cacheline *lineptr;
	rb_dlink_node *ptr;
	rb_dlink_node *fptr;
	hash_f *htype = HASH_HELP; 
	if(EmptyString(topic))
		topic = ntopic;

	if(flags & HELP_OPER)
		htype = HASH_OHELP;

	hptr = hash_find_data(htype, topic);

	if(hptr == NULL)
	{
		sendto_one_numeric(source_p, s_RPL(ERR_HELPNOTFOUND), topic);
		return;
	}

	fptr = hptr->contents.head;
	lineptr = fptr->data;
	SetCork(source_p);

	/* first line cant be empty */
	sendto_one_numeric(source_p, s_RPL(RPL_HELPSTART), topic, lineptr->data);

	RB_DLINK_FOREACH(ptr, fptr->next)
	{
		lineptr = ptr->data;
		sendto_one_numeric(source_p, s_RPL(RPL_HELPTXT), topic, lineptr->data);
	}
	ClearCork(source_p);
	sendto_one_numeric(source_p, s_RPL(RPL_ENDOFHELP), topic);
}
