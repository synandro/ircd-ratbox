/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_kill.c: Kills a user.
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
#include "hash.h"
#include "ircd.h"
#include "numeric.h"
#include "s_log.h"
#include "s_conf.h"
#include "send.h"
#include "whowas.h"
#include "match.h"
#include "parse.h"
#include "modules.h"
#include "s_newconf.h"
#include "s_user.h"
#include "hook.h"

static int ms_kill(struct Client *, struct Client *, int, const char **);
static int mo_kill(struct Client *, struct Client *, int, const char **);
static void relay_kill(struct Client *, struct Client *, struct Client *,
		       const char *, const char *);

struct Message kill_msgtab = {
	.cmd = "KILL",
	.handlers[UNREGISTERED_HANDLER] =       { mm_unreg },
	.handlers[CLIENT_HANDLER] =             { mm_not_oper },
	.handlers[RCLIENT_HANDLER] =            { .handler = ms_kill, .min_para = 2 },
	.handlers[SERVER_HANDLER] =             { .handler = ms_kill, .min_para = 2 },
	.handlers[ENCAP_HANDLER] =              { mm_ignore },
	.handlers[OPER_HANDLER] =               { .handler = mo_kill, .min_para = 2 },
};

mapi_clist_av1 kill_clist[] = { &kill_msgtab, NULL };

DECLARE_MODULE_AV1(kill, NULL, NULL, kill_clist, NULL, NULL, "$Revision$");

/*
** mo_kill
**      parv[0] = sender prefix
**      parv[1] = kill victim
**      parv[2] = kill path
*/
static int
mo_kill(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;
	const char *inpath = client_p->name;
	const char *user;
	const char *reason;
	char buf[IRCD_BUFSIZE];

	user = parv[1];

	if(!IsOperLocalKill(source_p))
	{
		sendto_one_numeric(source_p, s_RPL(ERR_NOPRIVS), "local_kill");
		return 0;
	}

	if(!EmptyString(parv[2]))
	{
		reason = LOCAL_COPY_N(parv[2], KILLLEN);
	}
	else
		reason = "<No reason given>";

	if((target_p = find_named_person(user)) == NULL)
	{
		/*
		 ** If the user has recently changed nick, automatically
		 ** rewrite the KILL for this new nickname--this keeps
		 ** servers in synch when nick change and kill collide
		 */
		if((target_p = whowas_get_history(user, KILLCHASETIMELIMIT)) == NULL)
		{
			sendto_one_numeric(source_p, ERR_NOSUCHNICK,
					   form_str(ERR_NOSUCHNICK), user);
			return 0;
		}
		sendto_one_notice(source_p, ":KILL changed from %s to %s", user, target_p->name);
	}
	if(IsServer(target_p) || IsMe(target_p))
	{
		sendto_one_numeric(source_p, ERR_CANTKILLSERVER, form_str(ERR_CANTKILLSERVER));
		return 0;
	}

	if(!MyConnect(target_p) && (!IsOperGlobalKill(source_p)))
	{
		sendto_one_notice(source_p, ":Nick %s isnt on your server", target_p->name);
		return 0;
	}

        if(IsFake(target_p))
        {
                sendto_one(source_p, ":%s NOTICE %s :Cannot kill a service",
                                me.name, source_p->name);
             	return 0;
        }

	if(MyConnect(target_p))
		sendto_one(target_p, ":%s!%s@%s KILL %s :%s",
			   source_p->name, source_p->username, source_p->host,
			   target_p->name, reason);

	/* Do not change the format of this message.  There's no point in changing messages
	 * that have been around for ever, for no reason.. */
	sendto_realops_flags(UMODE_ALL, L_ALL,
			     "Received KILL message for %s. From %s Path: %s (%s)",
			     target_p->name, parv[0], me.name, reason);

	ilog(L_KILL, "%c %s %s!%s@%s %s %s",
	     MyConnect(target_p) ? 'L' : 'G', get_oper_name(source_p),
	     target_p->name, target_p->username, target_p->host, target_p->servptr->name, reason);

	/*
	 ** And pass on the message to other servers. Note, that if KILL
	 ** was changed, the message has to be sent to all links, also
	 ** back.
	 ** Suicide kills are NOT passed on --SRB
	 */
	if(!MyConnect(target_p))
	{
		relay_kill(client_p, source_p, target_p, inpath, reason);
		/*
		 ** Set FLAGS_KILLED. This prevents exit_one_client from sending
		 ** the unnecessary QUIT for this. (This flag should never be
		 ** set in any other place)
		 */
		target_p->flags |= FLAGS_KILLED;
	}

	snprintf(buf, sizeof(buf), "Killed (%s (%s))", source_p->name, reason);

	exit_client(client_p, target_p, source_p, buf);

	return 0;
}

/*
 * ms_kill
 *      parv[0] = sender prefix
 *      parv[1] = kill victim
 *      parv[2] = kill path and reason
 */
static int
ms_kill(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;
	const char *user;
	const char *reason;
	char default_reason[] = "<No reason given>";
	const char *path;
	char buf[IRCD_BUFSIZE];

	*buf = '\0';

	user = parv[1];

	if(EmptyString(parv[2]))
	{
		reason = default_reason;

		/* hyb6 takes the nick of the killer from the path *sigh* --fl_ */
		path = source_p->name;
	}
	else
	{
		char *s = LOCAL_COPY(parv[2]), *t;
		t = strchr(s, ' ');

		if(t)
		{
			*t = '\0';
			t++;
			reason = t;
		}
		else
			reason = default_reason;

		path = s;
	}

	if((target_p = find_person(user)) == NULL)
	{
		/*
		 * If the user has recently changed nick, but only if its 
		 * not an uid, automatically rewrite the KILL for this new nickname.
		 * --this keeps servers in synch when nick change and kill collide
		 */
		if(IsDigit(*user) || (!(target_p = whowas_get_history(user, KILLCHASETIMELIMIT))))
		{
			sendto_one_numeric(source_p, ERR_NOSUCHNICK,
					   form_str(ERR_NOSUCHNICK), IsDigit(*user) ? "*" : user);
			return 0;
		}
		sendto_one_notice(source_p, ":KILL changed from %s to %s", user, target_p->name);
	}
	
        if (IsFake(target_p))
        {
                /* fake client was killed, reintroduce */
                introduce_client(NULL, target_p);
                
                if (IsServer(source_p))
                        call_hook(h_service_skill, target_p);
                else
                        call_hook(h_service_kill, target_p);
                
                return 0;
        }

	if(MyConnect(target_p))
	{
		if(IsServer(source_p))
		{
			sendto_one(target_p, ":%s KILL %s :%s",
				   source_p->name, target_p->name, reason);
		}
		else
			sendto_one(target_p, ":%s!%s@%s KILL %s :%s",
				   source_p->name, source_p->username, source_p->host,
				   target_p->name, reason);
	}

	/* Be warned, this message must be From %s, or it confuses clients
	 * so dont change it to From: or the case or anything! -- fl -- db */
	/* path must contain at least 2 !'s, or bitchx falsely declares it
	 * local --fl
	 */
	if(IsOper(source_p))	/* send it normally */
	{
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Received KILL message for %s. From %s Path: %s!%s!%s!%s %s",
				     target_p->name, parv[0], source_p->servptr->name,
				     source_p->host, source_p->username, source_p->name, reason);

		ilog(L_KILL, "%c %s %s!%s@%s %s %s",
		     MyConnect(target_p) ? 'O' : 'R', get_oper_name(source_p),
		     target_p->name, target_p->username, target_p->host,
		     target_p->servptr->name, reason);
	}
	else
	{
		sendto_realops_flags(UMODE_SKILL, L_ALL,
				     "Received KILL message for %s. From %s %s",
				     target_p->name, parv[0], reason);

		ilog(L_KILL, "S %s %s!%s@%s %s %s",
		     source_p->name, target_p->name, target_p->username,
		     target_p->host, target_p->servptr->name, reason);
	}

	relay_kill(client_p, source_p, target_p, path, reason);

	/* FLAGS_KILLED prevents a quit being sent out */
	target_p->flags |= FLAGS_KILLED;

	snprintf(buf, sizeof(buf), "Killed (%s %s)", source_p->name, reason);

	exit_client(client_p, target_p, source_p, buf);

	return 0;
}

static void
relay_kill(struct Client *one, struct Client *source_p,
	   struct Client *target_p, const char *inpath, const char *reason)
{
	rb_dlink_node *ptr;
	char buffer[IRCD_BUFSIZE];

	if(MyClient(source_p))
		snprintf(buffer, sizeof(buffer),
			 "%s!%s!%s!%s (%s)",
			 me.name, source_p->host, source_p->username, source_p->name, reason);
	else
		snprintf(buffer, sizeof(buffer), "%s %s", inpath, reason);

	RB_DLINK_FOREACH(ptr, serv_list.head)
	{
		struct Client *client_p = ptr->data;

		if(!client_p || client_p == one)
			continue;

		sendto_one(client_p, ":%s KILL %s :%s",
			   get_id(source_p, client_p), get_id(target_p, client_p), buffer);
	}
}
