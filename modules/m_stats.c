/*
 *  ircd-ratbox: an advanced Internet Relay Chat Daemon(ircd).
 *  m_stats.c: Sends the user statistics or config information.
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
#include "ratbox_lib.h"
#include "class.h"
#include "client.h"
#include "channel.h"
#include "match.h"
#include "ircd.h"
#include "listener.h"
#include "s_gline.h"
#include "hostmask.h"
#include "numeric.h"
#include "send.h"
#include "s_conf.h"
#include "s_serv.h"
#include "s_stats.h"
#include "s_user.h"
#include "parse.h"
#include "hook.h"
#include "modules.h"
#include "s_newconf.h"
#include "hash.h"
#include "dns.h"
#include "reject.h"
#include "whowas.h"
#include "operhash.h"
#include "scache.h"
#include "s_log.h"

#ifdef HAVE_STRUCT_MALLINFO
#include <malloc.h>
#endif


static int m_stats(struct Client *, struct Client *, int, const char **);

struct Message stats_msgtab = {
	.cmd = "STATS", 
	.handlers[UNREGISTERED_HANDLER] =	{ mm_unreg },			     
	.handlers[CLIENT_HANDLER] =		{ .handler = m_stats, .min_para = 2 },
	.handlers[RCLIENT_HANDLER] =		{ .handler = m_stats, .min_para = 3 },
	.handlers[SERVER_HANDLER] =		{ mm_ignore },
	.handlers[ENCAP_HANDLER] =		{ mm_ignore },
	.handlers[OPER_HANDLER] =		{ .handler = m_stats, .min_para = 2 },
};

int doing_stats_hook;
int doing_stats_p_hook;

mapi_clist_av1 stats_clist[] = { &stats_msgtab, NULL };

mapi_hlist_av1 stats_hlist[] = {
	{"doing_stats", &doing_stats_hook},
	{"doing_stats_p", &doing_stats_p_hook},
	{NULL, NULL}
};

DECLARE_MODULE_AV1(stats, NULL, NULL, stats_clist, stats_hlist, NULL, "$Revision$");


static void stats_l_list(struct Client *s, const char *, int, int, rb_dlink_list *, char);
static void stats_l_client(struct Client *source_p, struct Client *target_p, char statchar);

static void stats_spy(struct Client *, char, const char *);
static void stats_p_spy(struct Client *);

/* Heres our struct for the stats table */
struct StatsStruct
{
	char letter;
	void (*handler) ();
	int need_oper;
	int need_admin;
};

static void stats_dns_servers(struct Client *);
static void stats_delay(struct Client *);
static void stats_hash(struct Client *);
static void stats_connect(struct Client *);
static void stats_tdeny(struct Client *);
static void stats_deny(struct Client *);
static void stats_exempt(struct Client *);
static void stats_events(struct Client *);
static void stats_glines(struct Client *);
static void stats_pending_glines(struct Client *);
static void stats_hubleaf(struct Client *);
static void stats_auth(struct Client *);
static void stats_tklines(struct Client *);
static void stats_klines(struct Client *);
static void stats_messages(struct Client *);
static void stats_oper(struct Client *);
static void stats_operedup(struct Client *);
static void stats_ports(struct Client *);
static void stats_tresv(struct Client *);
static void stats_resv(struct Client *);
static void stats_usage(struct Client *);
static void stats_tstats(struct Client *);
static void stats_uptime(struct Client *);
static void stats_shared(struct Client *);
static void stats_servers(struct Client *);
static void stats_tgecos(struct Client *);
static void stats_gecos(struct Client *);
static void stats_class(struct Client *);
static void stats_memory(struct Client *);
static void stats_servlinks(struct Client *);
static void stats_ltrace(struct Client *, int, const char **);
static void stats_ziplinks(struct Client *);
static void stats_comm(struct Client *);
/* This table contains the possible stats items, in order:
 * stats letter,  function to call, operonly? adminonly?
 * case only matters in the stats letter column.. -- fl_
 */
static struct StatsStruct stats_cmd_table[] = {
	/* letter     function	      need_oper need_admin */
	{'a', stats_dns_servers, 1, 1,},
	{'A', stats_dns_servers, 1, 1,},
	{'b', stats_delay, 1, 1,},
	{'B', stats_hash, 1, 1,},
	{'c', stats_connect, 0, 0,},
	{'C', stats_connect, 0, 0,},
	{'d', stats_tdeny, 1, 0,},
	{'D', stats_deny, 1, 0,},
	{'e', stats_exempt, 1, 0,},
	{'E', stats_events, 1, 1,},
	{'f', stats_comm, 1, 1,},
	{'F', stats_comm, 1, 1,},
	{'g', stats_pending_glines, 1, 0,},
	{'G', stats_glines, 1, 0,},
	{'h', stats_hubleaf, 0, 0,},
	{'H', stats_hubleaf, 0, 0,},
	{'i', stats_auth, 0, 0,},
	{'I', stats_auth, 0, 0,},
	{'k', stats_tklines, 0, 0,},
	{'K', stats_klines, 0, 0,},
	{'l', stats_ltrace, 0, 0,},
	{'L', stats_ltrace, 0, 0,},
	{'m', stats_messages, 0, 0,},
	{'M', stats_messages, 0, 0,},
	{'o', stats_oper, 0, 0,},
	{'O', stats_oper, 0, 0,},
	{'p', stats_operedup, 0, 0,},
	{'P', stats_ports, 0, 0,},
	{'q', stats_tresv, 1, 0,},
	{'Q', stats_resv, 1, 0,},
	{'r', stats_usage, 1, 0,},
	{'R', stats_usage, 1, 0,},
	{'t', stats_tstats, 1, 0,},
	{'T', stats_tstats, 1, 0,},
	{'u', stats_uptime, 0, 0,},
	{'U', stats_shared, 1, 0,},
	{'v', stats_servers, 0, 0,},
	{'V', stats_servers, 0, 0,},
	{'x', stats_tgecos, 1, 0,},
	{'X', stats_gecos, 1, 0,},
	{'y', stats_class, 0, 0,},
	{'Y', stats_class, 0, 0,},
	{'z', stats_memory, 1, 0,},
	{'Z', stats_ziplinks, 1, 0,},
	{'?', stats_servlinks, 0, 0,},
	{(char) 0, (void (*)()) 0, 0, 0,}
};

/*
 * m_stats by fl_
 *	parv[0] = sender prefix
 *	parv[1] = stat letter/command
 *	parv[2] = (if present) server/mask in stats L, or target
 *
 * This will search the tables for the appropriate stats letter,
 * if found execute it.	 
 */
static int
m_stats(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	static time_t last_used = 0;
	int i;
	char statchar;

	statchar = parv[1][0];

	if(MyClient(source_p) && !IsOper(source_p))
	{
		/* Check the user is actually allowed to do /stats, and isnt flooding */
		if((last_used + ConfigFileEntry.pace_wait) > rb_current_time())
		{
			/* safe enough to give this on a local connect only */
			sendto_one_numeric(source_p, s_RPL(RPL_LOAD2HI), "STATS");
			sendto_one_numeric(source_p, RPL_ENDOFSTATS,
					   form_str(RPL_ENDOFSTATS), statchar);
			return 0;
		}
		else
			last_used = rb_current_time();
	}

	if(hunt_server(client_p, source_p, ":%s STATS %s :%s", 2, parc, parv) != HUNTED_ISME)
		return 0;

	if((statchar != 'L') && (statchar != 'l'))
		stats_spy(source_p, statchar, NULL);

	for(i = 0; stats_cmd_table[i].handler; i++)
	{
		if(stats_cmd_table[i].letter == statchar)
		{
			/* The stats table says what privs are needed, so check --fl_ */
			/* Called for remote clients and for local opers, so check need_admin
			 * and need_oper
			 */
			if((stats_cmd_table[i].need_admin && !IsOperAdmin(source_p)) ||
			   (stats_cmd_table[i].need_oper && !IsOper(source_p)))
			{
				sendto_one_numeric(source_p, ERR_NOPRIVILEGES,
						   form_str(ERR_NOPRIVILEGES));
				break;
			}
			SetCork(source_p);
			/* Blah, stats L needs the parameters, none of the others do.. */
			if(statchar == 'L' || statchar == 'l')
				stats_cmd_table[i].handler(source_p, parc, parv);
			else
				stats_cmd_table[i].handler(source_p);
			ClearCork(source_p);

		}
	}

	/* Send the end of stats notice */
	sendto_one_numeric(source_p, s_RPL(RPL_ENDOFSTATS), statchar);

	return 0;
}

static void
stats_dns_servers(struct Client *source_p)
{
	report_dns_servers(source_p);
}

static void
stats_delay(struct Client *source_p)
{
	list_nd_entries(source_p);
}

static void
stats_hash(struct Client *source_p)
{
	hash_stats(source_p);
}

static void
stats_connect(struct Client *source_p)
{
	char buf[5];
	char *s;
	rb_dlink_node *ptr;

	if((ConfigFileEntry.stats_c_oper_only ||
	    (ConfigServerHide.flatten_links && !IsExemptShide(source_p))) && !IsOper(source_p))
	{
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));
		return;
	}

	RB_DLINK_FOREACH(ptr, server_conf_list.head)
	{
		struct server_conf *server_p = ptr->data;

		if(ServerConfIllegal(server_p))
			continue;

		buf[0] = '\0';
		s = buf;

		if(IsOper(source_p))
		{
			if(ServerConfAutoconn(server_p))
				*s++ = 'A';
			if(ServerConfSSL(server_p))
				*s++ = 'S';
			if(ServerConfTb(server_p))
				*s++ = 'T';
			if(ServerConfCompressed(server_p))
				*s++ = 'Z';
		}

		if(!buf[0])
			*s++ = '*';

		*s = '\0';

		sendto_one_numeric(source_p, RPL_STATSCLINE,
				   form_str(RPL_STATSCLINE),
				   "*@127.0.0.1", buf, server_p->name,
				   server_p->port, server_p->class_name);
	}
}

/* stats_tdeny()
 *
 * input	- client to report to
 * output	- none
 * side effects - client is given temp dline list.
 */
static void
stats_tdeny(struct Client *source_p)
{
	report_tdlines(source_p);
}

/* stats_deny()
 *
 * input	- client to report to
 * output	- none
 * side effects - client is given dline list.
 */
static void
stats_deny(struct Client *source_p)
{
	report_dlines(source_p);
}


/* stats_exempt()
 *
 * input	- client to report to
 * output	- none
 * side effects - client is given list of exempt blocks
 */
static void
stats_exempt(struct Client *source_p)
{
	if(ConfigFileEntry.stats_e_disabled)
	{
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));
		return;
	}

	report_elines(source_p);
}

static void
stats_events_cb(char *str, void *ptr)
{
	sendto_one_numeric(ptr, RPL_STATSDEBUG, "E :%s", str);
}

static void
stats_events(struct Client *source_p)
{
	rb_dump_events(stats_events_cb, source_p);
	send_pop_queue(source_p);
}

/* stats_pending_glines()
 *
 * input	- client pointer
 * output	- none
 * side effects - client is shown list of pending glines
 */
static void
stats_pending_glines(struct Client *source_p)
{
	if(ConfigFileEntry.glines)
	{
		rb_dlink_node *pending_node;
		struct gline_pending *glp_ptr;
		char timebuffer[MAX_DATE_STRING];
		struct tm *tmptr;

		RB_DLINK_FOREACH(pending_node, pending_glines.head)
		{
			glp_ptr = pending_node->data;

			tmptr = gmtime(&glp_ptr->time_request1);
			strftime(timebuffer, MAX_DATE_STRING, "%Y/%m/%d %H:%M:%S", tmptr);

			sendto_one_notice(source_p,
					  ":1) %s!%s@%s on %s requested gline at %s for %s@%s [%s]",
					  glp_ptr->oper_nick1,
					  glp_ptr->oper_user1, glp_ptr->oper_host1,
					  glp_ptr->oper_server1, timebuffer,
					  glp_ptr->user, glp_ptr->host, glp_ptr->reason1);

			if(glp_ptr->oper_nick2[0])
			{
				tmptr = gmtime(&glp_ptr->time_request2);
				strftime(timebuffer, MAX_DATE_STRING, "%Y/%m/%d %H:%M:%S", tmptr);
				sendto_one_notice(source_p,
						  ":2) %s!%s@%s on %s requested gline at %s for %s@%s [%s]",
						  glp_ptr->oper_nick2,
						  glp_ptr->oper_user2, glp_ptr->oper_host2,
						  glp_ptr->oper_server2, timebuffer,
						  glp_ptr->user, glp_ptr->host, glp_ptr->reason2);
			}
		}

		if(rb_dlink_list_length(&pending_glines) > 0)
			sendto_one_notice(source_p, ":End of Pending G-lines");
	}
	else
		sendto_one_notice(source_p, ":This server does not support G-Lines");

}

/* stats_glines()
 *
 * input	- client pointer
 * output	- none
 * side effects - client is shown list of glines
 */
static void
stats_glines(struct Client *source_p)
{
	if(ConfigFileEntry.glines)
	{
		rb_dlink_node *gline_node;
		struct ConfItem *kill_ptr;

		RB_DLINK_FOREACH_PREV(gline_node, glines.tail)
		{
			kill_ptr = gline_node->data;

			sendto_one_numeric(source_p, RPL_STATSKLINE,
					   form_str(RPL_STATSKLINE), 'G',
					   kill_ptr->host ? kill_ptr->host : "*",
					   kill_ptr->user ? kill_ptr->user : "*",
					   kill_ptr->passwd ? kill_ptr->passwd : "No Reason",
					   kill_ptr->spasswd ? "|" : "",
					   kill_ptr->spasswd ? kill_ptr->spasswd : "");
		}
	}
	else
		sendto_one_notice(source_p, ":This server does not support G-Lines");
}


static void
stats_hubleaf(struct Client *source_p)
{
	struct remote_conf *hub_p;
	rb_dlink_node *ptr;

	if((ConfigFileEntry.stats_h_oper_only ||
	    (ConfigServerHide.flatten_links && !IsExemptShide(source_p))) && !IsOper(source_p))
	{
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));
		return;
	}

	RB_DLINK_FOREACH(ptr, hubleaf_conf_list.head)
	{
		hub_p = ptr->data;

		if(hub_p->flags & CONF_HUB)
			sendto_one_numeric(source_p, RPL_STATSHLINE,
					   form_str(RPL_STATSHLINE), hub_p->host, hub_p->server);
		else
			sendto_one_numeric(source_p, RPL_STATSLLINE,
					   form_str(RPL_STATSLLINE), hub_p->host, hub_p->server);
	}
}


static void
stats_auth(struct Client *source_p)
{
	const char *name, *host, *pass, *user, *classname;
	struct AddressRec *arec;
	struct ConfItem *aconf;
	int i, port;

	/* Oper only, if unopered, return ERR_NOPRIVS */
	if((ConfigFileEntry.stats_i_oper_only == 2) && !IsOper(source_p))
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));

	/* If unopered, Only return matching auth blocks */
	else if((ConfigFileEntry.stats_i_oper_only == 1) && !IsOper(source_p))
	{
		if(MyConnect(source_p))
			aconf = find_auth(source_p->host, source_p->sockhost,
					  (struct sockaddr *) &source_p->localClient->ip,
					  GET_SS_FAMILY(&source_p->localClient->ip),
					  source_p->username);
		else
			aconf = find_auth(source_p->host, NULL, NULL, 0, source_p->username);

		if(aconf == NULL)
			return;

		get_printable_conf(aconf, &name, &host, &pass, &user, &port, &classname);

		sendto_one_numeric(source_p, s_RPL(RPL_STATSILINE),
				   name, show_iline_prefix(source_p, aconf, user),
				   host, port, classname);
	}

	/* Theyre opered, or allowed to see all auth blocks */
	else
	{
		HOSTHASH_WALK(i, arec)
		{
			if((arec->type & ~CONF_SKIPUSER) == CONF_CLIENT)
			{
				aconf = arec->aconf;
				if(!MyOper(source_p) && IsConfDoSpoofIp(aconf))
					continue;
				get_printable_conf(aconf, &name, &host, &pass, &user, &port,
						   &classname);

				sendto_one_numeric(source_p, RPL_STATSILINE,
						   form_str(RPL_STATSILINE), name,
						   show_iline_prefix(source_p, aconf, user),
						   show_ip_conf(aconf,
								source_p) ? host :
						   "255.255.255.255", port, classname);
			}
		}
		HOSTHASH_WALK_END;
		send_pop_queue(source_p);
	}
}


static void
stats_tklines(struct Client *source_p)
{
	const char *host, *pass, *user, *oper_reason;
	struct ConfItem *aconf;

	/* Oper only, if unopered, return ERR_NOPRIVS */
	if((ConfigFileEntry.stats_k_oper_only == 2) && !IsOper(source_p))
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));

	/* If unopered, Only return matching klines */
	else if((ConfigFileEntry.stats_k_oper_only == 1) && !IsOper(source_p))
	{

		if(MyConnect(source_p))
			aconf = find_conf_by_address(source_p->host, source_p->sockhost,
						     (struct sockaddr *) &source_p->localClient->ip,
						     CONF_KILL,
						     GET_SS_FAMILY(&source_p->localClient->ip),
						     source_p->username);
		else
			aconf = find_conf_by_address(source_p->host, NULL, NULL, CONF_KILL,
						     0, source_p->username);

		if(aconf == NULL)
			return;

		/* dont report a permanent kline as a tkline */
		if((aconf->flags & CONF_FLAGS_TEMPORARY) == 0)
			return;

		get_printable_kline(source_p, aconf, &host, &pass, &user, &oper_reason);

		sendto_one_numeric(source_p, RPL_STATSKLINE,
				   form_str(RPL_STATSKLINE), 'k',
				   host, user, pass, oper_reason ? "|" : "",
				   oper_reason ? oper_reason : "");
	}
	/* Theyre opered, or allowed to see all klines */
	else
	{
		rb_dlink_node *ptr;
		int i;

		for(i = 0; i < LAST_TEMP_TYPE; i++)
		{
			RB_DLINK_FOREACH(ptr, temp_klines[i].head)
			{
				aconf = ptr->data;

				get_printable_kline(source_p, aconf, &host, &pass,
						    &user, &oper_reason);

				sendto_one_numeric(source_p, RPL_STATSKLINE,
						   form_str(RPL_STATSKLINE),
						   'k', host, user, pass,
						   oper_reason ? "|" : "",
						   oper_reason ? oper_reason : "");
			}
		}
	}
}

static void
stats_klines(struct Client *source_p)
{
	struct ConfItem *aconf;
	const char *host, *pass, *user, *oper_reason;
	struct AddressRec *arec;
	int i;

	/* Oper only, if unopered, return ERR_NOPRIVS */
	if((ConfigFileEntry.stats_k_oper_only == 2) && !IsOper(source_p))
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));

	/* If unopered, Only return matching klines */
	else if((ConfigFileEntry.stats_k_oper_only == 1) && !IsOper(source_p))
	{

		/* search for a kline */
		if(MyConnect(source_p))
			aconf = find_conf_by_address(source_p->host, source_p->sockhost,
						     (struct sockaddr *) &source_p->localClient->ip,
						     CONF_KILL,
						     GET_SS_FAMILY(&source_p->localClient->ip),
						     source_p->username);
		else
			aconf = find_conf_by_address(source_p->host, NULL, NULL, CONF_KILL,
						     0, source_p->username);

		if(aconf == NULL)
			return;

		/* dont report a tkline as a kline */
		if(aconf->flags & CONF_FLAGS_TEMPORARY)
			return;

		get_printable_kline(source_p, aconf, &host, &pass, &user, &oper_reason);

		sendto_one_numeric(source_p, s_RPL(RPL_STATSKLINE),
				   'K', host, user, pass, oper_reason ? "|" : "",
				   oper_reason ? oper_reason : "");
	}
	/* Theyre opered, or allowed to see all klines */
	else
	{
		HOSTHASH_WALK(i, arec)
		{
			if((arec->type & ~CONF_SKIPUSER) == CONF_KILL)
			{
				aconf = arec->aconf;

				if(aconf->flags & CONF_FLAGS_TEMPORARY)	/* skip temps */
					continue;

				get_printable_kline(source_p, aconf, &host, &pass, &user,
						    &oper_reason);

				sendto_one_numeric(source_p, RPL_STATSKLINE,
						   form_str(RPL_STATSKLINE), 'K', host, user, pass,
						   oper_reason ? "|" : "",
						   oper_reason ? oper_reason : "");

			}
		}
		HOSTHASH_WALK_END;
		send_pop_queue(source_p);
	}
}



static void
list_msg_cb(void *data, void *cbptr)
{
	struct Client *source_p = (struct Client *)cbptr;
	struct Message *msg = (struct Message *)data;

	if(source_p == NULL || msg == NULL)
		return;

	sendto_one_numeric(source_p, s_RPL(RPL_STATSCOMMANDS), 
		  	   msg->cmd, msg->count, msg->bytes, msg->rcount);
}


static void
stats_messages(struct Client *source_p)
{
	hash_walkall(HASH_COMMAND, list_msg_cb, source_p);
}


static void
stats_oper(struct Client *source_p)
{
	struct oper_conf *oper_p;
	rb_dlink_node *ptr;

	if(!IsOper(source_p) && ConfigFileEntry.stats_o_oper_only)
	{
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));
		return;
	}

	RB_DLINK_FOREACH(ptr, oper_conf_list.head)
	{
		oper_p = ptr->data;

		sendto_one_numeric(source_p, RPL_STATSOLINE,
				   form_str(RPL_STATSOLINE),
				   oper_p->username, oper_p->host, oper_p->name,
				   IsOper(source_p) ? get_oper_privs(oper_p->flags) : "0", "-1");
	}
}


/* stats_operedup()
 *
 * input	- client pointer
 * output	- none
 * side effects - client is shown a list of active opers
 */
static void
stats_operedup(struct Client *source_p)
{
	struct Client *target_p;
	rb_dlink_node *oper_ptr;
	unsigned int count = 0;

	RB_DLINK_FOREACH(oper_ptr, oper_list.head)
	{
		target_p = oper_ptr->data;

		if(IsOperInvis(target_p) && !IsOper(source_p))
			continue;

		count++;

		if(MyClient(source_p) && IsOper(source_p))
		{
			sendto_one_numeric(source_p, RPL_STATSDEBUG,
					   "p :[%c][%s] %s (%s@%s) Idle: %" RBTT_FMT,
					   IsAdmin(target_p) ? 'A' : 'O',
					   get_oper_privs(target_p->operflags),
					   target_p->name, target_p->username, target_p->host,
					   (rb_current_time() - target_p->localClient->last));
		}
		else
		{
			sendto_one_numeric(source_p, RPL_STATSDEBUG,
					   "p :[%c] %s (%s@%s) Idle: %" RBTT_FMT,
					   IsAdmin(target_p) ? 'A' : 'O',
					   target_p->name, target_p->username, target_p->host,
					   (rb_current_time() - target_p->localClient->last));
		}
	}

	sendto_one_numeric(source_p, RPL_STATSDEBUG, "p :%u OPER(s)", count);

	stats_p_spy(source_p);
}

static void
stats_ports(struct Client *source_p)
{
	if(!IsOper(source_p) && ConfigFileEntry.stats_P_oper_only)
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));
	else
		show_ports(source_p);
}


static void
stats_resv_common(struct Client *source_p, bool wanttemp)
{
	rb_dlink_node *ptr;
	rb_dlink_list *resv_lists[2];
	char letter = 'q';
	if(wanttemp == false)
		letter = 'Q';

	resv_lists[0] = &resv_nick_list;
	if(wanttemp == true)
		resv_lists[1] = &resv_channel_temp_list;
	else
		resv_lists[1] = &resv_channel_perm_list;


	for(int lcnt = 0; lcnt < 2; lcnt++)
	{
		RB_DLINK_FOREACH(ptr, resv_lists[lcnt]->head)
		{
			struct ConfItem *aconf = ptr->data;
			bool istemp = aconf->flags & CONF_FLAGS_TEMPORARY;
		
			if((istemp == true && wanttemp == false) || (istemp == false && wanttemp == true))
				continue;
			sendto_one_numeric(source_p, RPL_STATSQLINE,
					   form_str(RPL_STATSQLINE),
					   letter, aconf->port, aconf->host, aconf->passwd);
		}
	}
}

static void
stats_tresv(struct Client *source_p)
{
	stats_resv_common(source_p, true);
}


static void
stats_resv(struct Client *source_p)
{
	stats_resv_common(source_p, false);
}


static void
stats_usage(struct Client *source_p)
{
#ifndef _WIN32
	struct rusage rus;
	time_t secs;
	time_t rup;
#ifdef	hz
#define hzz hz
#else
#ifdef HZ
#define hzz HZ
#else
	int hzz = 1;
#endif
#endif

	if(getrusage(RUSAGE_SELF, &rus) == -1)
	{
		sendto_one_notice(source_p, ":Getruseage error: %s.", strerror(errno));
		return;
	}
	secs = rus.ru_utime.tv_sec + rus.ru_stime.tv_sec;
	if(0 == secs)
		secs = 1;

	rup = (rb_current_time() - startup_time) * hzz;
	if(0 == rup)
		rup = 1;

	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "R :CPU Secs %" RBTT_FMT ":%" RBTT_FMT " User %" RBTT_FMT ":%" RBTT_FMT
			   " System %" RBTT_FMT ":%" RBTT_FMT, (secs / 60), (secs % 60),
			   (rus.ru_utime.tv_sec / 60), (rus.ru_utime.tv_sec % 60),
			   (rus.ru_stime.tv_sec / 60), (rus.ru_stime.tv_sec % 60));
	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "R :RSS %ld ShMem %ld Data %ld Stack %ld",
			   rus.ru_maxrss, (rus.ru_ixrss / rup), (rus.ru_idrss / rup),
			   (rus.ru_isrss / rup));
	sendto_one_numeric(source_p, RPL_STATSDEBUG, "R :Swaps %ld Reclaims %ld Faults %ld",
			   rus.ru_nswap, rus.ru_minflt, rus.ru_majflt);
	sendto_one_numeric(source_p, RPL_STATSDEBUG, "R :Block in %ld out %ld", rus.ru_inblock,
			   rus.ru_oublock);
	sendto_one_numeric(source_p, RPL_STATSDEBUG, "R :Msg Rcv %ld Send %ld", rus.ru_msgrcv,
			   rus.ru_msgsnd);
	sendto_one_numeric(source_p, RPL_STATSDEBUG, "R :Signals %ld Context Vol. %ld Invol %ld",
			   rus.ru_nsignals, rus.ru_nvcsw, rus.ru_nivcsw);
#endif
}

static void
stats_tstats(struct Client *source_p)
{
	struct Client *target_p;
	struct ServerStatistics sp;
	rb_dlink_node *ptr;

	memcpy(&sp, &ServerStats, sizeof(struct ServerStatistics));

	RB_DLINK_FOREACH(ptr, serv_list.head)
	{
		target_p = ptr->data;

		sp.is_sbs += target_p->localClient->sendB;
		sp.is_sbr += target_p->localClient->receiveB;
		sp.is_sti += (uint64_t) (rb_current_time() - target_p->localClient->firsttime);
		sp.is_sv++;
	}

	RB_DLINK_FOREACH(ptr, lclient_list.head)
	{
		target_p = ptr->data;

		sp.is_cbs += target_p->localClient->sendB;
		sp.is_cbr += target_p->localClient->receiveB;
		sp.is_cti += (uint64_t) (rb_current_time() - target_p->localClient->firsttime);
		sp.is_cl++;
	}

	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "T :accepts %u refused %u", sp.is_ac, sp.is_ref);
	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "T :rejected %u delaying %lu", sp.is_rej, delay_exit_length());
	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "T :throttled refused %u throttle list size %lu", sp.is_thr,
			   throttle_size());
	sendto_one_numeric(source_p, RPL_STATSDEBUG, "T :nicks being delayed %lu", get_nd_count());
	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "T :unknown commands %u prefixes %u", sp.is_unco, sp.is_unpf);
	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "T :nick collisions %u saves %u unknown closes %u",
			   sp.is_kill, sp.is_save, sp.is_ni);
	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "T :wrong direction %u empty %u", sp.is_wrdi, sp.is_empt);
	sendto_one_numeric(source_p, RPL_STATSDEBUG, "T :numerics seen %u", sp.is_num);
	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "T :auth successes %u fails %u", sp.is_asuc, sp.is_abad);
	sendto_one_numeric(source_p, RPL_STATSDEBUG, "T :Client Server");
	sendto_one_numeric(source_p, RPL_STATSDEBUG, "T :connected %u %u", sp.is_cl, sp.is_sv);
	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "T :bytes sent %" PRIu64 "K %" PRIu64 "K", sp.is_cbs / 1024,
			   sp.is_sbs / 1024);
	sendto_one_numeric(source_p, RPL_STATSDEBUG, "T :bytes recv %" PRIu64 "K %" PRIu64 "K",
			   sp.is_cbr / 1024, sp.is_sbr / 1024);
	sendto_one_numeric(source_p, RPL_STATSDEBUG, "T :time connected %" PRIu64 " %" PRIu64 "",
			   sp.is_cti, sp.is_sti);
}

static void
stats_uptime(struct Client *source_p)
{
	time_t now;

	now = rb_current_time() - startup_time;
	sendto_one_numeric(source_p, RPL_STATSUPTIME,
			   form_str(RPL_STATSUPTIME),
			   now / 86400, (now / 3600) % 24, (now / 60) % 60, now % 60);
	sendto_one_numeric(source_p, RPL_STATSCONN,
			   form_str(RPL_STATSCONN),
			   MaxConnectionCount, MaxClientCount, Count.totalrestartcount);
}

struct shared_flags
{
	int flag;
	char letter;
};
static struct shared_flags shared_flagtable[] = {
	{SHARED_PKLINE, 'K'},
	{SHARED_TKLINE, 'k'},
	{SHARED_UNKLINE, 'U'},
	{SHARED_PXLINE, 'X'},
	{SHARED_TXLINE, 'x'},
	{SHARED_UNXLINE, 'Y'},
	{SHARED_PRESV, 'Q'},
	{SHARED_TRESV, 'q'},
	{SHARED_UNRESV, 'R'},
	{SHARED_LOCOPS, 'L'},
	{0, '\0'}
};


static void
stats_shared(struct Client *source_p)
{
	struct remote_conf *shared_p;
	rb_dlink_node *ptr;
	char buf[15];
	char *p;
	int i;

	RB_DLINK_FOREACH(ptr, shared_conf_list.head)
	{
		shared_p = ptr->data;

		p = buf;

		*p++ = 'c';

		for(i = 0; shared_flagtable[i].flag != 0; i++)
		{
			if(shared_p->flags & shared_flagtable[i].flag)
				*p++ = shared_flagtable[i].letter;
		}

		*p = '\0';

		sendto_one_numeric(source_p, RPL_STATSULINE,
				   form_str(RPL_STATSULINE),
				   shared_p->server, shared_p->username, shared_p->host, buf);
	}

	RB_DLINK_FOREACH(ptr, cluster_conf_list.head)
	{
		shared_p = ptr->data;

		p = buf;

		*p++ = 'C';

		for(i = 0; shared_flagtable[i].flag != 0; i++)
		{
			if(shared_p->flags & shared_flagtable[i].flag)
				*p++ = shared_flagtable[i].letter;
		}

		*p = '\0';

		sendto_one_numeric(source_p, RPL_STATSULINE,
				   form_str(RPL_STATSULINE), shared_p->server, "*", "*", buf);
	}
}

/* stats_servers()
 *
 * input	- client pointer
 * output	- none
 * side effects - client is shown lists of who connected servers
 */
static void
stats_servers(struct Client *source_p)
{
	struct Client *target_p;
	rb_dlink_node *ptr;
	time_t days, hours, minutes, seconds;
	int j = 0;

	if(ConfigServerHide.flatten_links && !IsOper(source_p) && !IsExemptShide(source_p))
	{
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));
		return;
	}

	RB_DLINK_FOREACH(ptr, serv_list.head)
	{
		target_p = ptr->data;

		j++;
		seconds = (rb_current_time() - target_p->localClient->firsttime);

		days = seconds / 86400;
		seconds %= 86400;
		hours = seconds / 3600;
		seconds %= 3600;
		minutes = seconds / 60;
		seconds %= 60;

		sendto_one_numeric(source_p, RPL_STATSDEBUG,
				   "V :%s (%s!*@*) Idle: %" RBTT_FMT " SendQ: %zu "
				   "Connected: %" RBTT_FMT " day%s, %" RBTT_FMT ":%02" RBTT_FMT
				   ":%02" RBTT_FMT, target_p->name,
				   (target_p->serv->by[0] ? target_p->serv->by : "Remote."),
				   (rb_current_time() - target_p->localClient->lasttime),
				   rb_linebuf_len(target_p->localClient->buf_sendq), days,
				   (days == 1) ? "" : "s", hours, minutes, seconds);
	}

	sendto_one_numeric(source_p, RPL_STATSDEBUG, "V :%d Server(s)", j);
}

static void
stats_tgecos(struct Client *source_p)
{
	struct ConfItem *aconf;
	rb_dlink_node *ptr;

	RB_DLINK_FOREACH(ptr, xline_conf_list.head)
	{
		aconf = ptr->data;

		if(aconf->flags & CONF_FLAGS_TEMPORARY)
			sendto_one_numeric(source_p, RPL_STATSXLINE,
					   form_str(RPL_STATSXLINE),
					   'x', aconf->port, aconf->host, aconf->passwd);
	}
}

static void
stats_gecos(struct Client *source_p)
{
	struct ConfItem *aconf;
	rb_dlink_node *ptr;

	RB_DLINK_FOREACH(ptr, xline_conf_list.head)
	{
		aconf = ptr->data;

		if((aconf->flags & CONF_FLAGS_TEMPORARY) == 0)
			sendto_one_numeric(source_p, RPL_STATSXLINE,
					   form_str(RPL_STATSXLINE),
					   'X', aconf->port, aconf->host, aconf->passwd);
	}
}

static void
stats_class(struct Client *source_p)
{
	struct Class *cltmp;
	rb_dlink_node *ptr;

	if(ConfigFileEntry.stats_y_oper_only && !IsOper(source_p))
	{
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));
		return;
	}

	RB_DLINK_FOREACH(ptr, class_list.head)
	{
		cltmp = ptr->data;

		sendto_one_numeric(source_p, RPL_STATSYLINE,
				   form_str(RPL_STATSYLINE),
				   ClassName(cltmp), PingFreq(cltmp),
				   ConFreq(cltmp), MaxUsers(cltmp),
				   MaxSendq(cltmp),
				   MaxLocal(cltmp), MaxIdent(cltmp),
				   MaxGlobal(cltmp), MaxIdent(cltmp), CurrUsers(cltmp));
	}

	/* also output the default class */
	sendto_one_numeric(source_p, s_RPL(RPL_STATSYLINE),
			   ClassName(default_class), PingFreq(default_class),
			   ConFreq(default_class), MaxUsers(default_class),
			   MaxSendq(default_class),
			   MaxLocal(default_class), MaxIdent(default_class),
			   MaxGlobal(default_class), MaxIdent(default_class),
			   CurrUsers(default_class));
	send_pop_queue(source_p);
}


static void
stats_memory(struct Client *source_p)
{
	struct Client *target_p;
	//struct Channel *chptr;
	struct Ban *actualBan;
	rb_dlink_node *dlink;
	rb_dlink_node *ptr;
	int channel_count = 0;
	int local_client_conf_count = 0;	/* local client conf links */
	int users_counted = 0;	/* user structs */

	int channel_users = 0;
	int channel_invites = 0;
	int channel_bans = 0;
	int channel_except = 0;
	int channel_invex = 0;

	int class_count = 0;	/* classes */
	int users_invited_count = 0;	/* users invited */
	int user_channels = 0;	/* users in channels */
	int aways_counted = 0;
	size_t number_servers_cached;	/* number of servers cached by scache */

	size_t channel_memory = 0;
	size_t channel_ban_memory = 0;
	size_t channel_except_memory = 0;
	size_t channel_invex_memory = 0;

	size_t away_memory = 0;	/* memory used by aways */
	size_t mem_servers_cached;	/* memory used by scache */

	size_t rb_linebuf_count = 0;
	size_t rb_linebuf_memory_used = 0;

	size_t total_channel_memory = 0;

	size_t local_client_count = 0;
	size_t local_client_memory_used = 0;

	size_t remote_client_count = 0;
	size_t remote_client_memory_used = 0;

	size_t whowas_memory = 0;
	size_t whowas_count = 0;

	size_t ohash_count = 0;
	size_t ohash_mem = 0;

	size_t total_memory = 0;


	whowas_memory_usage(&whowas_count, &whowas_memory);
	total_memory += whowas_memory;
	
	RB_DLINK_FOREACH(ptr, global_client_list.head)
	{
		target_p = ptr->data;
		if(MyConnect(target_p))
		{
			local_client_conf_count++;
		}

		if(target_p->user)
		{
			users_counted++;
			if(MyConnect(target_p))
				users_invited_count +=
					rb_dlink_list_length(&target_p->localClient->invited);
			user_channels += rb_dlink_list_length(&target_p->user->channel);
			if(target_p->user->away)
			{
				aways_counted++;
				away_memory += (strlen(target_p->user->away) + 1);
			}
		}
	}
	total_memory += users_counted * sizeof(struct User); 
	total_memory += users_invited_count * sizeof(rb_dlink_node);
	total_memory += away_memory;
	
	/* Count up all channels, ban lists, except lists, Invex lists */
	RB_DLINK_FOREACH(ptr, global_channel_list.head)
	{
		struct Channel *chptr = ptr->data;
		channel_count++;
		channel_memory += (strlen(chptr->chname) + sizeof(struct Channel));

		channel_users += chan_member_count(chptr);
		channel_invites += rb_dlink_list_length(&chptr->invites);
#define ban_size(b) sizeof(struct Ban) + strlen(b->banstr)+ 1 + strlen(b->who) + 1;
		RB_DLINK_FOREACH(dlink, chptr->banlist.head)
		{
			actualBan = dlink->data;
			channel_bans++;

			channel_ban_memory += ban_size(actualBan);
		}

		RB_DLINK_FOREACH(dlink, chptr->exceptlist.head)
		{
			actualBan = dlink->data;
			channel_except++;

			channel_except_memory += ban_size(actualBan);
		}

		RB_DLINK_FOREACH(dlink, chptr->invexlist.head)
		{
			actualBan = dlink->data;
			channel_invex++;

			channel_invex_memory += ban_size(actualBan);
		}
#undef ban_size
	}

	total_channel_memory += channel_memory + channel_ban_memory + channel_invex_memory;
	total_channel_memory += (channel_bans + channel_invites + channel_except + channel_invex) * sizeof(rb_dlink_node);
	total_memory += total_channel_memory;
	
	
	/* count up all classes */

	class_count = rb_dlink_list_length(&class_list) + 1;

	total_memory += class_count * sizeof(struct Class);


	rb_count_rb_linebuf_memory(&rb_linebuf_count, &rb_linebuf_memory_used);
	total_memory += rb_linebuf_memory_used;


	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "z :Users %u(%zu) Invites %u(%zu)",
			   users_counted,
			   users_counted * sizeof(struct User),
			   users_invited_count, users_invited_count * sizeof(rb_dlink_node));

	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "z :User channels %u(%zu) Aways %u(%zu)",
			   user_channels,
			   user_channels * sizeof(rb_dlink_node), aways_counted, away_memory);

	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "z :Attached confs %u(%zu)",
			   local_client_conf_count,
			   local_client_conf_count * sizeof(rb_dlink_node));
	total_memory += local_client_conf_count * sizeof(rb_dlink_node);

	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "z :Classes %u(%zu)", class_count, class_count * sizeof(struct Class));
	total_memory += class_count * sizeof(struct Class);
	
	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "z :Channels %u(%zu)", channel_count, channel_memory);

	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "z :Bans %u(%zu)", channel_bans, channel_ban_memory);

	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "z :Exceptions %u(%zu)", channel_except, channel_except_memory);

	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "z :Invex %u(%zu)", channel_invex, channel_invex_memory);

	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "z :Channel members %u(%zu) invite %u(%zu)",
			   channel_users,
			   channel_users * sizeof(rb_dlink_node),
			   channel_invites, channel_invites * sizeof(rb_dlink_node));

	sendto_one_numeric(source_p, RPL_STATSDEBUG, "z :Whowas entries: %zu, memory used: %zu",
		 whowas_count, whowas_memory);

/* XXX need to have the hash.c code report its memory usage 
	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "z :Hash: client %u(%zu) chan %u(%zu)",
			   U_MAX, (U_MAX * sizeof(rb_dlink_list)),
			   CH_MAX, (CH_MAX * sizeof(rb_dlink_list)));
 */
 
	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "z :linebuf %zu(%zu)", rb_linebuf_count, rb_linebuf_memory_used);

	count_scache(&number_servers_cached, &mem_servers_cached);
	total_memory += mem_servers_cached;

	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "z :scache %ld(%ld)",
			   (long) number_servers_cached, (long) mem_servers_cached);

	operhash_count(&ohash_count, &ohash_mem);
	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "z :Operator Hash entries: %zu memory used: %zu", ohash_count, ohash_mem); 
			   
	total_memory += ohash_mem;
				 
	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "z :Total: channel %zu",
			   total_channel_memory);

	count_local_client_memory(&local_client_count, &local_client_memory_used);
	total_memory += local_client_memory_used;

	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "z :Local client Memory in use: %zu(%zu)",
			   local_client_count, local_client_memory_used);


	count_remote_client_memory(&remote_client_count, &remote_client_memory_used);
	total_memory += remote_client_memory_used;

	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "z :Remote client Memory in use: %zu(%zu)",
			   remote_client_count, remote_client_memory_used);

	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "z :TOTAL: %zu Available:  Current max RSS: %" PRIuPTR,
			   total_memory, get_maxrss());
#ifdef HAVE_STRUCT_MALLINFO2
	struct mallinfo2 mi;
	mi = mallinfo2();
	sendto_one_numeric(source_p, RPL_STATSDEBUG, "z :Malloc allocated: %zu free: %zu arena: %zu mmap blocks: %zu mmap bytes: %zu", mi.uordblks, mi.fordblks, mi.arena, mi.hblks, mi.hblkhd);
#else
#ifdef HAVE_STRUCT_MALLINFO
	struct mallinfo mi;
	mi = mallinfo();
	sendto_one_numeric(source_p, RPL_STATSDEBUG, "z :Malloc allocated: %i free: %i arena: %i mmap blocks: %i mmap bytes: %i", mi.uordblks, mi.fordblks, mi.arena, mi.hblks, mi.hblkhd);
#endif
#endif

}

static void
stats_ziplinks(struct Client *source_p)
{
	rb_dlink_node *ptr;
	struct Client *target_p;
	struct ZipStats *zipstats;
	int sent_data = 0;
	RB_DLINK_FOREACH(ptr, serv_list.head)
	{
		target_p = ptr->data;
		if(IsCapable(target_p, CAP_ZIP))
		{
			zipstats = target_p->localClient->zipstats;
			sendto_one_numeric(source_p, RPL_STATSDEBUG,
					   "Z :ZipLinks stats for %s send[%.2f%% compression "
					   "(%" PRIu64 " kB data/%" PRIu64
					   " kB wire)] recv[%.2f%% compression " "(%" PRIu64
					   " kB data/%" PRIu64 " kB wire)]", target_p->name, zipstats->out_ratio,
					   zipstats->out >> 10, zipstats->out_wire >> 10, zipstats->in_ratio,
					   zipstats->in >> 10, zipstats->in_wire >> 10);
			sent_data++;
		}
	}

	sendto_one_numeric(source_p, RPL_STATSDEBUG, "Z :%u ziplink(s)", sent_data);
}

static void
stats_servlinks(struct Client *source_p)
{
	time_t uptime;
	uint64_t sent, receive;
	struct Client *target_p;
	rb_dlink_node *ptr;
	int j = 0;

	if(ConfigServerHide.flatten_links && !IsOper(source_p) && !IsExemptShide(source_p))
	{
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));
		return;
	}

	sent = receive = 0;

	RB_DLINK_FOREACH(ptr, serv_list.head)
	{
		target_p = ptr->data;

		j++;
		sent += target_p->localClient->sendB;
		receive += target_p->localClient->receiveB;

		sendto_one_numeric(source_p, s_RPL(RPL_STATSLINKINFO),
			   target_p->name, rb_linebuf_len(target_p->localClient->buf_sendq),
			   target_p->localClient->sendM, target_p->localClient->sendB / 1024,
			   target_p->localClient->receiveM, target_p->localClient->receiveB / 1024,
			   (rb_current_time() - target_p->localClient->firsttime),
			   ((rb_current_time() >
			     target_p->localClient->lasttime) ? (rb_current_time() -
								 target_p->localClient->
								 lasttime) : 0),
			   IsOper(source_p) ? show_capabilities(target_p) : "TS");
	}

	sendto_one_numeric(source_p, RPL_STATSDEBUG, "? :%u total server(s)", j);

	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "? :Sent total : %7.2f %s", _GMKv((sent / 1024)), _GMKs((sent / 1024)));

	sendto_one_numeric(source_p, RPL_STATSDEBUG,
			   "? :Recv total : %7.2f %s", _GMKv((sent / 1024)), _GMKs((receive / 1024)));

	uptime = (rb_current_time() - startup_time);

	sendto_one_numeric(source_p, RPL_STATSDEBUG, "? :Server send: %7.2f %s (%4.1f K/s) ", 
		_GMKv(me.localClient->sendB / 1024), _GMKs((me.localClient->sendB / 1024)),
		 (float) ((float) (me.localClient->sendB / 1024) / (float) uptime));

	sendto_one_numeric(source_p, RPL_STATSDEBUG, "? :Server recv: %7.2f %s (%4.1f K/s)",
		_GMKv((me.localClient->receiveB / 1024)), _GMKs((me.localClient->receiveB / 1024)),
		(float) ((float) (me.localClient->receiveB / 1024) / (float) uptime));

}

static void
stats_ltrace(struct Client *source_p, int parc, const char *parv[])
{
	int doall = 0;
	int wilds = 0;
	const char *name;
	char statchar = parv[1][0];

	/* this is def targeted at us somehow.. */
	if(parc > 2 && !EmptyString(parv[2]))
	{
		/* directed at us generically? */
		if(match(parv[2], me.name) || (!MyClient(source_p) && !irccmp(parv[2], me.id)))
		{
			name = me.name;
			doall = 1;
		}
		else
		{
			name = parv[2];
			wilds = (strpbrk(name, "*?") != NULL);
		}

		/* must be directed at a specific person thats not us */
		if(!doall && !wilds)
		{
			struct Client *target_p;

			if(MyClient(source_p))
				target_p = find_named_person(name);
			else
				target_p = find_person(name);

			if(target_p != NULL)
			{
				stats_spy(source_p, statchar, target_p->name);
				stats_l_client(source_p, target_p, statchar);
			}
			else
				sendto_one_numeric(source_p, ERR_NOSUCHSERVER,
						   form_str(ERR_NOSUCHSERVER), name);

			return;
		}
	}
	else
	{
		name = me.name;
		doall = 1;
	}

	stats_spy(source_p, statchar, name);

	if(doall)
	{
		/* local opers get everyone */
		if(MyOper(source_p))
		{
			stats_l_list(source_p, name, doall, wilds, &unknown_list, statchar);
			stats_l_list(source_p, name, doall, wilds, &lclient_list, statchar);
		}
		else
		{
			/* they still need themselves if theyre local.. */
			if(MyClient(source_p))
				stats_l_client(source_p, source_p, statchar);

			stats_l_list(source_p, name, doall, wilds, &oper_list, statchar);
		}

		stats_l_list(source_p, name, doall, wilds, &serv_list, statchar);

		return;
	}

	/* ok, at this point theyre looking for a specific client whos on
	 * our server.. but it contains a wildcard.  --fl
	 */
	stats_l_list(source_p, name, doall, wilds, &lclient_list, statchar);

	return;
}


static void
stats_l_list(struct Client *source_p, const char *name, int doall, int wilds,
	     rb_dlink_list * list, char statchar)
{
	rb_dlink_node *ptr;
	struct Client *target_p;

	/* send information about connections which match.  note, we
	 * dont need tests for IsInvisible(), because non-opers will
	 * never get here for normal clients --fl
	 */
	RB_DLINK_FOREACH(ptr, list->head)
	{
		target_p = ptr->data;

		if(!doall && wilds && !match(name, target_p->name))
			continue;

		stats_l_client(source_p, target_p, statchar);
	}
}

void
stats_l_client(struct Client *source_p, struct Client *target_p, char statchar)
{
	if(IsAnyServer(target_p))
	{
		sendto_one_numeric(source_p, s_RPL(RPL_STATSLINKINFO),
				   target_p->name,
				   rb_linebuf_len(target_p->localClient->buf_sendq),
				   target_p->localClient->sendM,
				   target_p->localClient->sendB / 1024,
				   target_p->localClient->receiveM,
				   target_p->localClient->receiveB / 1024,
				   rb_current_time() - target_p->localClient->firsttime,
				   (rb_current_time() > target_p->localClient->lasttime) ?
				   (rb_current_time() - target_p->localClient->lasttime) : 0,
				   IsOper(source_p) ? show_capabilities(target_p) : "-");
	}

	else if(!show_ip(source_p, target_p))
	{
		sendto_one_numeric(source_p, s_RPL(RPL_STATSLINKINFO),
				   get_client_name(target_p, MASK_IP),
				   rb_linebuf_len(target_p->localClient->buf_sendq),
				   target_p->localClient->sendM,
				   target_p->localClient->sendB / 1024,
				   target_p->localClient->receiveM,
				   target_p->localClient->receiveB / 1024,
				   (rb_current_time() - target_p->localClient->firsttime),
				   (rb_current_time() > target_p->localClient->lasttime) ?
				   (rb_current_time() - target_p->localClient->lasttime) : 0, "-");
	}

	else
	{
		sendto_one_numeric(source_p, s_RPL(RPL_STATSLINKINFO),
				   IsUpper(statchar) ?
				   get_client_name(target_p, SHOW_IP) :
				   get_client_name(target_p, HIDE_IP),
				   rb_linebuf_len(target_p->localClient->buf_sendq),
				   target_p->localClient->sendM,
				   target_p->localClient->sendB / 1024,
				   target_p->localClient->receiveM,
				   target_p->localClient->receiveB / 1024,
				   rb_current_time() - target_p->localClient->firsttime,
				   (rb_current_time() > target_p->localClient->lasttime) ?
				   (rb_current_time() - target_p->localClient->lasttime) : 0, "-");
	}
}

static void
rb_dump_fd_callback(int fd, const char *desc, void *data)
{
	struct Client *source_p = data;
	sendto_one_numeric(source_p, RPL_STATSDEBUG, "F :fd %-3d desc '%s'", fd, desc);
}

static void
stats_comm(struct Client *source_p)
{
	rb_dump_fd(rb_dump_fd_callback, source_p);
	send_pop_queue(source_p);
}

/*
 * stats_spy
 *
 * inputs	- pointer to client doing the /stats
 *		- char letter they are doing /stats on
 * output	- none
 * side effects -
 * This little helper function reports to opers if configured.
 * personally, I don't see why opers need to see stats requests
 * at all. They are just "noise" to an oper, and users can't do
 * any damage with stats requests now anyway. So, why show them?
 * -Dianora
 */
static void
stats_spy(struct Client *source_p, char statchar, const char *name)
{
	hook_data_int data;

	data.client = source_p;
	data.arg1 = name;
	data.arg2 = (int) statchar;

	call_hook(doing_stats_hook, &data);
}

/* stats_p_spy()
 *
 * input	- pointer to client doing stats
 * ouput	-
 * side effects - call hook doing_stats_p
 */
static void
stats_p_spy(struct Client *source_p)
{
	hook_data data;

	data.client = source_p;
	data.arg1 = data.arg2 = NULL;

	call_hook(doing_stats_p_hook, &data);
}
