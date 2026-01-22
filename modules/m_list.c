/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_list.c: Shows what servers are currently connected.
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
#include "channel.h"
#include "hash.h"
#include "match.h"
#include "ircd.h"
#include "numeric.h"
#include "s_conf.h"
#include "send.h"
#include "parse.h"
#include "modules.h"
#include "class.h"
#include "client.h"

static int m_list(struct Client *, struct Client *, int, const char **);
static int mo_list(struct Client *, struct Client *, int, const char **);

struct Message list_msgtab = {
	.cmd = "LIST",
	.handlers[UNREGISTERED_HANDLER] =	{ mm_unreg },
	.handlers[CLIENT_HANDLER] =		{ .handler = m_list },
	.handlers[RCLIENT_HANDLER] =		{ mm_ignore },
	.handlers[SERVER_HANDLER] =		{  mm_ignore },
	.handlers[ENCAP_HANDLER] =		{  mm_ignore },
	.handlers[OPER_HANDLER] =		{ .handler = mo_list },
};

mapi_clist_av1 list_clist[] = { &list_msgtab, NULL };

DECLARE_MODULE_AV1(list, NULL, NULL, list_clist, NULL, NULL, "$Revision$");

static void list_all_channels(struct Client *source_p);
static void list_limit_channels(struct Client *source_p, const char *param);
static void list_named_channel(struct Client *source_p, const char *name);

/* m_list()
 *	parv[0] = sender prefix
 *	parv[1] = channel
 */
static int
m_list(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	static time_t last_used = 0L;

	if(parc < 2 || !IsChannelName(parv[1]))
	{
		/* pace this due to the sheer traffic involved */
		if(((last_used + ConfigFileEntry.pace_wait) > rb_current_time()))
		{
			sendto_one_numeric(source_p, s_RPL(RPL_LOAD2HI), "LIST");
			sendto_one_numeric(source_p, s_RPL(RPL_LISTEND));
			return 0;
		}
		else
			last_used = rb_current_time();
	}

	/* If no arg, do all channels *whee*, else just one channel */
	if(parc < 2 || EmptyString(parv[1]))
		list_all_channels(source_p);
	else if(IsChannelName(parv[1]))
		list_named_channel(source_p, parv[1]);
	else
		list_limit_channels(source_p, parv[1]);

	return 0;
}

/* mo_list()
 *	parv[0] = sender prefix
 *	parv[1] = channel
 */
static int
mo_list(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	/* If no arg, do all channels *whee*, else just one channel */
	if(parc < 2 || EmptyString(parv[1]))
		list_all_channels(source_p);
	else if(IsChannelName(parv[1]))
		list_named_channel(source_p, parv[1]);
	else
		list_limit_channels(source_p, parv[1]);

	return 0;
}

/* list_all_channels()
 *
 * inputs	- pointer to client requesting list
 * output	-
 * side effects	- list all channels to source_p
 */
static void
list_all_channels(struct Client *source_p)
{
	rb_dlink_node *ptr;
	long sendq_limit;
	int count = 0;
	/* give them an output limit of 90% of their sendq. --fl */
	sendq_limit = get_sendq(source_p);
	sendq_limit /= 10;
	sendq_limit *= 9;

	sendto_one_numeric(source_p, s_RPL(RPL_LISTSTART));
	SetCork(source_p);

	RB_DLINK_FOREACH(ptr, global_channel_list.head)
	{
		struct Channel *chptr = ptr->data;

		/* if theyre overflowing their sendq, stop. --fl */
		if(rb_linebuf_len(source_p->localClient->buf_sendq) > sendq_limit)
		{
			sendto_one_numeric(source_p, s_RPL(ERR_TOOMANYMATCHES), "LIST");
			break;
		}

		if(SecretChannel(chptr) && !IsMember(source_p, chptr))
			continue;
		sendto_one_numeric(source_p, s_RPL(RPL_LIST), chptr->chname,
				   chan_member_count(chptr),
				   chptr->topic == NULL ? "" : chptr->topic->topic);

		if(count++ >= 10)
		{
			ClearCork(source_p);
			send_pop_queue(source_p);
			SetCork(source_p);
			count = 0;
		}
	}
	ClearCork(source_p);
	sendto_one_numeric(source_p, s_RPL(RPL_LISTEND));
	return;
}

static void
list_limit_channels(struct Client *source_p, const char *param)
{
	char *args;
	char *p;
	rb_dlink_node *ptr;
	long sendq_limit;
	unsigned long max = ULONG_MAX;
	unsigned int min = 0;
	unsigned int i;
	unsigned int count = 0;
	char *endptr;
	time_t cmintime = 0, cmaxtime = 0;
	time_t tmintime = 0, tmaxtime = 0;
	
	args = LOCAL_COPY(param);

	for(i = 0; i < 2; i++)
	{
		if((p = strchr(args, ',')) != NULL)
			*p++ = '\0';

		switch(*args)
		{
			case '<':
			{
				args++;
				errno = 0;
				max = strtoul(args, &endptr, 10);
				if(errno || endptr == args)
					max = ULONG_MAX;
				break;
			}
			case '>':
			{
				args++;
				errno = 0;
				min = strtoul(args, &endptr, 10);
				if(errno || endptr == args)
					min = 0;
				break;

			}
			case 'C':
			case 'c':
			{
				args++;
				errno = 0;
				switch(*args)
				{
					case '<':
					{
                                        	args++;
						time_t mintime = (time_t) (strtol(args, &endptr, 10) * 60);
						if(errno || endptr == args) 
						{
							mintime = 0;
							cmintime = 0;
                                                } else {
  							cmintime = rb_current_time() - mintime;
						}
						break;
						
					}
					case '>':
					{
						args++;
						time_t maxtime = (time_t)(strtol(args, &endptr, 10) * 60);
						if(errno || endptr == args) 
						{
							maxtime = 0;
							cmaxtime = 0;
                                                } else
							cmaxtime = rb_current_time() - maxtime;
						break;
					}
					default:
						break;
					
				}	
				break;
			}
			case 'T':
			case 't':
			{
				args++;
				errno = 0;
				switch(*args)
				{
					case '<':
					{
                                        	args++;
						time_t mintime = (time_t) (strtol(args, &endptr, 10) * 60);
						if(errno || endptr == args) 
						{
							mintime = 0;
							tmintime = 0;
                                                } else {
  							tmintime = rb_current_time() - mintime;
						}
						break;
						
					}
					case '>':
					{
						args++;
						time_t maxtime = (time_t)(strtol(args, &endptr, 10) * 60);
						if(errno || endptr == args) 
						{
							maxtime = 0;
							tmaxtime = 0;
                                                } else
							tmaxtime = rb_current_time() - maxtime;
						break;
					}
					default:
						break;
					
				}	
				break;
			}


			default:
				break;
			
		}

		if(EmptyString(p))
			break;
		else
			args = p;
	}

	/* give them an output limit of 90% of their sendq. --fl */
	sendq_limit = get_sendq(source_p);
	sendq_limit /= 10;
	sendq_limit *= 9;

	sendto_one_numeric(source_p, s_RPL(RPL_LISTSTART));
	SetCork(source_p);

	RB_DLINK_FOREACH(ptr, global_channel_list.head)
	{
		struct Channel *chptr = ptr->data;

		/* if theyre overflowing their sendq, stop. --fl */
		if(rb_linebuf_len(source_p->localClient->buf_sendq) > sendq_limit)
		{
			sendto_one_numeric(source_p, s_RPL(ERR_TOOMANYMATCHES), "LIST");
			break;
		}

		if(chan_member_count(chptr) >= max ||
		   chan_member_count(chptr) <= min)
			continue;

		if(cmintime > 0 && chptr->channelts < cmintime)
			continue;
			
		if(cmaxtime > 0 && chptr->channelts > cmaxtime)
			continue;

                if(tmintime > 0 || tmaxtime > 0)
                {
			if(chptr->topic == NULL)
				continue;
	                if(tmintime > 0 && chptr->topic->topic_time < tmintime)
        	        	continue;
			if(tmaxtime > 0 && chptr->topic->topic_time > tmaxtime)
				continue;
		}

		if(SecretChannel(chptr) && !IsMember(source_p, chptr))
			continue;

		sendto_one_numeric(source_p, s_RPL(RPL_LIST), chptr->chname,
				   chan_member_count(chptr),
				   chptr->topic == NULL ? "" : chptr->topic->topic);

		if(count++ >= 10)
		{
			ClearCork(source_p);
			send_pop_queue(source_p);
			SetCork(source_p);
			count = 0;
		}
	}
	ClearCork(source_p);
	sendto_one_numeric(source_p, s_RPL(RPL_LISTEND));
	return;
}


/* list_named_channel()
 * 
 * inputs	- pointer to client requesting list
 * output	-
 * side effects	- list single channel to source
 */
static void
list_named_channel(struct Client *source_p, const char *name)
{
	struct Channel *chptr;
	char *p;
	char *n = LOCAL_COPY(name);

	SetCork(source_p);
	sendto_one_numeric(source_p, s_RPL(RPL_LISTSTART));

	if((p = strchr(n, ',')))
		*p = '\0';

	if(*n == '\0')
	{
		sendto_one_numeric(source_p, s_RPL(ERR_NOSUCHNICK), name);
		ClearCork(source_p);
		sendto_one_numeric(source_p, s_RPL(RPL_LISTEND));
		return;
	}

	chptr = find_channel(n);

	if(chptr == NULL)
	{
		sendto_one_numeric(source_p, s_RPL(ERR_NOSUCHNICK), n);
		ClearCork(source_p);
		sendto_one_numeric(source_p, s_RPL(RPL_LISTEND));
		return;
	}

	if(ShowChannel(source_p, chptr))
		sendto_one_numeric(source_p, s_RPL(RPL_LIST), chptr->chname,
				   chan_member_count(chptr),
				   chptr->topic == NULL ? "" : chptr->topic->topic);

	ClearCork(source_p);
	sendto_one_numeric(source_p, s_RPL(RPL_LISTEND));
	return;
}
