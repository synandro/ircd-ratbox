/* modules/m_monitor.c
 * 
 *  Copyright (C) 2005 Lee Hardy <lee@leeh.co.uk>
 *  Copyright (C) 2005-2026 ircd-ratbox development team
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1.Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * 2.Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3.The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "stdinc.h"
#include "struct.h"
#include "client.h"
#include "parse.h"
#include "modules.h"
#include "monitor.h"
#include "numeric.h"
#include "s_conf.h"
#include "ircd.h"
#include "match.h"
#include "send.h"

static int m_monitor(struct Client *, struct Client *, int, const char **);

static int modinit(void);
static void moddeinit(void);

struct Message monitor_msgtab = {
	.cmd = "MONITOR",
	.handlers[UNREGISTERED_HANDLER] =	{  mm_unreg },
	.handlers[CLIENT_HANDLER] =		{ .handler = m_monitor, .min_para = 2 },
	.handlers[RCLIENT_HANDLER] =		{  mm_ignore },
	.handlers[SERVER_HANDLER] =		{  mm_ignore },
	.handlers[ENCAP_HANDLER] =		{  mm_ignore },
	.handlers[OPER_HANDLER] =		{ .handler = m_monitor, .min_para = 2 },
};

mapi_clist_av1 monitor_clist[] = { &monitor_msgtab, NULL };

DECLARE_MODULE_AV1(monitor, modinit, moddeinit, monitor_clist, NULL, NULL, "$Revision$");

static int
modinit(void)
{
	return 0;

}

static void
moddeinit(void)
{
	return;
}

static void
add_monitor(struct Client *client_p, const char *nicks)
{
	char onbuf[IRCD_BUFSIZE], offbuf[IRCD_BUFSIZE];
	struct Client *target_p;
	struct monitor *monptr;
	const char *name;
	char *tmp;
	char *p;
	char *onptr, *offptr;
	int mlen, arglen;
	int cur_onlen, cur_offlen;

	/* these two are same length, just diff numeric */
	cur_offlen = cur_onlen = mlen = sprintf(onbuf, form_str(RPL_MONONLINE),
						me.name, client_p->name, "");
	sprintf(offbuf, form_str(RPL_MONOFFLINE), me.name, client_p->name, "");

	onptr = onbuf + mlen;
	offptr = offbuf + mlen;

	tmp = LOCAL_COPY(nicks);

	for(name = rb_strtok_r(tmp, ",", &p); name; name = rb_strtok_r(NULL, ",", &p))
	{
		if(EmptyString(name) || strlen(name) > ServerInfo.nicklen - 1)
			continue;

		if((int) rb_dlink_list_length(&client_p->localClient->monitor_list) >=
		   ConfigFileEntry.max_monitor)
		{
			char buf[100];

			if(cur_onlen != mlen)
				sendto_one_buffer(client_p, onbuf);
			if(cur_offlen != mlen)
				sendto_one_buffer(client_p, offbuf);

			if(p)
				snprintf(buf, sizeof(buf), "%s,%s", name, p);
			else
				snprintf(buf, sizeof(buf), "%s", name);

			sendto_one_numeric(client_p, s_RPL(ERR_MONLISTFULL),
				   ConfigFileEntry.max_monitor, buf);
			return;
		}

		monptr = find_monitor(name, true);

		/* already monitoring this nick */
		if(rb_dlinkFind(client_p, &monptr->users) != NULL)
			continue;

		rb_dlinkAddAlloc(client_p, &monptr->users);
		rb_dlinkAddAlloc(monptr, &client_p->localClient->monitor_list);

		if((target_p = find_named_person(name)) != NULL)
		{
			if(cur_onlen + strlen(target_p->name) +
			   strlen(target_p->username) + strlen(target_p->host) + 3 >= IRCD_BUFSIZE - 3)
			{
				sendto_one_buffer(client_p, onbuf);
				cur_onlen = mlen;
				onptr = onbuf + mlen;
			}

			if(cur_onlen != mlen)
			{
				*onptr++ = ',';
				cur_onlen++;
			}
			arglen = sprintf(onptr, "%s!%s@%s",
					 target_p->name, target_p->username, target_p->host);
			onptr += arglen;
			cur_onlen += arglen;
		}
		else
		{
			if(cur_offlen + strlen(name) + 1 >= IRCD_BUFSIZE - 3)
			{
				sendto_one_buffer(client_p, offbuf);
				cur_offlen = mlen;
				offptr = offbuf + mlen;
			}

			if(cur_offlen != mlen)
			{
				*offptr++ = ',';
				cur_offlen++;
			}
			arglen = sprintf(offptr, "%s", name);
			offptr += arglen;
			cur_offlen += arglen;
		}
	}

	if(cur_onlen != mlen)
		sendto_one_buffer(client_p, onbuf);
	if(cur_offlen != mlen)
		sendto_one_buffer(client_p, offbuf);
}

static void
del_monitor(struct Client *client_p, const char *nicks)
{
	struct monitor *monptr;
	const char *name;
	char *tmp;
	char *p;

	if(!rb_dlink_list_length(&client_p->localClient->monitor_list))
		return;

	tmp = LOCAL_COPY(nicks);

	for(name = rb_strtok_r(tmp, ",", &p); name; name = rb_strtok_r(NULL, ",", &p))
	{
		if(EmptyString(name))
			continue;

		/* not monitored */
		if((monptr = find_monitor(name, false)) == NULL)
			continue;

		rb_dlinkFindDestroy(client_p, &monptr->users);
		rb_dlinkFindDestroy(monptr, &client_p->localClient->monitor_list);
		free_monitor(monptr);
	}
}

static void
list_monitor(struct Client *client_p)
{
	char buf[IRCD_BUFSIZE];
	char *nbuf;
	rb_dlink_node *ptr;
	int mlen, arglen, cur_len;

	if(!rb_dlink_list_length(&client_p->localClient->monitor_list))
	{
		sendto_one_numeric(client_p, s_RPL(RPL_ENDOFMONLIST));
		return;
	}

	cur_len = mlen = sprintf(buf, form_str(RPL_MONLIST), me.name, client_p->name, "");
	nbuf = buf + mlen;
	SetCork(client_p);
	RB_DLINK_FOREACH(ptr, client_p->localClient->monitor_list.head)
	{
		struct monitor *monptr = ptr->data;

		if(cur_len + strlen(monptr->name) + 1 >= IRCD_BUFSIZE - 3)
		{
			sendto_one_buffer(client_p, buf);
			nbuf = buf + mlen;
			cur_len = mlen;
		}

		if(cur_len != mlen)
		{
			*nbuf++ = ',';
			cur_len++;
		}
		arglen = sprintf(nbuf, "%s", monptr->name);
		cur_len += arglen;
		nbuf += arglen;
	}

	sendto_one_buffer(client_p, buf);
	ClearCork(client_p);
	sendto_one_numeric(client_p, s_RPL(RPL_ENDOFMONLIST));
}

static void
show_monitor_status(struct Client *client_p)
{
	char onbuf[IRCD_BUFSIZE], offbuf[IRCD_BUFSIZE];
	char *onptr, *offptr;
	int cur_onlen, cur_offlen;
	int mlen, arglen;
	rb_dlink_node *ptr;

	mlen = cur_onlen = sprintf(onbuf, form_str(RPL_MONONLINE), me.name, client_p->name, "");
	cur_offlen = sprintf(offbuf, form_str(RPL_MONOFFLINE), me.name, client_p->name, "");

	onptr = onbuf + mlen;
	offptr = offbuf + mlen;
	SetCork(client_p);
	RB_DLINK_FOREACH(ptr, client_p->localClient->monitor_list.head)
	{
		struct monitor *monptr = ptr->data;
		struct Client *target_p;

		if((target_p = find_named_person(monptr->name)) != NULL)
		{
			if(cur_onlen + strlen(target_p->name) +
			   strlen(target_p->username) + strlen(target_p->host) + 3 >= IRCD_BUFSIZE - 3)
			{
				sendto_one_buffer(client_p, onbuf);
				cur_onlen = mlen;
				onptr = onbuf + mlen;
			}

			if(cur_onlen != mlen)
			{
				*onptr++ = ',';
				cur_onlen++;
			}
			arglen = sprintf(onptr, "%s!%s@%s",
					 target_p->name, target_p->username, target_p->host);
			onptr += arglen;
			cur_onlen += arglen;
		}
		else
		{
			if(cur_offlen + strlen(monptr->name) + 1 >= IRCD_BUFSIZE - 3)
			{
				sendto_one_buffer(client_p, offbuf);
				cur_offlen = mlen;
				offptr = offbuf + mlen;
			}

			if(cur_offlen != mlen)
			{
				*offptr++ = ',';
				cur_offlen++;
			}

			arglen = sprintf(offptr, "%s", monptr->name);
			offptr += arglen;
			cur_offlen += arglen;
		}
	}

	ClearCork(client_p);
	if(cur_onlen != mlen)
		sendto_one_buffer(client_p, onbuf);
	if(cur_offlen != mlen)
		sendto_one_buffer(client_p, offbuf);
}

static int
m_monitor(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	switch (parv[1][0])
	{
	case '+':
		if(parc < 3 || EmptyString(parv[2]))
		{
			sendto_one_numeric(client_p, s_RPL(ERR_NEEDMOREPARAMS), "MONITOR");
			return 0;
		}

		add_monitor(source_p, parv[2]);
		break;
	case '-':
		if(parc < 3 || EmptyString(parv[2]))
		{
			sendto_one_numeric(client_p, s_RPL(ERR_NEEDMOREPARAMS),"MONITOR");
			return 0;
		}

		del_monitor(source_p, parv[2]);
		break;

	case 'C':
	case 'c':
		clear_monitor(source_p);
		break;

	case 'L':
	case 'l':
		list_monitor(source_p);
		break;

	case 'S':
	case 's':
		show_monitor_status(source_p);
		break;

	default:
		break;
	}

	return 0;
}
