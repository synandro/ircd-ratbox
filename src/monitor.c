/*
 * ircd-ratbox: an advanced Internet Relay Chat Daemon(ircd).
 * monitor.c - Code for server-side notify lists
 *
 * Copyright (C) 2005 Lee Hardy <lee -at- leeh.co.uk>
 * Copyright (C) 2005-2026 ircd-ratbox development team
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
#include "hash.h"
#include "monitor.h"
#include "numeric.h"
#include "ircd.h"
#include "match.h"
#include "send.h"

struct monitor *
find_monitor(const char *name, bool add)
{
	struct monitor *monptr;
	hash_node *hnode;
	if((monptr = hash_find_data(HASH_MONITOR, name)) != NULL)
		return monptr;

	if(add == true)
	{
		monptr = rb_malloc(sizeof(struct monitor));
		monptr->name = rb_strdup(name);
		hnode = hash_add(HASH_MONITOR, name, monptr);
		monptr->hnode = hnode;
		return monptr;
	}

	return NULL;
}

void
free_monitor(struct monitor *monptr)
{
	/* don't free if there are users attached */
	if(rb_dlink_list_length(&monptr->users) > 0)
		return;
	
	hash_del_hnode(HASH_MONITOR, monptr->hnode);		
	rb_free(monptr->name);
	rb_free(monptr);
}


/* monitor_signon()
 *
 * inputs	- client who has just connected
 * outputs	-
 * side effects	- notifies any clients monitoring this nickname that it has
 *		  connected to the network
 */
void
monitor_signon(struct Client *client_p)
{
	char buf[USERHOST_REPLYLEN];
	struct monitor *monptr;
	
	monptr = find_monitor(client_p->name, false);

	/* no watchers watching this nick */
	if(monptr == NULL)
		return;

	snprintf(buf, sizeof(buf), "%s!%s@%s", client_p->name, client_p->username, client_p->host);

	sendto_monitor(monptr, form_str(RPL_MONONLINE), me.name, "*", buf);
}

/* monitor_signoff()
 *
 * inputs	- client who is exiting
 * outputs	-
 * side effects	- notifies any clients monitoring this nickname that it has
 *		  left the network
 */
void
monitor_signoff(struct Client *client_p)
{
	struct monitor *monptr;

	monptr  = find_monitor(client_p->name, false);

	/* noones watching this nick */
	if(monptr == NULL)
		return;

	sendto_monitor(monptr, form_str(RPL_MONOFFLINE), me.name, "*", client_p->name);
}


void
clear_monitor(struct Client *client_p)
{
	rb_dlink_node *ptr, *next_ptr;

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, client_p->localClient->monitor_list.head)
	{
		struct monitor *monptr = ptr->data;
		rb_dlinkFindDestroy(client_p, &monptr->users);

		/* free the rb_dlink_node allocated in add_monitor -
		 * we don't use rb_dlinkDestory here as we are clearing the list anyways.. */
		rb_free(ptr); 

		free_monitor(monptr); /* this checks if monptr is still in use */
	}

	client_p->localClient->monitor_list.head = client_p->localClient->monitor_list.tail = NULL;
	client_p->localClient->monitor_list.length = 0;
}


