/*
 *  OpenServices 1.0
 *  Base Structure and parsing tools.
 *
 *  Copyright (C) 2006 Alan "alz" Milford
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 */

#include "stdinc.h"
#include "struct.h"
#include "parse.h"
#include "client.h"
#include "channel.h"
#include "hash.h"
#include "ircd.h"
#include "numeric.h"
#include "s_log.h"
#include "s_stats.h"
#include "send.h"
#include "s_conf.h"
#include "memory.h"
#include "s_serv.h"
#include "hook.h"
#include "s_user.h"
#include "match.h"
#include "scache.h"
#include "services.h"

#ifdef ENABLE_OCF_SERVICES

#define OCF_MAX_MSG_HASH 512

static rb_dlink_list services;

static struct SVCMessage *service_cmd_parse(struct Client *client_p, const char *cmd);

static void
handle_command(struct SVCMessage *mptr, struct Client *client_p,
	       struct Client *target_p, int i, const char *hpara[MAXPARA], int direct);

/* support functions */
static uint32_t
cmd_hash(const char *p)
{
        uint32_t hash_val = 0, q = 1, n;

        while(*p)
        {
                n = ToUpper(*p++);
                hash_val += ((n) + (q++ << 1)) ^ ((n) << 2);
        }
        /* note that 9 comes from 2^9 = MAX_MSG_HASH */
        return (hash_val >> (32 - 9)) ^ (hash_val & (OCF_MAX_MSG_HASH - 1));
}

/* create_service()
 *
 * inputs   - nick
 *          - username
 *          - hostname
 *          - gecos
 *          - opered (1 = yes, 0 = no)
 * outputs  - returns pointer to created service
 *
 */
struct Service *
create_service(const char *nick, const char *username, const char *host, const char *gecos, bool opered)
{
	struct Service *service_p;
	struct Client *client_p = create_fake_client(nick, username, host, gecos, opered);

	service_p = rb_malloc(sizeof(struct Service));
	service_p->client_p = client_p;

	rb_dlinkAdd(service_p, &service_p->node, &services);

	return service_p;
}

/* destroy_service()
 * 
 * inputs       - pointer to service struct
 * ouputs       - none
 * side_effects - kills and destroys services client
 */
void
destroy_service(struct Service *service_p)
{
	struct Client *client_p = service_p->client_p;

	if(service_p == NULL)
		return;

	rb_dlinkFindDelete(service_p, &services);
	rb_free(service_p);
	if(client_p != NULL)
		destroy_fake_client(client_p);
}

/* handle_services_message()
 *
 * inputs       - data from fakeclient msg hook
 * outputs      - 0
 * side_effects - begin parsing routine for msg
 */
int
handle_services_message(hook_service_message_data * hd)
{
	struct Client *source_p = hd->source_p;
	struct Client *target_p = hd->target_p;
	int direct = hd->direct;

	int p_or_n = hd->notice;
	int length = strlen(hd->message);

	/* RFC says don't reply to NOTICES */
	if(p_or_n == 1)
		return 0;

	parse_services_message(source_p, target_p, hd->message, length, direct);

	return 0;
}

/* svc_message()
 *
 * inputs       - service pointer
 *              - client pointer
 *              - message type
 *              - message (&args)
 * outputs      - none
 * side_effects - sends either PRIVMSG or NOTICE to given
 *                client, depending on given type.
 */

#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#if (((__GNUC__ * 100) + __GNUC_MINOR__) >= 406)
#pragma GCC diagnostic push
#endif

void
svc_message(struct Service *service, struct Client *target_p, svc_type_t type, const char *pattern, ...)
{
	va_list args;
	char tmpBuf1[IRCD_BUFSIZE];

	va_start(args, pattern);
	vsnprintf(tmpBuf1, sizeof(tmpBuf1), pattern, args);
	va_end(args);
	switch (type)
	{
	case SVC_NOTICE:
		{
			if(target_p->localClient)
			{
				if(service == NULL)
				{
					sendto_one(target_p, ":%s NOTICE %s :%s", me.name, target_p->name, tmpBuf1);
				}
				else
				{
					sendto_one(target_p, ":%s!%s@%s NOTICE %s :%s", service->client_p->name,
						   service->client_p->username, service->client_p->host,
						   target_p->name, tmpBuf1);
					service->client_p->localClient->last = rb_current_time();
				}
			}
			else
			{
				if(service == NULL)
				{
					sendto_one(target_p, ":%s NOTICE %s :%s", me.name, target_p->name, tmpBuf1);
				}
				else
				{
					sendto_anywhere(target_p, service->client_p, "NOTICE", ":%s", tmpBuf1);
					service->client_p->localClient->last = rb_current_time();
				}
			}
		}
	case SVC_PRIVMSG:
		{
			/* server sending privmsg? something is wrong here !? */
			if(service == NULL)
				sendto_one(target_p, ":%s PRIVMSG %s :%s", me.name, target_p->name, tmpBuf1);
			else
				sendto_anywhere(target_p, service->client_p, "PRIVMSG", ":%s", tmpBuf1);
		}
	}
}

#if (((__GNUC__ * 100) + __GNUC_MINOR__) >= 406)
#pragma GCC diagnostic pop
#endif

/* find_service()
 *
 * inputs       - client pointer
 * outputs      - service pointer
 *
 */
struct Service *
find_service(struct Client *client_p)
{
	rb_dlink_node *ptr;

	//not a service?
	if(!IsFake(client_p))
		return NULL;

	RB_DLINK_FOREACH(ptr, services.head)
	{
		struct Service *service_p = (struct Service *) ptr->data;

		if(service_p->client_p == client_p)
			return service_p;
	}

	return NULL;
}

/* process_unknown_command()
 *
 * inputs       - source client pointer
 *              - dest client pointer
 * outputs      - none
 *
 * does nothing unless unknown command handler
 * has been overridden by the service, if so it 
 * runs the specified function
 */
void
process_unknown_command(struct Client *source_p, struct Client *target_p, int parc, const char *parv[], int direct)
{
	struct Service *service_p = find_service(target_p);

	if(service_p == NULL)
		return;

	if(service_p->unknown != 0)
		(*service_p->unknown) (source_p, service_p->client_p, parc, parv, direct);
}

/* parse_message()
 *
 * given a service message, parses it and generates parv, parc and sender
 */
void
parse_services_message(struct Client *client_p, struct Client *target_p, const char *text, int length, int direct)
{
	char *ch;
	char *s;
	int i = 1;
	struct SVCMessage *mptr = NULL;
	char *pbuffer = LOCAL_COPY(text);
	char *para[MAXPARA + 1];

	//whoa! not a fake client, ignore
	if(!IsFake(target_p))
		return;


	//empty para - just incase.
	memset(&para, 0, MAXPARA + 1);

	for(ch = pbuffer; *ch == ' '; ch++)	/* skip spaces */
		/* null statement */ ;

	if((s = strchr(ch, ' ')))
		*s++ = '\0';

	mptr = service_cmd_parse(target_p, ch);

	/* no command or its encap only, error */
	if(mptr == NULL)
	{
		process_unknown_command(client_p, target_p, i, (const char **) (uintptr_t) para, direct);
		return;
	}

	// this shouldn't happen
	if(mptr == NULL)
		return;

	if(s != NULL)
		i = rb_string_to_array(s, &para[1], MAXPARA) + 1;
	para[0] = ch;

	handle_command(mptr, client_p, target_p, i, /* XXX discards const!!! */ (const char **) (uintptr_t) para,
		       direct);

}

/* svc_set_unknown()
 * 
 * inputs       - service pointer
 *              - message handler
 * outputs      - none
 * side_effects - set's given services unknown command to given
 *                message handler
 */
void
svc_set_unknown(struct Service *service_p, SVCMessageHandler unknown)
{
	if(service_p == NULL)
		return;

	service_p->unknown = unknown;
}

/* handle_command()
 *
 * inputs       - message pointer
 *              - source client pointer
 *              - target client pointer
 *              - number of args (parc)
 *              - args (parv)
 * outputs      - none
 * side_effects - runs service command with given args
 */
static void
handle_command(struct SVCMessage *mptr, struct Client *source_p,
	       struct Client *target_p, int parc, const char *parv[MAXPARA], int direct)
{
	if(!IsFake(target_p))
		return;

	if(IsServer(source_p))
		return;

	// no command
	if(mptr == NULL)
		return;

	/* check right amount of params is passed... --is */
	if(parc < mptr->min_para || (mptr->min_para && EmptyString(parv[mptr->min_para - 1])))
	{
		return;
	}

	(*mptr->handler) (source_p, target_p, parc, parv, direct);
	return;
}

/* svc_get_cmd()
 * 
 * inputs       - service pointer
 *              - command name
 * outputs      - service message pointer
 */
struct SVCMessage *
svc_get_cmd(struct Service *service_p, char *cmd)
{
	rb_dlink_node *ptr;
	uint32_t hashv;
	
	hashv = cmd_hash(cmd);
	
	RB_DLINK_FOREACH(ptr, service_p->command_tbl[hashv].head)
	{
		struct SVCMessage *mptr = ptr->data;

		if(strcasecmp(mptr->cmd, cmd) == 0)
			return mptr;
	}

	return NULL;
}

/* is_svc_command
 *
 * inputs - service pointer
 *        - command pointer
 *
 * output - 1 if exists
 */
int
is_svc_command(struct Service *service_p, struct SVCMessage *msg)
{
	rb_dlink_node *ptr;
	uint32_t hashv;
	
	hashv = cmd_hash(msg->cmd);
	RB_DLINK_FOREACH(ptr, service_p->command_tbl[hashv].head)
	{
		struct SVCMessage *mptr = ptr->data;
		if(strcasecmp(mptr->cmd, msg->cmd) == 0)
			return 1;
	}
	return 0;
}

/* svc_add_cmd
 *
 * inputs   - service to add command to
 *          - struct SVCMessage pointer
 * output   - none
 * side effects - adds this command to given service
 */
void
svc_add_cmd(struct Service *service_p, struct SVCMessage *msg)
{
	uint32_t hashv;
	//already a command, ignore
	if(is_svc_command(service_p, msg) == 1)
		return;

	service_p->unknown = 0;

	hashv = cmd_hash(msg->cmd);
	rb_dlinkAddAlloc(msg, &service_p->command_tbl[hashv]);
}

/* svc_del_cmd
 *
 * inputs   - command name
 * output   - none
 * side effects - unload this one command name
 */
void
svc_del_cmd(struct Service *service_p, struct SVCMessage *msg)
{
	uint32_t hashv;
	if(!is_svc_command(service_p, msg))
		return;

	hashv = cmd_hash(msg->cmd);
	rb_dlinkFindDelete(msg, &service_p->command_tbl[hashv]);
}

/* service_cmd_parse
 *
 * inputs   - service client pointer
 *          - command name
 * output   - pointer to struct Message
 * side effects - 
 */
static struct SVCMessage *
service_cmd_parse(struct Client *client_p, const char *cmd)
{
	rb_dlink_node *ptr;
	struct Service *service_p = NULL;
	uint32_t hashv;
	RB_DLINK_FOREACH(ptr, services.head)
	{
		service_p = (struct Service *) ptr->data;

		if(service_p->client_p == client_p)
			break;
	}

	//failed to find service
	if(service_p == NULL)
		return NULL;
		
	hashv = cmd_hash(cmd);
	RB_DLINK_FOREACH(ptr, service_p->command_tbl[hashv].head)
	{
		struct SVCMessage *mptr = ptr->data;

		if(strcasecmp(mptr->cmd, cmd) == 0)
			return mptr;
	}
	//no message
	return NULL;
}

#endif

struct Client *
create_fake_client(const char *name, const char *username, const char *host,
               const char *gecos, bool opered)
{
	struct Client *fake_p;
	
	if((fake_p = find_client(name)))
	{
		kill_client_serv_butone(NULL, fake_p, "%s (In use by services)", me.name);
		fake_p->flags |= FLAGS_KILLED;
		exit_client(NULL, fake_p, &me, "In use by services");
	}
	
	fake_p = rb_malloc(sizeof(struct Client)); 
	
	make_user(fake_p);
	
	fake_p->localClient = rb_malloc(sizeof(struct LocalUser));
	
	fake_p->from = fake_p;
	
	rb_strlcpy(fake_p->user->name, name, sizeof(fake_p->user->name));
	rb_strlcpy(fake_p->username, username, sizeof(fake_p->username));
	rb_strlcpy(fake_p->host, host, sizeof(fake_p->host));
	rb_strlcpy(fake_p->info, gecos, sizeof(fake_p->info));
	
	fake_p->name = fake_p->user->name;
	fake_p->hopcount = 0;
	fake_p->flags |= FLAGS_IP_SPOOFING|FLAGS_FAKE;
	fake_p->tsinfo = 1;
	fake_p->localClient->F = NULL;
	fake_p->localClient->firsttime = fake_p->localClient->last = rb_current_time();
	
	fake_p->umodes = UMODE_INVISIBLE;
	
	if(opered == true)
		fake_p->umodes |= UMODE_OPER;
	
	//fake_p->user->server = me.name;
	//fake_p->servptr = find_server(NULL, me.name);
	fake_p->servptr = &me;
	
	hash_add(HASH_HOSTNAME, fake_p->host, fake_p);

	strcpy(fake_p->id, generate_uid());

	hash_add(HASH_ID, fake_p->id, fake_p);
	hash_add(HASH_CLIENT, fake_p->name, fake_p);
	SetClient(fake_p);
	SetDead(fake_p);
	
	rb_dlinkAddTail(fake_p, &fake_p->node, &global_client_list);
	
	introduce_client(NULL, fake_p);
	
	return fake_p;
}

void
destroy_fake_client(struct Client *fake_p)
{
	sendto_server(fake_p, NULL, CAP_TS6, NOCAPS,
					":%s QUIT :Service unloaded", use_id(fake_p));
	sendto_server(fake_p, NULL, NOCAPS, CAP_TS6,
					":%s QUIT :Service unloaded", fake_p->name);

	hash_del(HASH_ID, fake_p->id, fake_p);
	hash_del(HASH_CLIENT, fake_p->name, fake_p);
	
	rb_dlinkDelete(&fake_p->node, &global_client_list);
	free_user(fake_p->user, fake_p);
	rb_free(fake_p->localClient);
	rb_free(fake_p);
}

struct Client *
create_fake_server(const char *name, const char *gecos, int persist)
{
	struct Client *fake_p;
	
	if((fake_p = find_server(NULL, name)))
		return NULL;
	
	fake_p = rb_malloc(sizeof(struct Client));
	
	make_server(fake_p);
	
	fake_p->localClient = rb_malloc(sizeof(struct LocalUser));
	
	fake_p->from = fake_p;
	//fake_p->serv->up = me.name;
	fake_p->servptr = &me;
	
	fake_p->name = scache_add(name);
	rb_strlcpy(fake_p->info, gecos, sizeof(fake_p->info));
	
	fake_p->hopcount = 1;
	fake_p->flags = FLAGS_FAKE;
	fake_p->localClient->F = NULL;
	
	if(persist)
		fake_p->flags |= FLAGS_FAKEPERSIST;
	
	hash_add(HASH_CLIENT, fake_p->name, fake_p);
	
	SetServer(fake_p);
	SetDead(fake_p);
	
	rb_dlinkAddTail(fake_p, &fake_p->node, &global_client_list);
	rb_dlinkAddTailAlloc(fake_p, &global_serv_list);
	
	sendto_server(NULL, NULL, NOCAPS, NOCAPS,
					":%s SERVER %s 2 :%s",
					me.name, fake_p->name, fake_p->info);
	
	return fake_p;
}

void
destroy_fake_server(struct Client *fake_p, int send_squit)
{
	if(send_squit)
		sendto_server(NULL, NULL, NOCAPS, NOCAPS,
						":%s SQUIT %s :Service unloaded",
						me.name, fake_p->name);
	
	hash_del(HASH_CLIENT, fake_p->name, fake_p);
	
	rb_dlinkDelete(&fake_p->node, &global_client_list);
	rb_dlinkFindDestroy(fake_p, &global_serv_list);
	
	rb_free(fake_p->serv);
	rb_free(fake_p->localClient);
	rb_free(fake_p);
}


void
init_fake_services(void)
{
#ifdef ENABLE_OCF_SERVICES
	add_hook("service_message", (hookfn)handle_services_message);
#endif
}
