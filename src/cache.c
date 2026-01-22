/*
 * ircd-ratbox: an advanced Internet Relay Chat Daemon(ircd).
 * cache.c - code for caching files
 *
 * Copyright (C) 2003 Lee Hardy <lee@leeh.co.uk>
 * Copyright (C) 2003-2026 ircd-ratbox development team
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
#include "ratbox_lib.h"
#include "struct.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "client.h"
#include "cache.h"
#include "hash.h"
#include "match.h"
#include "ircd.h"
#include "numeric.h"
#include "send.h"

static struct cachefile *user_motd = NULL;
static struct cachefile *oper_motd = NULL;
static struct cacheline emptyline = { .data[0] = ' ', .data[1] = '\0' };
static rb_dlink_list links_cache_list;
static char user_motd_changed[MAX_DATE_STRING];

/* init_cache()
 *
 * inputs	-
 * outputs	-
 * side effects - inits the file/line cache blockheaps, loads motds
 */
void
init_cache(void)
{
	user_motd_changed[0] = '\0';
	cache_user_motd();
	cache_oper_motd();
	memset(&links_cache_list, 0, sizeof(links_cache_list));
}

/* 
 * removes tabs from src, replaces with 8 spaces, and returns the length
 * of the new string.  if the new string would be greater than destlen,
 * it is truncated to destlen - 1
 */
static size_t
untabify(char *dest, const char *src, size_t destlen)
{
	size_t x = 0, i;
	const char *s = src;
	char *d = dest;

	while(*s != '\0' && x < destlen - 1)
	{
		if(*s == '\t')
		{
			for(i = 0; i < 8 && x < destlen - 1; i++, x++, d++)
				*d = ' ';
			s++;
		}
		else
		{
			*d++ = *s++;
			x++;
		}
	}
	*d = '\0';
	return x;
}


/* cache_file()
 *
 * inputs	- file to cache, files "shortname", flags to set
 * outputs	- pointer to file cached, else NULL
 * side effects -
 */
struct cachefile *
cache_file(const char *filename, const char *shortname, int flags)
{
	FILE *in;
	struct cachefile *cacheptr;
	struct cacheline *lineptr;
	char line[IRCD_BUFSIZE];
	struct stat st;
	char *p;

	if(filename == NULL || shortname == NULL)
		return NULL;

	if((in = fopen(filename, "r")) == NULL)
		return NULL;

	/* check and make sure we have something that is a file... */
	if(fstat(fileno(in), &st) == -1)
	{
		fclose(in);
		return NULL;
	}
	if(!S_ISREG(st.st_mode))
	{
		fclose(in);
		return NULL;
	}

	cacheptr = rb_malloc(sizeof(struct cachefile));

	rb_strlcpy(cacheptr->name, shortname, sizeof(cacheptr->name));
	cacheptr->flags = flags;

	/* cache the file... */
	while(fgets(line, sizeof(line), in) != NULL)
	{
		if((p = strpbrk(line, "\r\n")) != NULL)
			*p = '\0';

		if(!EmptyString(line))
		{
			lineptr = rb_malloc(sizeof(struct cacheline));
			untabify(lineptr->data, line, sizeof(lineptr->data));
			rb_dlinkAddTail(lineptr, &lineptr->linenode, &cacheptr->contents);
		}
		else
			rb_dlinkAddTailAlloc(&emptyline, &cacheptr->contents);
	}
	if(rb_dlink_list_length(&cacheptr->contents) == 0)
	{
		rb_free(cacheptr);
		cacheptr = NULL;
	}
	fclose(in);
	return cacheptr;
}

void
cache_links(void *unused)
{
	rb_dlink_node *ptr;
	rb_dlink_node *next_ptr;
	char *links_line;

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, links_cache_list.head)
	{
		rb_free(ptr->data);
		rb_free(ptr);
	}

	links_cache_list.head = links_cache_list.tail = NULL;
	links_cache_list.length = 0;

	RB_DLINK_FOREACH(ptr, global_serv_list.head)
	{
		struct Client *target_p = ptr->data;

		/* skip ourselves (done in /links) and hidden servers */
		if(IsMe(target_p) || (IsHidden(target_p) && !ConfigServerHide.disable_hidden))
			continue;

		/* if the below is ever modified, change LINKSLINELEN */
		links_line = rb_malloc(LINKSLINELEN);
		snprintf(links_line, LINKSLINELEN, "%s %s :1 %s",
			 target_p->name, me.name, target_p->info[0] ? target_p->info : "(Unknown Location)");

		rb_dlinkAddTailAlloc(links_line, &links_cache_list);
	}
}

/* free_cachefile()
 *
 * inputs	- cachefile to free
 * outputs	-
 * side effects - cachefile and its data is free'd
 */
void
free_cachefile(struct cachefile *cacheptr)
{
	rb_dlink_node *ptr;
	rb_dlink_node *next_ptr;

	if(cacheptr == NULL)
		return;

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, cacheptr->contents.head)
	{
		if(ptr->data != &emptyline)
			rb_free(ptr->data);
	}

	rb_free(cacheptr);
}

void
clear_help(void)
{
	hash_destroyall(HASH_HELP, (hash_destroy_cb *)free_cachefile);
	hash_destroyall(HASH_OHELP,(hash_destroy_cb *) free_cachefile);
}


/* load_help()
 *
 * inputs	-
 * outputs	-
 * side effects - contents of help directories are loaded.
 */
void
load_help(void)
{
	DIR *helpfile_dir = NULL;
	struct dirent *ldirent = NULL;
	char filename[MAXPATHLEN];
	struct cachefile *cacheptr;

	/* opers must be done first */
	helpfile_dir = opendir(HPATH);

	if(helpfile_dir == NULL)
		return;

	while((ldirent = readdir(helpfile_dir)) != NULL)
	{
		snprintf(filename, sizeof(filename), "%s/%s", HPATH, ldirent->d_name);
		cacheptr = cache_file(filename, ldirent->d_name, HELP_OPER);
		if(cacheptr != NULL) {
			hash_add(HASH_OHELP, cacheptr->name, cacheptr);
		}
	}

	closedir(helpfile_dir);
	helpfile_dir = opendir(UHPATH);

	if(helpfile_dir == NULL)
		return;

	while((ldirent = readdir(helpfile_dir)) != NULL)
	{
		snprintf(filename, sizeof(filename), "%s/%s", UHPATH, ldirent->d_name);
		cacheptr = cache_file(filename, ldirent->d_name, HELP_USER);
		if(cacheptr != NULL)
			hash_add(HASH_HELP, cacheptr->name, cacheptr);
	}

	closedir(helpfile_dir);
}

/* send_user_motd()
 *
 * inputs	- client to send motd to
 * outputs	- client is sent motd if exists, else ERR_NOMOTD
 * side effects -
 */
void
send_user_motd(struct Client *source_p)
{
	rb_dlink_node *ptr;
	if(user_motd == NULL || rb_dlink_list_length(&user_motd->contents) == 0)
	{
		sendto_one_numeric(source_p, s_RPL(ERR_NOMOTD));
		return;
	}
	SetCork(source_p);
	sendto_one_numeric(source_p, s_RPL(RPL_MOTDSTART), me.name);

	RB_DLINK_FOREACH(ptr, user_motd->contents.head)
	{
		struct cacheline *lineptr = ptr->data;
		sendto_one_numeric(source_p, s_RPL(RPL_MOTD), lineptr->data);
	}
	ClearCork(source_p);
	sendto_one_numeric(source_p, s_RPL(RPL_ENDOFMOTD));
}

/* send_oper_motd()
 *
 * inputs	- client to send motd to
 * outputs	- client is sent oper motd if exists
 * side effects -
 */
void
send_oper_motd(struct Client *source_p)
{
	rb_dlink_node *ptr;

	if(oper_motd == NULL || rb_dlink_list_length(&oper_motd->contents) == 0)
		return;
	SetCork(source_p);
	sendto_one_numeric(source_p, s_RPL(RPL_OMOTDSTART));

	RB_DLINK_FOREACH(ptr, oper_motd->contents.head)
	{
		struct cacheline *lineptr = ptr->data;
		sendto_one_numeric(source_p, s_RPL(RPL_OMOTD), lineptr->data);
	}
	ClearCork(source_p);
	sendto_one_numeric(source_p, s_RPL(RPL_ENDOFOMOTD));
}


void 
send_links_cache(struct Client *source_p)
{
        rb_dlink_node *ptr;
        SetCork(source_p);
        RB_DLINK_FOREACH(ptr, links_cache_list.head)
        {
        	
                sendto_one(source_p, ":%s 364 %s %s",
                           me.name, source_p->name, (const char *) ptr->data); 
        }

        sendto_one_numeric(source_p, s_RPL(RPL_LINKS), me.name, me.name, 0, me.info);
        ClearCork(source_p);
        sendto_one_numeric(source_p, s_RPL(RPL_ENDOFLINKS), "*");
}



void
cache_user_motd(void)
{
	struct stat sb;
	struct tm *local_tm;

	if(stat(MPATH, &sb) == 0)
	{
		local_tm = gmtime(&sb.st_mtime);

		if(local_tm != NULL)
		{
			snprintf(user_motd_changed, sizeof(user_motd_changed),
				 "%d/%d/%d %d:%d",
				 local_tm->tm_mday, local_tm->tm_mon + 1,
				 1900 + local_tm->tm_year, local_tm->tm_hour, local_tm->tm_min);
		}
	}
	free_cachefile(user_motd);
	user_motd = cache_file(ConfigFileEntry.motd_path, "ircd.motd", 0);
}


void
cache_oper_motd(void)
{
	free_cachefile(oper_motd);
	oper_motd = cache_file(ConfigFileEntry.oper_motd_path, "oper.motd", 0);
}


const char *
cache_user_motd_updated(void)
{
	return user_motd_changed;
}

