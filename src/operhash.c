/* ircd-ratbox: an advanced Internet Relay Chat Daemon(ircd).
 * operhash.c - Hashes nick!user@host{oper}
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
#include "ratbox_lib.h"
#include "stdinc.h"
#include "struct.h"
#include "match.h"
#include "hash.h"
#include "operhash.h"

struct operhash_entry
{
	unsigned int refcount;
	char name[];
};

const char *
operhash_add(const char *name)
{
	struct operhash_entry *ohash;
	size_t len;

	if(EmptyString(name))
		return NULL;
		
	if((ohash = (struct operhash_entry *)hash_find_data(HASH_OPER, name)) != NULL)
	{
		ohash->refcount++;
		return ohash->name;
	}

	len = strlen(name) + 1;
	ohash = rb_malloc(sizeof(struct operhash_entry) + len);
	ohash->refcount = 1;
	memcpy(ohash->name, name, len);
	hash_add(HASH_OPER, ohash->name, ohash);
	return ohash->name;
}

void
operhash_delete(const char *name)
{
	hash_node *hnode;
	struct operhash_entry *ohash;

	if(EmptyString(name))
		return;

	if((hnode = hash_find(HASH_OPER, name)) == NULL)
		return;

	ohash = hnode->data;
	ohash->refcount--;
	
	if(ohash->refcount > 0)
		return;

	hash_del_hnode(HASH_OPER, hnode);
	rb_free(ohash);
}



struct ohash_usage
{
	size_t count;
	size_t memusage;
};

static void
operhash_cnt_usage(void *data, void *cbdata)
{
	struct ohash_usage *ousage = cbdata;
	struct operhash_entry *ohash = data;
	ousage->memusage += strlen(ohash->name) + sizeof(struct operhash_entry) + sizeof(hash_node);
	ousage->count++;
}


void
operhash_count(size_t * number, size_t * mem)
{
	struct ohash_usage ousage;
	memset(&ousage, 0, sizeof(ousage));
	
        hash_walkall(HASH_OPER, operhash_cnt_usage, &ousage);
        *number = ousage.count;
        *mem = ousage.memusage;
}
 
