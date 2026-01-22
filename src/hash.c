/* 
 *  ircd-ratbox: A slightly useful ircd.
 *  hash.c: Maintains hashtables.
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
#include "hash.h"
#include "s_conf.h"
#include "channel.h"
#include "client.h"
#include "match.h"
#include "ircd.h"
#include "numeric.h"
#include "send.h"
#include "cache.h"
#include "s_newconf.h"
#include "s_log.h"
#include "s_stats.h"


/* Magic value for FNV hash functions */
#define FNV1_32_INIT 0x811c9dc5UL

/*
 * Hashing.
 *
 *   The server uses a chained hash table to provide quick and efficient
 * hash table maintenance (providing the hash function works evenly over
 * the input range).  The hash table is thus not susceptible to problems
 * of filling all the buckets or the need to rehash.
 *    It is expected that the hash table would look something like this
 * during use:
 *		     +-----+	+-----+	   +-----+   +-----+
 *		  ---| 224 |----| 225 |----| 226 |---| 227 |---
 *		     +-----+	+-----+	   +-----+   +-----+
 *			|	   |	      |
 *		     +-----+	+-----+	   +-----+
 *		     |	A  |	|  C  |	   |  D	 |
 *		     +-----+	+-----+	   +-----+
 *			|
 *		     +-----+
 *		     |	B  |
 *		     +-----+
 *
 * A - GOPbot, B - chang, C - hanuaway, D - *.mu.OZ.AU
 *
 * The order shown above is just one instant of the server. 
 *
 *
 * The hash functions currently used are based Fowler/Noll/Vo hashes
 * which work amazingly well and have a extremely low collision rate
 * For more info see http://www.isthe.com/chongo/tech/comp/fnv/index.html
 *
 * 
 */

hash_f *hash_client;
hash_f *hash_id;
hash_f *hash_channel;
hash_f *hash_hostname;
hash_f *hash_resv;
hash_f *hash_oper;
hash_f *hash_scache;
hash_f *hash_help;
hash_f *hash_ohelp;
hash_f *hash_nd;
hash_f *hash_connid;
hash_f *hash_zconnid;
hash_f *hash_monitor;
hash_f *hash_command;

/* init_hash()
 *
 * clears the various hashtables
 */
void
init_hash(void)
{
	hash_client = hash_create("NICK", CMP_IRCCMP, U_MAX_BITS, 0);
	hash_id = hash_create("ID", CMP_STRCMP, U_MAX_BITS, 0);
	hash_channel = hash_create("Channel", CMP_IRCCMP, CH_MAX_BITS, 30);
	hash_hostname = hash_create("Host", CMP_IRCCMP, HOST_MAX_BITS, 30);
	hash_resv = hash_create("Channel RESV", CMP_IRCCMP, R_MAX_BITS, 30);
	hash_oper = hash_create("Operator", CMP_IRCCMP, OPERHASH_MAX_BITS, 0);
	hash_scache = hash_create("Server", CMP_IRCCMP, SCACHE_MAX_BITS, 0);
	hash_help = hash_create("Help", CMP_IRCCMP, HELP_MAX_BITS, 10);
	hash_ohelp = hash_create("Operator Help", CMP_IRCCMP, HELP_MAX_BITS, 10);
	hash_nd = hash_create("ND", CMP_IRCCMP, U_MAX_BITS, 0);
	hash_connid = hash_create("Connection ID", CMP_MEMCMP, CLI_CONNID_MAX_BITS, sizeof(uint32_t));
	hash_zconnid = hash_create("Ziplinks ID", CMP_MEMCMP, CLI_ZCONNID_MAX_BITS, sizeof(uint32_t));
	hash_monitor = hash_create("MONITOR", CMP_IRCCMP, MONITOR_MAX_BITS, 0);
	hash_command = hash_create("Command", CMP_IRCCMP, COMMAND_MAX_BITS, 10);
}

/* fnv_hash_len_data hashses any data */
static uint32_t
fnv_hash_len_data(const unsigned char *s, unsigned int bits, size_t len)
{
	uint32_t h = FNV1_32_INIT;
	const unsigned char *x = s + len;
	while(s < x)
	{
		h ^= *s++;
		h += (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24);
	}
	h = (h >> (32 - bits)) ^ (h & ((1U << bits) - 1));
	return h;
}

static uint32_t
fnv_hash_upper(const unsigned char *s, unsigned int bits, size_t unused)
{
	uint32_t h = FNV1_32_INIT;
	while(*s)
	{
		h ^= ToUpper(*s++);
		h += (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24);
	}
	h = (h >> (32 - bits)) ^ (h & ((1U << bits) - 1));
	return h;
}

static uint32_t
fnv_hash(const unsigned char *s, unsigned int bits, size_t unused)
{
	uint32_t h = FNV1_32_INIT;
	while(*s)
	{
		h ^= *s++;
		h += (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24);
	}
	h = (h >> (32 - bits)) ^ (h & ((1U << bits) - 1));
	return h;
}

#if 1				/* unused currently */

static uint32_t
fnv_hash_len(const unsigned char *s, unsigned int bits, size_t len)
{
	uint32_t h = FNV1_32_INIT;
	const unsigned char *x = s + len;
	while(s < x && *s)
	{
		h ^= *s++;
		h += (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24);
	}
	h = (h >> (32 - bits)) ^ (h & ((1U << bits) - 1));
	return h;
}
#endif

static uint32_t
fnv_hash_upper_len(const unsigned char *s, unsigned int bits, size_t len)
{
	uint32_t h = FNV1_32_INIT;
	const unsigned char *x = s + len;
	while(s < x && *s)
	{
		h ^= ToUpper(*s++);
		h += (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24);
	}
	h = (h >> (32 - bits)) ^ (h & ((1U << bits) - 1));
	return h;
}

static void
free_hashnode(hash_node * hnode)
{
	rb_free(hnode->key);
	rb_free(hnode);
}

typedef bool hash_cmp(const void *x, const void *y, size_t len);


struct _hash_function
{
	char *name;
	uint32_t(*func) (unsigned const char *, unsigned int, size_t);
	hash_cmptype cmptype;
	rb_dlink_list **htable;
	unsigned int hashbits;
	unsigned int hashlen;
};

static rb_dlink_list list_of_hashes;

static void
hash_free(hash_f *hf)
{
	rb_dlinkFindDestroy(hf, &list_of_hashes);
	rb_free(hf->name);
	rb_free(hf->htable);
	rb_free(hf);
}

hash_f *
hash_create(const char *name, hash_cmptype cmptype, unsigned int hashbits, unsigned int maxkeylen)
{
	hash_f *hfunc;

	/* save us some messy cleanup later */
	if(cmptype == CMP_MEMCMP && maxkeylen == 0)
		return NULL;

	hfunc = rb_malloc(sizeof(struct _hash_function));

	hfunc->name = rb_strdup(name);
	hfunc->hashbits = hashbits;
	hfunc->htable = rb_malloc(sizeof(rb_dlink_list *) * (1 << hashbits));
	hfunc->cmptype = cmptype;
	hfunc->hashlen = maxkeylen; 
	switch(cmptype)
	{
		case CMP_IRCCMP:
			if(hfunc->hashlen > 0)
				hfunc->func = fnv_hash_upper_len;
			else
				hfunc->func = fnv_hash_upper;
			break;
		case CMP_STRCMP:
			if(hfunc->hashlen > 0)
				hfunc->func = fnv_hash_len;
			else
				hfunc->func = fnv_hash;
			break;
		case CMP_MEMCMP:
			hfunc->func = fnv_hash_len_data;
			break;
	
	}
	rb_dlinkAddAlloc(hfunc, &list_of_hashes);
	return hfunc;	

}

static inline uint32_t do_hfunc(hash_f *hf, const void *hashindex, size_t hashlen)
{
	return hf->func((unsigned const char *)hashindex, hf->hashbits, hashlen);
}


static inline int
hash_do_cmp(hash_f *hfunc, hash_node *hnode, const void *hashindex, size_t len)
{
	if(hnode->keylen != len)
		return -1;
	
	switch (hfunc->cmptype)
	{
	/* the irccmp and strcmp types assume there is a \0 delimited string in both buffers */
	case CMP_IRCCMP:
		return irccmp(hnode->key, hashindex);
	case CMP_STRCMP:
		return strcmp(hnode->key, hashindex);
	case CMP_MEMCMP:
		return memcmp(hnode->key, hashindex, len);
	}
	return -1;
}


void
hash_free_list(rb_dlink_list * table)
{
	rb_dlink_node *ptr, *next;
	RB_DLINK_FOREACH_SAFE(ptr, next, table->head)
	{
		rb_free(ptr);
	}
	rb_free(table);
}

rb_dlink_list *
hash_find_list_len(hash_f *hf, const void *hashindex, size_t size)
{
	rb_dlink_list *bucket;
	rb_dlink_list *results;
	size_t hashlen;
	uint32_t hashv;
	rb_dlink_node *ptr;

	if(hashindex == NULL || hf == NULL)
		return NULL;

	if(hf->hashlen == 0)
		hashlen = size;
	else
		hashlen = IRCD_MIN(size, hf->hashlen);

	hashv = do_hfunc(hf, hashindex, hashlen);
	
	if(hf->htable[hashv] == NULL)
		return NULL;

	bucket = hf->htable[hashv];

	results = rb_malloc(sizeof(rb_dlink_list));

	RB_DLINK_FOREACH(ptr, bucket->head)
	{
		hash_node *hnode = ptr->data;
		if(hash_do_cmp(hf, hnode, hashindex, size) == 0)
			rb_dlinkAddAlloc(hnode->data, results);
	}
	if(rb_dlink_list_length(results) == 0)
	{
		rb_free(results);
		return NULL;
	}
	return results;
}

rb_dlink_list *
hash_find_list(hash_f *hf, const char *hashindex)
{
	if(hf == NULL || EmptyString(hashindex))
		return NULL;
	return hash_find_list_len(hf, hashindex, strlen(hashindex) + 1);
}

hash_node *
hash_find_len(hash_f *hf, const void *hashindex, size_t size)
{
	rb_dlink_list *bucket; // = hash_function[type].table;

	size_t hashlen;
	uint32_t hashv;
	rb_dlink_node *ptr;

	if(hf == NULL || hashindex == NULL)
		return NULL;

	if(hf->hashlen == 0)
		hashlen = size;
	else
		hashlen = IRCD_MIN(size, hf->hashlen);

	hashv = do_hfunc(hf, hashindex, hashlen);
	
	if(hf->htable[hashv] == NULL)
		return NULL;
	
	bucket = hf->htable[hashv];

	RB_DLINK_FOREACH(ptr, bucket->head)
	{
		hash_node *hnode = ptr->data;

		if(hash_do_cmp(hf, hnode, hashindex, size) == 0)
			return hnode;
	}
	return NULL;
}

hash_node *
hash_find(hash_f *hf, const char *hashindex)
{
	if(hf == NULL || EmptyString(hashindex))
		return NULL;
	return hash_find_len(hf, hashindex, strlen(hashindex) + 1);
}

void *
hash_find_data_len(hash_f *hf, const void *hashindex, size_t size)
{
	hash_node *hnode;
	hnode = hash_find_len(hf, hashindex, size);
	if(hnode == NULL)
		return NULL;
	return hnode->data;
}

void *
hash_find_data(hash_f *hf, const char *hashindex)
{
	if(hf == NULL || EmptyString(hashindex))
		return NULL;
	return hash_find_data_len(hf, hashindex, strlen(hashindex) + 1);
}

static rb_dlink_list *
hash_allocate_bucket(hash_f *hf, uint32_t hashv)
{
	if(hf->htable[hashv] != NULL)
		return hf->htable[hashv];
	hf->htable[hashv] = rb_malloc(sizeof(rb_dlink_list));
	return hf->htable[hashv];
}

static void
hash_free_bucket(hash_f *hf, uint32_t hashv)
{
	if(rb_dlink_list_length(hf->htable[hashv]) > 0)
		return;
	rb_free(hf->htable[hashv]);
	hf->htable[hashv] = NULL;
}

hash_node *
hash_add_len(hash_f *hf, const void *hashindex, size_t indexlen, void *pointer)
{
	rb_dlink_list *bucket; // = hash_function[type].table;
	hash_node *hnode;
	uint32_t hashv;

	if(hf == NULL || hashindex == NULL || pointer == NULL)
		return NULL;

	hashv = do_hfunc(hf, hashindex, IRCD_MIN(indexlen, hf->hashlen));
	bucket = hash_allocate_bucket(hf, hashv);
	hnode = rb_malloc(sizeof(hash_node));
	hnode->key = rb_malloc(indexlen);
	hnode->keylen = indexlen;
	memcpy(hnode->key, hashindex, indexlen);
	hnode->hashv = hashv;
	hnode->data = pointer;
	rb_dlinkAdd(hnode, &hnode->node, bucket);
	return hnode;
}

hash_node *
hash_add(hash_f *hf, const char *hashindex, void *pointer)
{
	if(hf == NULL || EmptyString(hashindex))
		return NULL;
	return hash_add_len(hf, hashindex, strlen(hashindex) + 1, pointer);
}

void
hash_del_len(hash_f *hf, const void *hashindex, size_t size, void *pointer)
{
	rb_dlink_list *bucket;
	rb_dlink_node *ptr;
	uint32_t hashv;
	size_t hashlen;

	if(hf == NULL || pointer == NULL || hashindex == NULL)
		return;

	if(hf->hashlen == 0)
		hashlen = size;
	else
		hashlen = IRCD_MIN(size, hf->hashlen);

	hashv = do_hfunc(hf, hashindex, hashlen);
	bucket = hf->htable[hashv];

	if(bucket == NULL)
		return;
	
	RB_DLINK_FOREACH(ptr, bucket->head)
	{
		hash_node *hnode = ptr->data;
		if(hnode->data == pointer)
		{
			rb_dlinkDelete(&hnode->node, bucket);
			free_hashnode(hnode);
			hash_free_bucket(hf, hashv);
			return;
		}
	}
}

void
hash_del(hash_f *hf, const char *hashindex, void *pointer)
{
	if(hf == NULL || EmptyString(hashindex))
		return;
	hash_del_len(hf, hashindex, strlen(hashindex) + 1, pointer);
}

void
hash_del_hnode(hash_f *hf, hash_node * hnode)
{
	rb_dlink_list *bucket; 
	uint32_t hashv;	
	if(hf == NULL || hnode == NULL)
		return;

	hashv = hnode->hashv;
	bucket = hf->htable[hashv];

	if(bucket == NULL)
		return;

	rb_dlinkDelete(&hnode->node, bucket);
	free_hashnode(hnode);
	hash_free_bucket(hf, hashv);
}

void
hash_destroyall(hash_f *hf, hash_destroy_cb * destroy_cb)
{
	for(int i = 0; i < (1 << hf->hashbits); i++)
	{
		rb_dlink_list *ltable;
		rb_dlink_node *ptr, *nptr;
		
		ltable = hf->htable[i];
		if(ltable == NULL)
			continue;
		RB_DLINK_FOREACH_SAFE(ptr, nptr, ltable->head)
		{
			hash_node *hnode = ptr->data;
			void *cbdata = hnode->data;
			
			rb_dlinkDelete(ptr, ltable);
			free_hashnode(hnode);
			if(destroy_cb != NULL)
				destroy_cb(cbdata);
		}
		hash_free_bucket(hf, i);
	}
	hash_free(hf);
}

void
hash_walkall(hash_f *hf, hash_walk_cb * walk_cb, void *walk_data)
{
	for(unsigned int i = 0; i < ( 1 << hf->hashbits); i++)
	{
		rb_dlink_list *ltable;
		rb_dlink_node *ptr, *next_ptr;
		
		ltable = hf->htable[i];
		if(ltable == NULL)
			continue;

		RB_DLINK_FOREACH_SAFE(ptr, next_ptr, ltable->head)
		{
			hash_node *hnode = ptr->data;
			void *cbdata = hnode->data;
			walk_cb(cbdata, walk_data);
		
		}
	}
}

rb_dlink_list *
hash_get_tablelist(hash_f *hf)
{
	rb_dlink_list *alltables;

	alltables = rb_malloc(sizeof(rb_dlink_list));

	for(int i = 0; i < (1 << hf->hashbits); i++)
	{
		rb_dlink_list *table = hf->htable[i];
		
		if(table == NULL || rb_dlink_list_length(table) == 0)
			continue;
		rb_dlinkAddAlloc(table, alltables);
	}

	if(rb_dlink_list_length(alltables) == 0)
	{
		rb_free(alltables);
		alltables = NULL;
	}
	return alltables;
}

void
hash_free_tablelist(rb_dlink_list * table)
{
	rb_dlink_node *ptr, *next;
	RB_DLINK_FOREACH_SAFE(ptr, next, table->head)
	{
		rb_free(ptr);
	}
	rb_free(table);
}

static void
output_hash(struct Client *source_p, const char *name, unsigned long length, unsigned long *counts,
	    unsigned long deepest)
{
	unsigned long total = 0;

	sendto_one_numeric(source_p, RPL_STATSDEBUG, "B :%s Hash Statistics", name);

	sendto_one_numeric(source_p, RPL_STATSDEBUG, "B :Size: %lu Empty: %lu (%.3f%%)",
			   length, counts[0], (float) ((counts[0] * 100) / (float) length));

	for(unsigned long i = 1; i < 11; i++)
	{
		total += (counts[i] * i);
	}

	/* dont want to divide by 0! --fl */
	if(counts[0] != length)
	{
		sendto_one_numeric(source_p, RPL_STATSDEBUG,
				   "B :Average depth: %.3f%%/%.3f%% Highest depth: %lu",
				   (float) (total / (length - counts[0])), (float) (total / length), deepest);
	}

	for(unsigned long i = 1; i < IRCD_MIN(11, deepest + 1); i++)
	{
		sendto_one_numeric(source_p, RPL_STATSDEBUG, "B :Nodes with %lu entries: %lu", i, counts[i]);
	}
}

static void
count_hash(struct Client *source_p, rb_dlink_list ** table, unsigned int length, const char *name)
{
	unsigned long counts[11];
	unsigned long deepest = 0;
	unsigned long i;

	memset(counts, 0, sizeof(counts));

	for(i = 0; i < length; i++)
	{
		if(table[i] == NULL) 
		{
			counts[0]++;
			continue;
		}
	
		if(rb_dlink_list_length(table[i]) >= 10)
			counts[10]++;
		else
			counts[rb_dlink_list_length(table[i])]++;

		if(rb_dlink_list_length(table[i]) > deepest)
			deepest = rb_dlink_list_length(table[i]);
	}

	output_hash(source_p, name, length, counts, deepest);
}

void
hash_stats(struct Client *source_p)
{
	rb_dlink_node *ptr;
	
	RB_DLINK_FOREACH(ptr, list_of_hashes.head)
	{
		hash_f *hf = ptr->data;
		count_hash(source_p, hf->htable, 1 << hf->hashbits, hf->name);
		sendto_one_numeric(source_p, RPL_STATSDEBUG, "B :--");
	}
}

void
hash_get_memusage(hash_f *hf, size_t * entries, size_t * memusage)
{
	rb_dlink_list **htable;
	rb_dlink_node *ptr;
	hash_node *hnode;
	size_t mem = 0, cnt = 0;
	unsigned int max, i;
	max = 1 << hf->hashbits;

	htable = hf->htable;
	for(i = 0; i < max; i++)
	{
		if(htable[i] == NULL)
			continue;

		mem += sizeof(rb_dlink_list);
		RB_DLINK_FOREACH(ptr, htable[i]->head)
		{
			hnode = ptr->data;
			mem += hnode->keylen + sizeof(hash_node);
			cnt++;
		} 
	}
	if(memusage != NULL)
		*memusage = mem;
	if(entries != NULL)
		*entries = cnt;
}
