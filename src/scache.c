/*
 *  ircd-ratbox: A slightly useful ircd.
 *  scache.c: Server names cache.
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
#include "ratbox_lib.h"
#include "match.h"
#include "ircd.h"
#include "numeric.h"
#include "send.h"
#include "hash.h"
#include "scache.h"

/*
 * this code intentionally leaks a little bit of memory, unless you're on a network
 * where you've got somebody screwing around and bursting a *lot* of servers, it shouldn't
 * be an issue...
 */

static size_t scache_allocated = 0;

const char *
scache_add(const char *name)
{
	char *sc;
	size_t len;

	if(EmptyString(name))
		return NULL;

	len = strlen(name) + 1;

	if((sc = hash_find_data_len(HASH_SCACHE, name, len)) != NULL)
		return sc;

	sc = rb_malloc(len);
	memcpy(sc, name, len);	
	scache_allocated += len;

	hash_add_len(HASH_SCACHE, sc, len, sc);
	return sc;
}

void
count_scache(size_t *number, size_t *mem)
{
	hash_get_memusage(HASH_SCACHE, number, mem);
	(*mem) += scache_allocated;
}
