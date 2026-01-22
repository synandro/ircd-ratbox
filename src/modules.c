/*
 *  ircd-ratbox: A slightly useful ircd.
 *  modules.c: A module loader.
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
#include "hook.h"
#include "modules.h"
#include "s_log.h"
#include "ircd.h"
#include "client.h"
#include "send.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "numeric.h"
#include "parse.h"
#include "match.h"




#ifndef STATIC_MODULES

#include "ltdl.h"



static rb_dlink_list module_list;
static char unknown_ver[] = "<unknown>";
static const char *core_module_table[] = {
	"m_die",
	"m_error",
	"m_join",
	"m_kick",
	"m_kill",
	"m_message",
	"m_mode",
	"m_nick",
	"m_part",
	"m_quit",
	"m_server",
	"m_squit",
	NULL
};

static rb_dlink_list mod_paths;

static int unload_one_module(struct module *mod, int);
static int load_a_module(const char *, int, int);

static int mo_modload(struct Client *, struct Client *, int, const char **);
static int mo_modreload(struct Client *, struct Client *, int, const char **);
static int mo_modunload(struct Client *, struct Client *, int, const char **);
static int mo_modrestart(struct Client *, struct Client *, int, const char **);

struct Message modload_msgtab = {
	.cmd = "MODLOAD", 
	.handlers[UNREGISTERED_HANDLER] =	{ mm_unreg },
	.handlers[CLIENT_HANDLER] =		{ mm_not_oper },
	.handlers[RCLIENT_HANDLER] =		{ mm_ignore },
	.handlers[SERVER_HANDLER] =		{ mm_ignore },
	.handlers[ENCAP_HANDLER] =		{ mm_ignore },
	.handlers[OPER_HANDLER] =		{ .handler = mo_modload, .min_para = 2 },
};

struct Message modunload_msgtab = {
	.cmd = "MODUNLOAD",
	.handlers[UNREGISTERED_HANDLER] =	{ mm_unreg },
	.handlers[CLIENT_HANDLER] =		{ mm_not_oper },
	.handlers[RCLIENT_HANDLER] =		{ mm_ignore },
	.handlers[SERVER_HANDLER] =		{ mm_ignore },
	.handlers[ENCAP_HANDLER] =		{ mm_ignore },
	.handlers[OPER_HANDLER] =		{ .handler = mo_modunload, .min_para = 2 },
};

struct Message modreload_msgtab = {
	.cmd = "MODRELOAD", 
	.handlers[UNREGISTERED_HANDLER] =	{ mm_unreg },
	.handlers[CLIENT_HANDLER] =		{ mm_not_oper },
	.handlers[RCLIENT_HANDLER] =		{ mm_ignore },
	.handlers[SERVER_HANDLER] =		{ mm_ignore },
	.handlers[ENCAP_HANDLER] =		{ mm_ignore },
	.handlers[OPER_HANDLER] =		{ .handler = mo_modreload, .min_para = 2 },
};


struct Message modrestart_msgtab = {
	.cmd = "MODRESTART", 
	.handlers[UNREGISTERED_HANDLER] =	{ mm_unreg },
	.handlers[CLIENT_HANDLER] =		{ mm_not_oper },
	.handlers[RCLIENT_HANDLER] =		{ mm_ignore },
	.handlers[SERVER_HANDLER] =		{ mm_ignore },
	.handlers[ENCAP_HANDLER] =		{ mm_ignore },
	.handlers[OPER_HANDLER] =		{ .handler = mo_modrestart },
};


static int mo_modlist(struct Client *, struct Client *, int, const char **);

struct Message modlist_msgtab = {
	.cmd = "MODLIST",
	.handlers[UNREGISTERED_HANDLER] =	{ mm_unreg },
	.handlers[CLIENT_HANDLER] =		{ mm_not_oper },
	.handlers[RCLIENT_HANDLER] =		{ mm_ignore },
	.handlers[SERVER_HANDLER] =		{ mm_ignore },
	.handlers[ENCAP_HANDLER] =		{ mm_ignore },
	.handlers[OPER_HANDLER] =		{ .handler = mo_modlist },
};


extern struct Message error_msgtab;
#endif /* !STATIC_MODULES */

void
modules_init(void)
{
#ifndef STATIC_MODULES
	if(lt_dlinit())
	{
		ilog(L_MAIN, "lt_dlinit failed");
		exit(0);
	}

	mod_add_cmd(&modload_msgtab);
	mod_add_cmd(&modunload_msgtab);
	mod_add_cmd(&modreload_msgtab);
	mod_add_cmd(&modrestart_msgtab);
	mod_add_cmd(&modlist_msgtab);	/* have modlist if we are static or not */
#endif

}

#ifndef STATIC_MODULES
static void 
mod_add_list(struct module *mod)
{
	rb_dlinkAdd(mod, &mod->node, &module_list); 	
}


static void
mod_del_list(struct module *mod)
{
	rb_dlinkDelete(&mod->node, &module_list);
}

struct module *
mod_find_name(const char *name)
{
	rb_dlink_node *ptr;
	
	RB_DLINK_FOREACH(ptr, module_list.head)
	{
		struct module *mod = ptr->data;
		if(!irccmp(mod->name, name))
		{
			return mod;
		}
	
	}
	return NULL;
}


/* mod_find_path()
 *
 * input	- path
 * output	- none
 * side effects - returns a module path from path
 */
static struct module_path *
mod_find_path(const char *path)
{
	rb_dlink_node *ptr;

	RB_DLINK_FOREACH(ptr, mod_paths.head)
	{
		struct module_path *mpath = ptr->data;

		if(!strcmp(path, mpath->path))
			return mpath;
	}

	return NULL;
}

/* mod_add_path
 *
 * input	- path
 * ouput	- 
 * side effects - adds path to list
 */
void
mod_add_path(const char *path)
{
	struct module_path *pathst;

	if(mod_find_path(path))
		return;

	pathst = rb_malloc(sizeof(struct module_path));

	strcpy(pathst->path, path);
	rb_dlinkAddAlloc(pathst, &mod_paths);
}

/* mod_clear_paths()
 *
 * input	-
 * output	-
 * side effects - clear the lists of paths
 */
void
mod_clear_paths(void)
{
	rb_dlink_node *ptr, *next_ptr;

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, mod_paths.head)
	{
		rb_free(ptr->data);
		rb_free(ptr);
	}

	mod_paths.head = mod_paths.tail = NULL;
	mod_paths.length = 0;
}


/* load_all_modules()
 *
 * input	-
 * output	-
 * side effects -
 */
void
load_all_modules(int warn)
{
	static const char *shext = SHLIBEXT;
	DIR *system_module_dir = NULL;
	struct dirent *ldirent = NULL;
	char module_fq_name[PATH_MAX + 1];
	char module_dir_name[PATH_MAX + 1];
	size_t ext_len = strlen(SHLIBEXT);
	modules_init();

	rb_strlcpy(module_dir_name, AUTOMODPATH, sizeof(module_dir_name));
	system_module_dir = opendir(module_dir_name);

	if(system_module_dir == NULL)
	{
		rb_strlcpy(module_dir_name, ConfigFileEntry.dpath, sizeof(module_dir_name));
		rb_strlcat(module_dir_name, "/modules/autoload", sizeof(module_dir_name));
		system_module_dir = opendir(module_dir_name);
	}

	if(system_module_dir == NULL)
	{
		ilog(L_MAIN, "Could not load modules from %s: %s", AUTOMODPATH, strerror(errno));
		return;
	}

	while((ldirent = readdir(system_module_dir)) != NULL)
	{
		size_t len = strlen(ldirent->d_name);

		if((len > ext_len) && !strcmp(ldirent->d_name + len - ext_len, shext))
		{
			snprintf(module_fq_name, sizeof(module_fq_name), "%s/%s", module_dir_name, ldirent->d_name);
			load_a_module(module_fq_name, warn, 0);
		}
	}
	closedir(system_module_dir);
}

/* load_core_modules()
 *
 * input	-
 * output	-
 * side effects - core modules are loaded, if any fail, kill ircd
 */
void
load_core_modules(int warn)
{
	char module_name[PATH_MAX + 1];
	char dir_name[PATH_MAX + 1];
	DIR *core_dir;
	int i;

	core_dir = opendir(MODPATH);
	if(core_dir == NULL)
	{
		snprintf(dir_name, sizeof(dir_name), "%s/modules", ConfigFileEntry.dpath);
		core_dir = opendir(dir_name);
	}
	else
	{
		rb_strlcpy(dir_name, MODPATH, sizeof(dir_name));
	}


	if(core_dir == NULL)
	{
		ilog(L_MAIN,
		     "Cannot find where core modules are located(tried %s and %s): terminating ircd",
		     MODPATH, dir_name);
		exit(0);
	}


	for(i = 0; core_module_table[i]; i++)
	{

		snprintf(module_name, sizeof(module_name), "%s/%s%s", dir_name, core_module_table[i], SHLIBEXT);

		if(load_a_module(module_name, warn, 1) == -1)
		{
			ilog(L_MAIN,
			     "Error loading core module %s%s: terminating ircd", core_module_table[i], SHLIBEXT);
			exit(0);
		}
	}
	closedir(core_dir);
}

/* load_one_module()
 *
 * input	-
 * output	-
 * side effects -
 */
int
load_one_module(const char *path, int coremodule)
{
	char modpath[MAXPATHLEN*2];
	rb_dlink_node *pathst;

	struct stat statbuf;

	RB_DLINK_FOREACH(pathst, mod_paths.head)
	{
		struct module_path *mpath = pathst->data;

		snprintf(modpath, sizeof(modpath), "%s/%s", mpath->path, path);
		if((strstr(modpath, "../") == NULL) && (strstr(modpath, "/..") == NULL))
		{
			if(stat(modpath, &statbuf) == 0)
			{
				if(S_ISREG(statbuf.st_mode))
				{
					/* Regular files only please */
					if(coremodule)
						return load_a_module(modpath, 1, 1);
					else
						return load_a_module(modpath, 1, 0);
				}
			}

		}
	}

	sendto_realops_flags(UMODE_ALL, L_ALL, "Cannot locate module %s", path);
	ilog(L_MAIN, "Cannot locate module %s", path);
	return -1;
}


/* load a module .. */
static int
mo_modload(struct Client *client_p, struct Client *source_p, int parc, const char **parv)
{
	char *m_bn;

	if(!IsOperAdmin(source_p))
	{
		sendto_one_numeric(source_p, s_RPL(ERR_NOPRIVS), "admin");
		return 0;
	}

	m_bn = rb_basename(parv[1]);

	if(mod_find_name(m_bn) == NULL) 
		load_one_module(parv[1], 0);
	else 
		sendto_one_notice(source_p, ":Module %s is already loaded", m_bn);

	rb_free(m_bn);

	return 0;
}


/* unload a module .. */
static int
mo_modunload(struct Client *client_p, struct Client *source_p, int parc, const char **parv)
{
	struct module *mod;
	char *m_bn;

	if(!IsOperAdmin(source_p))
	{
		sendto_one_numeric(source_p, s_RPL(ERR_NOPRIVS), "admin");
		return 0;
	}

	m_bn = rb_basename(parv[1]);

	if((mod = mod_find_name(m_bn)) == NULL)
	{
		sendto_one_notice(source_p, ":Module %s is not loaded", m_bn);
		rb_free(m_bn);
		return 0;
	}

	if(mod->core == 1)
	{
		sendto_one_notice(source_p, ":Module %s is a core module and may not be unloaded", m_bn);
		rb_free(m_bn);
		return 0;
	}

	if(unload_one_module(mod, 1) == -1)
	{
		sendto_one_notice(source_p, ":Module %s is not loaded", m_bn);
	}
	rb_free(m_bn);
	return 0;
}

/* unload and load in one! */
static int
mo_modreload(struct Client *client_p, struct Client *source_p, int parc, const char **parv)
{
	struct module *mod;
	char *m_bn;
	int check_core;

	if(!IsOperAdmin(source_p))
	{
		sendto_one_numeric(source_p, s_RPL(ERR_NOPRIVS), "admin");
		return 0;
	}

	m_bn = rb_basename(parv[1]);

	if((mod = mod_find_name(m_bn)) == NULL)
	{
		sendto_one_notice(source_p, ":Module %s is not loaded", m_bn);
		rb_free(m_bn);
		return 0;
	}

	check_core = mod->core;

	if(unload_one_module(mod, 1) == -1)
	{
		sendto_one_notice(source_p, ":Module %s is not loaded", m_bn);
		rb_free(m_bn);
		return 0;
	}

	if((load_one_module(parv[1], check_core) == -1) && check_core)
	{
		sendto_realops_flags(UMODE_ALL, L_ALL, "Error reloading core module: %s: terminating ircd", parv[1]);
		ilog(L_MAIN, "Error loading core module %s: terminating ircd", parv[1]);
		exit(0);
	}

	rb_free(m_bn);
	return 0;
}


/* unload and reload all modules */
static int
mo_modrestart(struct Client *client_p, struct Client *source_p, int parc, const char **parv)
{
	rb_dlink_node *ptr, *next;
	unsigned int unloadcnt = 0;
	if(!IsOperAdmin(source_p))
	{
		sendto_one_numeric(source_p, s_RPL(ERR_NOPRIVS), "admin");
		return 0;
	}

	sendto_one_notice(source_p, ":Reloading all modules");


	RB_DLINK_FOREACH_SAFE(ptr, next, module_list.head)
	{
		struct module *mod = ptr->data;
		unload_one_module(mod, 0);
		unloadcnt++;
	}

	load_all_modules(0);
	load_core_modules(0);
	rehash(0);

	sendto_realops_flags(UMODE_ALL, L_ALL,
			     "Module Restart: %u modules unloaded, %ld modules loaded", unloadcnt, rb_dlink_list_length(&module_list));
	ilog(L_MAIN, "Module Restart: %u modules unloaded, %ld modules loaded", unloadcnt, rb_dlink_list_length(&module_list));
	return 0;
}

/* list modules .. */
static int
mo_modlist(struct Client *client_p, struct Client *source_p, int parc, const char **parv)
{
	rb_dlink_node *ptr;

	if(!IsOperAdmin(source_p))
	{
		sendto_one_numeric(source_p, s_RPL(ERR_NOPRIVS), "admin");
		return 0;
	}
	SetCork(source_p);

	RB_DLINK_FOREACH(ptr, module_list.head)
	{
		struct module *mod = ptr->data;
		if(parc > 1)
		{
			if(match(parv[1], mod->name))
			{
				sendto_one_numeric(source_p, s_RPL(RPL_MODLIST),
					   mod->name,
					   mod->address, mod->version, mod->core ? "(core)" : "");
			}
		}
		else
		{
			sendto_one_numeric(source_p, s_RPL(RPL_MODLIST),
				   mod->name,
				   mod->address, mod->version, mod->core ? "(core)" : "");
		}
	}
	ClearCork(source_p);
	sendto_one_numeric(source_p, s_RPL(RPL_ENDOFMODLIST));
	return 0;
}

/* unload_one_module()
 *
 * inputs	- name of module to unload
 *		- 1 to say modules unloaded, 0 to not
 * output	- 0 if successful, -1 if error
 * side effects	- module is unloaded
 */
static int
unload_one_module(struct module *mod, int warn)
{
	char *name;
	if(mod == NULL)
		return -1;

	name = LOCAL_COPY(mod->name);
	switch (mod->mapi_version)
	{
	case 2:
		{
			struct mapi_mheader_av1 *mheader = mod->mapi_header;
			if(mheader->mapi_command_list)
			{
				struct Message **m;
				for(m = mheader->mapi_command_list; *m; ++m)
					mod_del_cmd(*m);
			}

			/* hook events are never removed, we simply lose the
			 * ability to call them --fl
			 */
			if(mheader->mapi_hfn_list)
			{
				mapi_hfn_list_av1 *m;
				for(m = mheader->mapi_hfn_list; m->hapi_name; ++m)
					remove_hook(m->hapi_name, m->hookfn);
			}

			if(mheader->mapi_unregister)
				mheader->mapi_unregister();
			break;
		}
	default:
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Unknown/unsupported MAPI version %d when unloading %s!",
				     mod->mapi_version, mod->name);
		ilog(L_MAIN, "Unknown/unsupported MAPI version %d when unloading %s!",
		     mod->mapi_version, mod->name);
		break;
	}

	lt_dlclose(mod->address);

	mod_del_list(mod);
	
	rb_free(mod->name);
	rb_free(mod);
	
	if(warn == 1)
	{
		ilog(L_MAIN, "Module %s unloaded", name);
		sendto_realops_flags(UMODE_ALL, L_ALL, "Module %s unloaded", name);
	}

	return 0;
}


/*
 * load_a_module()
 *
 * inputs	- path name of module, int to notice, int of core
 * output	- -1 if error 0 if success
 * side effects - loads a module if successful
 */
int
load_a_module(const char *path, int warn, int core)
{
	lt_dlhandle tmpptr = NULL;
	struct module *mod;
	char *mod_basename;
	const char *ver;

	void *mapi_base;
	int *mapi_version;

	mod_basename = rb_basename(path);

	tmpptr = lt_dlopen(path);

	if(tmpptr == NULL)
	{
		const char *err = lt_dlerror();

		sendto_realops_flags(UMODE_ALL, L_ALL, "Error loading module %s: %s", mod_basename, err);
		ilog(L_MAIN, "Error loading module %s: %s", mod_basename, err);
		rb_free(mod_basename);
		return -1;
	}

	/*
	 * _rb_mheader is actually a struct mapi_mheader_*, but mapi_version
	 * is always the first member of this structure, so we treate it
	 * as a single int in order to determine the API version.
	 *	-larne.
	 */
	mapi_base = lt_dlsym(tmpptr, "_rb_mheader");
	if(mapi_base == NULL)
	{
		mapi_base = lt_dlsym(tmpptr, "__rb_mheader");
	}

	mapi_version = (int *)mapi_base;

	if(mapi_base == NULL || (MAPI_MAGIC(*mapi_version) != MAPI_MAGIC_HDR))
	{
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Data format error: module %s has no MAPI header.", mod_basename);
		ilog(L_MAIN, "Data format error: module %s has no MAPI header.", mod_basename);
		lt_dlclose(tmpptr);
		rb_free(mod_basename);
		return -1;
	}

	switch (MAPI_VERSION(*mapi_version))
	{
	case 2:
		{
			struct mapi_mheader_av1 *mheader = mapi_base;	/* see above */
			if(mheader->mapi_register && (mheader->mapi_register() == -1))
			{
				ilog(L_MAIN, "Module %s indicated failure during load.", mod_basename);
				sendto_realops_flags(UMODE_ALL, L_ALL,
						     "Module %s indicated failure during load.", mod_basename);
				lt_dlclose(tmpptr);
				rb_free(mod_basename);
				return -1;
			}
			if(mheader->mapi_command_list)
			{
				struct Message **m;
				for(m = mheader->mapi_command_list; *m; ++m)
					mod_add_cmd(*m);
			}

			if(mheader->mapi_hook_list)
			{
				mapi_hlist_av1 *m;
				for(m = mheader->mapi_hook_list; m->hapi_name; ++m)
					*m->hapi_id = register_hook(m->hapi_name);
			}

			if(mheader->mapi_hfn_list)
			{
				mapi_hfn_list_av1 *m;
				for(m = mheader->mapi_hfn_list; m->hapi_name; ++m)
					add_hook(m->hapi_name, m->hookfn);
			}

			ver = mheader->mapi_module_version;
			break;
		}

	default:
		ilog(L_MAIN, "Module %s has unknown/unsupported MAPI version %d.",
		     mod_basename, MAPI_VERSION(*mapi_version));
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Module %s has unknown/unsupported MAPI version %d.", mod_basename, *mapi_version);
		lt_dlclose(tmpptr);
		rb_free(mod_basename);
		return -1;
	}

	if(ver == NULL)
		ver = unknown_ver;

	mod = rb_malloc(sizeof(struct module));
	mod->address = tmpptr;
	mod->version = ver;
	mod->core = core;
	mod->name = rb_strdup(mod_basename);
	mod->mapi_header = mapi_version;
	mod->mapi_version = MAPI_VERSION(*mapi_version);
	mod_add_list(mod);
	
	if(warn == 1)
	{
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Module %s [version: %s; MAPI version: %d] loaded at %p",
				     mod_basename, ver, MAPI_VERSION(*mapi_version), (void *)tmpptr);
		ilog(L_MAIN, "Module %s [version: %s; MAPI version: %d] loaded at %p",
		     mod_basename, ver, MAPI_VERSION(*mapi_version), (void *)tmpptr);
	}
	rb_free(mod_basename);
	return 0;
}

#endif /* !STATIC_MODULES */


#ifdef STATIC_MODULES
extern const struct mapi_header_av1 *static_mapi_headers[];
void
load_static_modules(void)
{
	int x;
	const int *mapi_version;

	modules_init();
	for(x = 0; static_mapi_headers[x] != NULL; x++)
	{
		mapi_version = (const int *)static_mapi_headers[x];
		if(MAPI_MAGIC(*mapi_version) != MAPI_MAGIC_HDR)
		{
			ilog(L_MAIN, "Error: linked in module without a MAPI header..giving up");
			exit(70);
		}
		switch (MAPI_VERSION(*mapi_version))
		{
		case 2:
			{
				const struct mapi_mheader_av1 *mheader = (const struct mapi_mheader_av1 *)mapi_version;
				if(mheader->mapi_register && (mheader->mapi_register() == -1))
				{
					ilog(L_MAIN, "Error: linked in module failed loading..giving up");
					exit(70);
				}

				if(mheader->mapi_command_list)
				{
					struct Message **m;
					for(m = mheader->mapi_command_list; *m; ++m)
						mod_add_cmd(*m);
				}

				if(mheader->mapi_hook_list)
				{
					mapi_hlist_av1 *m;
					for(m = mheader->mapi_hook_list; m->hapi_name; ++m)
						*m->hapi_id = register_hook(m->hapi_name);
				}

				if(mheader->mapi_hfn_list)
				{
					mapi_hfn_list_av1 *m;
					for(m = mheader->mapi_hfn_list; m->hapi_name; ++m)
						add_hook(m->hapi_name, m->hookfn);

				}
				break;
			}
		default:
			{
				ilog(L_MAIN,
				     "Error: Unknown MAPI version (%d)in linked in module..giving up",
				     MAPI_VERSION(*mapi_version));
				exit(70);
			}
		}
	}
}
#endif
