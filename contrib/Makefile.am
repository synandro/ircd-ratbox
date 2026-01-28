#
# Makefile.am: stuff for automake to vomit back up in a digested form



prefix          = @prefix@
libcoredir      = @libdir@
modulesdir      = @moduledir@/autoload
coredir         = @moduledir@
servicesdir     = @moduledir@/autoload
libmodulesdir   = @moduledir@
contribdir	= @moduledir@/contrib

AM_CPPFLAGS = -I../include -I../libratbox/include $(INCLTDL)
AM_CFLAGS=$(WARNFLAGS)

#if MINGW
#EXTRA_FLAGS = -no-undefined -Wl,--enable-runtime-pseudo-reloc -export-symbols-regex '*'
#endif


MODULE_FLAGS = $(EXTRA_FLAGS) -avoid-version



SRCS = \
example_module.c        \
m_42.c  	\
m_clearchan.c   \
m_flags.c       \
m_force.c       \
m_mkpasswd.c    \
m_ojoin.c       \
m_okick.c       \
m_olist.c       \
m_opme.c        \
m_webirc.c	\
spy_admin_notice.c      \
spy_info_notice.c       \
spy_links_notice.c      \
spy_motd_notice.c       \
spy_stats_notice.c      \
spy_stats_p_notice.c    \
spy_whois_notice.c      \
spy_whois_notice_global.c

ALL_SRCS = $(SRCS)
S_OBJS = $(ALL_SRCS:.c=.la)
S_CORE_OBJS = $(CORE_SRCS:.c=.la)
ST_OBJS = $(ALL_SRCS:.c=.lo) $(CORE_SRCS:.c=.lo)
SUFFIXES = .c .so .lo .la

.c.lo:
	$(LIBTOOL) --mode=compile $(CC) -prefer-pic -DHAVE_CONFIG_H $(INCLUDES) $(AM_CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c $< -o $@

.lo.la:
	$(LIBTOOL) --mode=link  $(CC) -rpath $(moduledir) -module -avoid-version $(AM_CFLAGS) $(CFLAGS) -o $@ $< $(LIBS) $(LDFLAGS) 

all: $(S_OBJS) $(S_CORE_OBJS) 

clean-generic:
	$(LIBTOOL) --mode=clean $(RB_RM) -f $(S_OBJS) $(S_CORE_OBJS)  $(ST_OBJS)

install_modules: $(S_OBJS)
	-@@$(MKDIR_P) $(DESTDIR)$(contribdir); \
	for x in $(S_OBJS); do $(SHELL) ../install-mod.sh $$x $(DESTDIR)$(contribdir);done

#install-mkdirs:
#	@echo "ircd: setting up modular directory structure"
#	-@if test ! -d $(DESTDIR)$(moduledir); then \
#		mkdir $(DESTDIR)$(moduledir); \
#	fi
#	-@if test -d $(DESTDIR)$(moduledir)-old; then \
#		rm -rf $(DESTDIR)$(moduledir)-old; \
#	fi
#	-@if test -d $(DESTDIR)$(moduledir); then \
#		echo "ircd: backing up modules"; \
#		mv $(DESTDIR)$(moduledir) $(DESTDIR)$(moduledir)-old; \
#	fi
#
#	@mkdir -p -m 755 $(DESTDIR)$(moduledir)

install: install_modules
