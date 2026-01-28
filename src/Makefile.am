#
# Makefile.am: stuff for automake to vomit back up in a digested form


AUTOMAKE_OPTIONS = foreign

prefix		= @prefix@
libcoredir	= @libdir@

AM_YFLAGS = -d
AM_CFLAGS = $(WARNFLAGS)
AM_CPPFLAGS = -I../libratbox/include $(LTDLINCL) @OpenSSL_CFLAGS@ @PICFLAGS@

BUILT_SOURCES = version.c

version.c: version.c.SH ../CREDITS ../include/version.h ../include/serno.h
	$(SHELL) version.c.SH
	$(CP) version.c version.c.last
	touch version.c.SH
                
libcore_la_SOURCES =			\
        bandbi.c                        \
        cache.c                         \
        channel.c                       \
        class.c                         \
        client.c                        \
	dns.c                           \
        getopt.c                        \
        hash.c                          \
        hook.c                          \
        hostmask.c                      \
        ipv4_from_ipv6.c                \
        ircd.c                          \
        ircd_lexer.l			\
        ircd_parser.y                   \
        ircd_signal.c                   \
        listener.c                      \
        match.c                         \
        modules.c                       \
        monitor.c                       \
        newconf.c                       \
        operhash.c                      \
        packet.c                        \
        parse.c                         \
        reject.c                        \
        s_auth.c                        \
        scache.c                        \
        s_conf.c                        \
        send.c                          \
        services.c			\
        s_log.c                         \
        s_newconf.c                     \
        s_serv.c                        \
        sslproc.c                       \
        substitution.c                  \
        supported.c                     \
        s_user.c                        \
        version.c                       \
        whowas.c                        
                        
libcore_LTLIBRARIES = libcore.la
libcore_la_LDFLAGS = $(EXTRA_FLAGS) -avoid-version

libcore_la_DEPENDENCIES = ../libratbox/src/libratbox.la
libcore_la_LIBADD = ../libratbox/src/libratbox.la $(LIBLTDL) @OpenSSL_LIBS@ @LIBJEMALLOC@ @LIBTCMALLOC@


install-exec-hook: install-libcoreLTLIBRARIES
	$(RB_RM) -f version.c

