# okay so i've flattened out the build stuff here.
# this is really for the best since so many things depend
# on each other now..

AUTOMAKE_OPTIONS = foreign subdir-objects 

prefix		= @prefix@
libcoredir 	= @libdir@
modulesdir	= @moduledir@/autoload
coredir		= @moduledir@
servicesdir	= @moduledir@/autoload


AM_CFLAGS = $(WARNFLAGS)

ircd_ratbox_SOURCES = main.c
bin_PROGRAMS = ircd-ratbox

if !STATIC_MODULES

SUBDIRS = @LTDL_SUBDIR@ libratbox src modules tools doc help bandb ssld resolver

ircd_ratbox_LDADD =  src/libcore.la libratbox/src/libratbox.la $(LIBLTDL) @LIBJEMALLOC@ @LIBTCMALLOC@
ircd_ratbox_LDFLAGS = $(EXTRA_FLAGS) -dlopen self

else

SUBDIRS = @LTDL_SUBDIR@ libratbox modules src tools doc help bandb ssld resolver
ircd_ratbox_LDADD = libratbox/src/libratbox.la modules/libmodules.la src/libcore.la modules/static_modules.o $(LIBLTDL) $(DLOPEN) @LIBJEMALLOC@ @LIBTCMALLOC@


endif

build_contrib:
	cd contrib && $(MAKE)

install_contrib: build_contrib
	cd contrib && $(MAKE) install

install-data-local:
	-@if test ! -d @logdir@; then mkdir @logdir@;fi

distclean_contrib: build_contrib
	cd contrib && $(MAKE) distclean

contrib: build_contrib


