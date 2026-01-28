dnl 
dnl Process this file with autoconf to produce a configure script.

dnl TODO: clean up all the OpenSSL and shared module checking stuff;
dnl the most major changes have already been made and it looks like
dnl said functions need to be just about as complex as they already are.

AC_PREREQ(2.63)
AUTOMAKE_OPTIONS = 1.10

dnl Sneaky way to get an Id tag into the configure script
AC_COPYRIGHT([])
AC_INIT([ircd-ratbox],[devel])
AC_CONFIG_AUX_DIR([libltdl/config])
AC_CONFIG_MACRO_DIR([libltdl/m4])


AM_INIT_AUTOMAKE([subdir-objects])

AM_CONFIG_HEADER(include/setup.h)

AC_PREFIX_DEFAULT(/usr/local/ircd-ratbox)
AC_GNU_SOURCE

dnl Checks for programs.
AC_PATH_PROG(CP, cp)
AC_PATH_PROG(MV, mv)
AC_PATH_PROG(RB_RM, rm)

dnl autoconf likes to put -O2 everywhere...like a jerk
AC_PROG_CC_C99



if test x"$ac_cv_prog_cc_c99" = "xno"; then
	AC_ERROR([ircd-ratbox requires a C99 capable compiler])
fi


AC_CANONICAL_HOST

AM_PROG_LEX

AC_PROG_INSTALL
AC_PROG_EGREP

F77=no
GCJ=no

AM_DISABLE_STATIC
AM_ENABLE_SHARED
AM_MAINTAINER_MODE([disable])

AC_ISC_POSIX
AC_C_INLINE
AC_PROG_GCC_TRADITIONAL
AC_PROG_MAKE_SET
AC_PROG_INSTALL

srcpwd=`cd ${srcdir} ; ${PWDCMD-pwd}`

# We pase INSTALL explicitly to sub-makes.  Make sure that it is not
# a relative path.
if test "$INSTALL" = "${srcdir}/install-sh -c"; then
  INSTALL="${srcpwd}/install-sh -c"
fi

AC_PROG_YACC
AC_LANG(C)

AM_CONDITIONAL([STATIC_MODULES], test "$enable_static" = "yes")

if test x"$enable_static" = "xyes"; then
	AC_DEFINE(STATIC_MODULES, 1, "Use static modules")
fi 

cc_accepts_flag()
{
        cc_accepts_flag_CFLAGS="$CFLAGS" 
        CFLAGS="$* -Werror" 
        AC_MSG_CHECKING([whether $CC accepts $@])
        AC_COMPILE_IFELSE([AC_LANG_SOURCE([int main(){return 0;}])] ,
        [RC=0; AC_MSG_RESULT([yes])],
        [RC=1; AC_MSG_RESULT([no])])
        CFLAGS="$cc_accepts_flag_CFLAGS"
        return $RC
}

have_win=no 
case "$host_os" in
        mingw*)
                have_win=yes
        ;;
        cygwin*)
        	have_win=yes
        ;;
esac
        

if test xyes != x"$have_win"; then


${CC} -v 2>&1 | grep -q clang

if test $? -eq 0 ; then
	CFLAGS="$CFLAGS -fstack-protector -D_FORTIFY_SOURCE=2"
else if cc_accepts_flag -fstack-protector-strong; then
	CFLAGS="$CFLAGS -fstack-protector-strong -D_FORTIFY_SOURCE=2"
else if cc_accepts_flag -fstack-protector-all; then
	CFLAGS="$CFLAGS -fstack-protector-all -D_FORTIFY_SOURCE=2"
else if cc_accepts_flag -fstack-protector; then
	CFLAGS="$CFLAGS -fstack-protector -D_FORTIFY_SOURCE=2"
fi
fi
fi
fi
fi



  
WARNLIST="  
	all  
	cast-qual
	missing-declarations
	missing-prototypes  
	nested-externs
	shadow
	write-strings
	no-unused
	unused-function
	unused-variable" 

for x in $WARNLIST; do 
	if cc_accepts_flag -W$x; then
		WARNFLAGS="$WARNFLAGS -W$x";
	fi
done

if cc_accepts_flag -fno-delete-null-pointer-checks; then
	CFLAGS="$CFLAGS -fno-delete-null-pointer-checks"
fi

LT_CONFIG_LTDL_DIR([libltdl])

LT_INIT([dlopen])

LTDL_INIT([subproject])

if test xyes = x"$with_included_ltdl"; then
	AC_SUBST(LTDL_SUBDIR, libltdl)
else
	AC_SUBST(LTDL_SUBDIR, '')
fi

LIBTOOL="$LIBTOOL --silent"

AC_CONFIG_SUBDIRS(libratbox)

if test "$LEX" != flex; then
  LEX="$SHELL $missing_dir/missing flex"
  AC_SUBST(LEX_OUTPUT_ROOT, lex.yy)
  AC_SUBST(LEXLIB, '')
fi

# backwards support for IRC_CFLAGS
CFLAGS="$CFLAGS $IRC_CFLAGS"

dnl Checks for header files.
AC_HEADER_STDC

AC_HEADER_SYS_WAIT
AC_HEADER_DIRENT

AC_CHECK_HEADERS([sys/types.h sys/resource.h sys/param.h sys/stat.h sys/socket.h netinet/in.h arpa/inet.h errno.h stddef.h strings.h string.h])
AC_HEADER_TIME

AC_CHECK_FUNCS([snprintf vasprintf asprintf lstat stat])

dnl Networking Functions
dnl ====================

AC_SEARCH_LIBS(socket, [socket],,)

dnl this gets passed on to the libratbox configure
AC_ARG_ENABLE(ipv6,AC_HELP_STRING([--disable-ipv6],[Disable IPv6 support (not recommended)]),[ipv6=$enableval],[ipv6=yes])
        

AC_C_BIGENDIAN

dnl Check for stdarg.h - if we can't find it, halt configure
AC_CHECK_HEADER(stdarg.h, , [AC_MSG_ERROR([** stdarg.h could not be found - ircd-ratbox will not compile without it **])])

AC_FUNC_ALLOCA

AC_CHECK_SIZEOF(time_t,,[
AC_INCLUDES_DEFAULT
#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
])

AC_CHECK_SIZEOF(long)


dnl Specialized functions checks
dnl ============================


AC_ARG_WITH([jemalloc],
	    [AS_HELP_STRING([--with-jemalloc], [enable jemalloc for memory allocations])],
	    [],
	    [with_jemalloc=no])
JEMALLOC=
AS_IF([test "x$with_jemalloc" = xyes],
	    [AC_CHECK_LIB([jemalloc], [free],
	     [AC_SUBST([LIBJEMALLOC], ["-ljemalloc"])
	       AC_DEFINE([HAVE_LIBJEMALLOC], [1],
                         [Define if you have jemalloc])
	       HAVE_LIBJEMALLOC=1
	     ],
	    [AC_MSG_FAILURE(
		  [no jemalloc found (do not use --with-jemalloc)])])])
AM_CONDITIONAL(WITH_JEMALLOC, [test "$HAVE_LIBJEMALLOC" = "1"])

# tcmalloc-minimal?
AC_ARG_WITH([tcmalloc-minimal],
	    [AS_HELP_STRING([--with-tcmalloc-minimal], [enable minimal tcmalloc support for memory allocations])],
	    [],
	    [with_tcmalloc_minimal=no])

AS_IF([test "x$with_jemalloc" = "xyes"],[with_tcmalloc_minimal=no],[])

TCMALLOC_MINIMAL=
AS_IF([test "x$with_tcmalloc_minimal" != xno],
        [AC_CHECK_LIB([tcmalloc_minimal], [free],
         [AC_SUBST([LIBTCMALLOC], ["-ltcmalloc_minimal"])
	       AC_DEFINE([HAVE_LIBTCMALLOC_MINIMAL], [1],
	       		 [Define if you have tcmalloc])
	       HAVE_LIBTCMALLOC_MINIMAL=1
	     ],
	    [AC_MSG_FAILURE(
		  [no tcmalloc found (do not use --with-tcmalloc-minimal)])])])
AM_CONDITIONAL(WITH_TCMALLOC_MINIMAL, [test "$HAVE_LIBTCMALLOC_MINIMAL" = "1"])

# tcmalloc?
AC_ARG_WITH([tcmalloc],
	    [AS_HELP_STRING([--with-tcmalloc], [enable tcmalloc for memory allocations])],
	    [],
	    [with_tcmalloc=no])

AS_IF([test "x$with_jemalloc" = "xyes"],[with_tcmalloc=no],[])
AS_IF([test "x$with_tcmalloc_minimal" = "xyes"],[with_tcmalloc=no],[])

TCMALLOC=
AS_IF([test "x$with_tcmalloc" != xno],
	    [AC_CHECK_LIB([tcmalloc], [free],
	     [AC_SUBST([LIBTCMALLOC], ["-ltcmalloc"])
	       AC_DEFINE([HAVE_LIBTCMALLOC], [1],
	       		 [Define if you have tcmalloc])
	       HAVE_LIBTCMALLOC=1
	     ],
	    [AC_MSG_FAILURE(
		  [no tcmalloc found (do not use --with-tcmalloc)])])])
AM_CONDITIONAL(WITH_TCMALLOC, [test "$HAVE_LIBTCMALLOC" = "1"])

# error out if --with-jemalloc and ! --without-tcmalloc
if test "x$with_jemalloc" = "xyes"; then
	if test "x$with_tcmalloc" = "xyes" || test "x$with_tcmalloc_minimal" = "xyes"; then
		AC_MSG_FAILURE([--with-jemalloc called with --with-tcmalloc/--with-tcmalloc-minimal, cannot enable both!])
	fi
fi


dnl tcmalloc has mallinfo, jemalloc does not 
if test "x$with_jemalloc" = "xyes";then
	ac_cv_type_struct_mallinfo=no
else
	AC_CHECK_TYPES([struct mallinfo],,, [#include <malloc.h>])
	AC_CHECK_TYPES([struct mallinfo2],,, [#include <malloc.h>])
fi

if test "$ac_cv_type_struct_mallinfo" = yes; then
  AC_SUBST(ac_cv_have_struct_mallinfo, 1)  
else
  AC_SUBST(ac_cv_have_struct_mallinfo, 0)
fi

if test "$ac_cv_type_struct_mallinfo2" = yes; then
  AC_SUBST(ac_cv_have_struct_mallinfo2, 1)
else
  AC_SUBST(ac_cv_have_struct_mallinfo2, 0)
fi


if test "x$with_jemalloc" = "xyes" || test "x$with_tcmalloc" = "xyes" || test "x$with_tcmalloc_minimal" = "xyes"; then
	dnl assume that a compiler supporting -fno-builtin-malloc also supports the rest(aka gcc)
	if cc_accepts_flag -fno-builtin-malloc; then
		CFLAGS="$CFLAGS -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free"
	fi
	AC_SUBST(ac_cv_have_struct_mallinfo, 0)  
fi


PKG_CHECK_MODULES([sqlite3], [sqlite3], [cf_enable_sqlite3=yes], [cf_enable_sqlite3=no])


ac_cv_build_sqlite3=no

if test x"$cf_enable_sqlite3" != xyes; then
	ac_cv_build_sqlite3=yes
	SQLITE_SUBDIR=sqlite3
	AC_SUBST(SQLITE_SUBDIR)
	sqlite3_CFLAGS="-Isqlite3"
	save_LIBS=$LIBS
	AC_SEARCH_LIBS(fdatasync, [rt],,)
	FDATASYNCLIB=$ac_cv_search_fdatasync
	LIBS=$save_LIBS

	if test "$FDATASYNCLIB" = "none required"; then
	        unset FDATASYNCLIB
	fi
	
	if test "$FDATASYNCLIB" = "no"; then
		unset FDATASYNCLIB
	fi
        	
	sqlite3_LIBS="$FDATASYNCLIB sqlite3/libsqlite3.a"
	AC_SUBST(sqlite3_LIBS, $sqlite3_LIBS)
	
fi

dnl AC_SUBST(SQLITE3_LIBS, $SQLITE3_LIBS)
dnl AC_SUBST(SQLITE3_CFLAGS, $SQLITE3_CFLAGS)

AM_CONDITIONAL([BUILD_SQLITE], [test "$ac_cv_build_sqlite3" = yes])


AC_ARG_ENABLE(openssl,
[AC_HELP_STRING([--enable-openssl],[Enable OpenSSL support.])
AC_HELP_STRING([--disable-openssl],[Disable OpenSSL support.])],
[cf_enable_openssl=$enableval],
[cf_enable_openssl="auto"])


if test "$cf_enable_openssl" != "no"; then
	PKG_CHECK_MODULES([OpenSSL], [openssl >= 0.9.8], [cf_enable_openssl=yes], [cf_enable_openssl=no])
fi

if test "$cf_enable_openssl" != no; then
	AC_DEFINE(USE_CHALLENGE, 1, [Define to enable CHALLENGE support, requires OpenSSL])
fi



dnl End OpenSSL detection



dnl Specialized functions and libraries
dnl ===================================

AC_ARG_WITH(zlib-path,
AC_HELP_STRING([--with-zlib-path=DIR],[Path to libz.so for ziplinks support.]),
[LIBS="$LIBS -L$withval"],)

AC_ARG_ENABLE(zlib,
AC_HELP_STRING([--disable-zlib],[Disable ziplinks support]),
[zlib=$enableval],[zlib=yes])
 
if test "$zlib" = yes; then

AC_CHECK_HEADER(zlib.h, [
	AC_CHECK_LIB(z, zlibVersion,
	[
		AC_SUBST(ZLIB_LD, -lz)
		AC_DEFINE(HAVE_ZLIB, 1, [Define to 1 if zlib (-lz) is available.])
	], zlib=no)
], zlib=no)

fi

dnl **********************************************************************
dnl Check for --with-confdir
dnl **********************************************************************

AC_MSG_CHECKING([whether to modify confdir])
AC_ARG_WITH(confdir, 
AC_HELP_STRING([--with-confdir=DIR],
	       [Directory to install config files.]),
	       [ confdir=`echo $withval | sed 's/\/$//'`
		 AC_MSG_RESULT(yes)
		 AC_DEFINE_DIR(ETC_DIR, confdir, [Prefix where config files are installed.])
		 AC_SUBST_DIR([confdir]) ],
	       [ confdir='${prefix}/etc'
		 AC_MSG_RESULT(no)
	         AC_DEFINE_DIR(ETC_DIR, confdir, [Prefix where config files are installed.])
	  	 AC_SUBST_DIR([confdir])]
)

dnl **********************************************************************
dnl Check for --with-logdir
dnl **********************************************************************

AC_MSG_CHECKING([whether to modify logdir])
AC_ARG_WITH(logdir, 
AC_HELP_STRING([--with-logdir=DIR],
	       [Directory where to write logfiles.]),
	       [ logdir=`echo $withval | sed 's/\/$//'`
		 AC_MSG_RESULT(yes)
		 AC_DEFINE_DIR(LOG_DIR, logdir, [Prefix where to write logfiles.])
		 AC_SUBST_DIR([logdir]) ],
	       [ logdir='${prefix}/logs'
		 AC_MSG_RESULT(no)
	         AC_DEFINE_DIR(LOG_DIR, logdir, [Prefix where to write logfiles.])
	  	 AC_SUBST_DIR([logdir])]
)

dnl **********************************************************************
dnl Check for --with-helpdir
dnl **********************************************************************

AC_MSG_CHECKING([whether to modify helpdir])
AC_ARG_WITH(helpdir, 
AC_HELP_STRING([--with-helpdir=DIR],
	       [Directory to install help files.]),
	       [ helpdir=`echo $withval | sed 's/\/$//'`
		 AC_MSG_RESULT(yes)
		 AC_DEFINE_DIR(HELP_DIR, helpdir, [Prefix where help files are installed.])
		 AC_SUBST_DIR([helpdir]) ],
	       [ helpdir='${prefix}/help'
		 AC_MSG_RESULT(no)
	         AC_DEFINE_DIR(HELP_DIR, helpdir, [Prefix where help file are installed.])
	  	 AC_SUBST_DIR([helpdir])]
)

dnl **********************************************************************
dnl Check for --with-moduledir
dnl **********************************************************************

AC_MSG_CHECKING([whether to modify moduledir])
AC_ARG_WITH(moduledir, 
AC_HELP_STRING([--with-moduledir=DIR],
	       [Directory to install modules.]),
	       [ moduledir=`echo $withval | sed 's/\/$//'`
		 AC_MSG_RESULT(yes)
		 AC_DEFINE_DIR(MODULE_DIR, moduledir, [Prefix where modules are installed.])
		 AC_SUBST_DIR([moduledir]) ],
	       [ moduledir='${prefix}/modules'
		 AC_MSG_RESULT(no)
	         AC_DEFINE_DIR(MODULE_DIR, moduledir, [Prefix where modules are installed.])
	  	 AC_SUBST_DIR([moduledir])]
)

dnl Debug-related options
dnl =====================

AC_ARG_ENABLE(assert,
AC_HELP_STRING([--enable-assert],[Enable assert(). Choose between soft(warnings) and hard(aborts the daemon)]),
[assert=$enableval], [assert=no])

if test "$assert" = no; then
	AC_DEFINE(NDEBUG, 1, [Define this to disable debugging support.])
elif test "$assert" = soft; then
	AC_DEFINE(SOFT_ASSERT, 1, [Define this to enable soft asserts.])
	AC_DEFINE(NDEBUG, 1, [Define this to disable debugging support.])
elif test "$assert" = yes; then
	assert = "hard";
fi

AC_MSG_CHECKING(if you want to do a profile build)
AC_ARG_ENABLE(profile,
AC_HELP_STRING([--enable-profile],[Enable profiling]),
[profile=$enableval], [profile=no])

if test "$profile" = yes; then
	if test "$ac_cv_c_compiler_gnu" = yes; then
		CFLAGS="$CFLAGS -pg -static"
		AC_MSG_RESULT([yes, adding -pg -static])
		AC_DEFINE(RATBOX_PROFILE, 1, [Defined to mark profiling is enabled])
	else
		AC_MSG_RESULT([no, profile builds only work with gcc])
	fi
else
	AC_MSG_RESULT(no)
fi

dnl Server Tweaks
dnl =============

AC_ARG_ENABLE(services,
AC_HELP_STRING([--enable-services],[Enable ratbox-services compatibility code.]),
[ratbox_services=$enableval], [ratbox_services=no])

M_SERVICES=""

if test "x$ratbox_services" = "xyes"; then
	AC_DEFINE([ENABLE_SERVICES], 1, [ratbox-services compatibility code])
	M_SERVICES="m_services.la"
fi

AM_CONDITIONAL([ENABLE_SERVICES], [test x"$M_SERVICES" != "x"])


AC_ARG_ENABLE(ocf-services,
AC_HELP_STRING([--enable-ocf-services],[Enable openchanfix/fake client support code - ONLY needed if you are running OCF on this ircd.]),
[ocf_services=$enableval], [ocf_services=no])

if test "x$ocf_services" = "xyes"; then
	AC_DEFINE([ENABLE_OCF_SERVICES], 1, [enable openchanfix/fake client support code])
fi

AC_DEFINE_UNQUOTED(RATBOX_CONFIGURE_OPTS, "$ac_configure_args", [configure arguments])


AC_SUBST(SSL_INCLUDES)
AC_SUBST(SSL_LIBS)

AC_SUBST(LDFLAGS)
AC_SUBST(PICFLAGS)
AC_SUBST(CFLAGS)
AC_SUBST(SEDOBJ)
AC_SUBST(WARNFLAGS)

if test "$prefix" = "NONE"; then 
	AC_DEFINE_UNQUOTED(IRCD_PREFIX, "$ac_default_prefix", [Prefix where the ircd is installed.])

else

dnl Don't get bitten by Cygwin's stupidity if the user specified
dnl a custom prefix with a trailing slash

	prefix=`echo $prefix | sed 's/\/$//'`
	AC_DEFINE_UNQUOTED(IRCD_PREFIX, "$prefix", [Prefix where the ircd is installed.])
	
fi

if test "x$libexecdir" = "xNONE"; then
	rb_cv_libexecdir=$ac_default_libexecdir
else
	rb_cv_libexecdir=$libexecdir
fi

libexecdir=`eval "echo ${rb_cv_libexecdir}/ircd-ratbox"`
AC_DEFINE_DIR(LIBEXEC_DIR, libexecdir, [Prefix where to install non-user executables.])

dnl lets see what libtool thinks our suffix is...
AC_MSG_CHECKING([for shared library suffix])
dnl this whole thing is a big hack...
module=yes
eval SHLIBEXT=\"$shrext_cmds\"
AC_MSG_RESULT($SHLIBEXT)
AC_SUBST(SHLIBEXT,$SHLIBEXT)
AC_SUBST(LT_OBJDIR,$lt_cv_objdir)
AC_DEFINE_UNQUOTED(SHLIBEXT,"$SHLIBEXT", [Extension that shared libs use])
                   
AC_SUBST(IRCD_PREFIX)

disable_backups=n
AC_ARG_ENABLE(backups,,disable_backups=y)
AM_CONDITIONAL([DISABLE_BACKUPS], [test x"$disable_backups" = "xy"])


AC_CONFIG_FILES(		\
	Makefile		\
	bandb/Makefile		\
	bandb/sqlite3/Makefile	\
	ssld/Makefile		\
	resolver/Makefile	\
	contrib/Makefile	\
	tools/Makefile		\
	doc/Makefile		\
	help/Makefile		\
	modules/Makefile	\
	src/Makefile		
)

AC_CONFIG_FILES([install-mod.sh], [chmod +x install-mod.sh])

AC_OUTPUT

dnl Make it look sexay!

echo
echo "Compiling $PACKAGE_NAME $PACKAGE_VERSION"
echo

echo "Installing into: $prefix"

echo "Ziplinks ....................... $zlib"

echo "OpenSSL ........................ $cf_enable_openssl"

tmpresult=shared

if test "x$enable_static" = "xyes"; then
	tmpresult=static
fi

echo "Modules ........................ $tmpresult"
echo "Assert debugging ............... $assert"
echo "ratbox-services compatibility .. $ratbox_services"
echo
