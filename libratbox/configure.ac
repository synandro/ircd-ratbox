dnl 
dnl Process this file with autoconf to produce a configure script.

dnl TODO: clean up all the OpenSSL and shared module checking stuff;
dnl the most major changes have already been made and it looks like
dnl said functions need to be just about as complex as they already are.

AC_PREREQ(2.63)
AUTOMAKE_OPTIONS = 1.10

saved_CFLAGS="$CFLAGS"
dnl Sneaky way to get an Id tag into the configure script
dnl AC_COPYRIGHT([$Id: configure.ac 29205 2015-12-09 20:08:43Z androsyn $])
AC_INIT([libratbox],[devel])


AM_INIT_AUTOMAKE
AC_CANONICAL_HOST

AM_CONFIG_HEADER(include/libratbox_config.h)

AC_PREFIX_DEFAULT(/usr/local/libratbox)
AC_GNU_SOURCE

CFLAGS=""
dnl Checks for programs.
AC_PROG_CC_C99

CFLAGS="$CFLAGS $saved_CFLAGS"

if test x"$ac_cv_prog_cc_c99" = "xno"; then
	AC_ERROR([ircd-ratbox requires a C99 capable compiler])
fi
        

AC_PROG_INSTALL
AC_PROG_EGREP
AC_PROG_SED

F77=no
CXX=no
GCJ=no

AM_DISABLE_STATIC
AM_ENABLE_SHARED
AM_MAINTAINER_MODE
AC_ISC_POSIX
AC_C_INLINE
AC_C_CONST
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_PATH_PROG(CP, cp)
AC_PATH_PROG(MV, mv)
AC_PATH_PROG(RB_RM, rm)


AC_LANG(C)


AC_LIBTOOL_DLOPEN
AC_PROG_LIBTOOL

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
  
if cc_accepts_flag -fno-delete-null-pointer-checks; then
	CFLAGS="$CFLAGS -fno-delete-null-pointer-checks"
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

AC_SUBST(WARNFLAGS)

LIBTOOL="$LIBTOOL --silent"

# backwards support for IRC_CFLAGS
CFLAGS="$IRC_CFLAGS $CFLAGS -Wall"

dnl use directory structure of cached as default (hack)
if test "$libexecdir" = '${exec_prefix}/libexec' &&
   test "$localstatedir" = '${prefix}/var'; then
	libexecdir='${bindir}'
	localstatedir='${prefix}'
fi

AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UID_T

AC_CHECK_SIZEOF(long)

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
  


dnl Checks for header files.
AC_HEADER_STDC

AC_CHECK_HEADERS([stdbool.h crypt.h unistd.h sys/socket.h sys/stat.h sys/time.h time.h netinet/in.h netinet/tcp.h arpa/inet.h errno.h sys/uio.h spawn.h sys/poll.h sys/epoll.h sys/select.h sys/devpoll.h sys/event.h port.h signal.h sys/signalfd.h sys/timerfd.h])
AC_HEADER_TIME

AC_CHECK_SIZEOF([struct signalfd_siginfo], [], [#include <sys/signalfd.h>])

dnl Networking Functions
dnl ====================

AC_SEARCH_LIBS(socket, [socket],,)


AC_CHECK_MEMBER([struct sockaddr.sa_len], [AC_DEFINE(SOCKADDR_IN_HAS_LEN, 1, [Define to 1 if sockaddr has a 'sa_len'
member.])],,[[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif
]])

AC_CHECK_TYPE([socklen_t], rb_cv_socklen_t=socklen_t,[
	AC_MSG_CHECKING([for socklen_t equivalent])
	AC_CACHE_VAL([rb_cv_socklen_t],
	[
	# Systems have either "struct sockaddr *" or
	# "void *" as the second argument to getpeername
	rb_cv_socklen_t=
	for arg2 in "struct sockaddr" void; do
		for t in int size_t unsigned long "unsigned long"; do
			AC_TRY_COMPILE([
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
int getpeername (int, $arg2 *, $t *);
],[
$t len;
getpeername(0,0,&len);
],[
	rb_cv_socklen_t="$t"
	break
])
		done
	done

	if test "x$rb_cv_socklen_t" = x; then
		rb_cv_socklen_t=int
	fi
	])
	AC_MSG_RESULT($rb_cv_socklen_t)],
	[#include <sys/types.h>
#include <sys/socket.h>])

rb_socklen_t=$rb_cv_socklen_t





AC_ARG_ENABLE(ipv6,AC_HELP_STRING([--disable-ipv6],[Disable IPv6 support]),[ipv6=$enableval],[ipv6=yes])

if test x$ipv6 != xyes; then
	have_v6="no"
else

have_v6=yes
RB_PROTO_INET6([], [
		AC_MSG_NOTICE([Disabling IPv6 support: PF_INET6 not found])
		have_v6=no
		])

	if test "X$have_v6" = "Xyes"; then
	RB_TYPE_STRUCT_SOCKADDR_IN6([], [
		AC_MSG_NOTICE([Disabling IPv6 support: struct sockaddr_in6 not found])
		have_v6=no
		])
	fi

fi			

AC_CHECK_TYPES([struct sockaddr_storage],[
	rb_have_sockaddr_storage=yes
        ],[], [
		#include <sys/types.h>
		#include <sys/socket.h>
	])
                

save_LIBS=$LIBS
AC_SEARCH_LIBS(crypt, [crypt descrypt],,)
LIBS=$save_LIBS

CRYPT_LIB=$ac_cv_search_crypt

if test "$CRYPT_LIB" = "none required"; then
	unset CRYPT_LIB
elif test "$CRYPT_LIB" = no; then
	need_crypt=yes;
	AC_DEFINE(NEED_CRYPT, 1, [Define if your system needs crypt.])
	unset CRYPT_LIB
fi

AM_CONDITIONAL([NEED_CRYPT], [test x"$need_crypt" = "xyes"])


AC_SUBST(CRYPT_LIB)

dnl Check for stdarg.h - if we cant find it, halt configure
AC_CHECK_HEADER(stdarg.h, , [AC_MSG_ERROR([** stdarg.h could not be found - libratbox will not compile without it **])])

AC_CHECK_TYPE([sa_family_t], [],
[AC_DEFINE(sa_family_t, [u_int16_t], [If system does not define sa_family_t, define it here.])],
[[#include <sys/types.h>
#include <sys/socket.h>]])


dnl check for various functions...
AC_CHECK_FUNCS([snprintf vsnprintf socketpair gettimeofday writev sendmsg gmtime_r strtok_r usleep posix_spawn strdup strndup strlcpy strlcat strnlen fstat signalfd select poll kevent kqueue1 port_create epoll_ctl epoll_create1 arc4random arc4random_stir getrusage timerfd_create accept4 pipe2])

AC_SEARCH_LIBS(nanosleep, rt posix4, AC_DEFINE(HAVE_NANOSLEEP, 1, [Define if you have nanosleep]))
AC_SEARCH_LIBS(timer_create, rt, AC_DEFINE(HAVE_TIMER_CREATE, 1, [Define if you have timer_create]))
RB_CHECK_TIMER_CREATE
RB_CHECK_TIMERFD_CREATE

AC_FUNC_ALLOCA
AC_FUNC_VFORK
AC_FUNC_MMAP


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
	if test "x$with_tcmalloc" == "xyes" || test "x$with_tcmalloc_minimal" == "xyes"; then
		AC_MSG_FAILURE([--with-jemalloc called with --with-tcmalloc/--with-tcmalloc-minimal, cannot enable both!])
	fi
fi

if test "x$with_jemalloc" = "xyes" || test "x$with_tcmalloc" = "xyes" || test "x$with_tcmalloc_minimal" = "xyes"; then
	dnl assume that a compiler supporting -fno-builtin-malloc also supports the rest(aka gcc)
	if cc_accepts_flag -fno-builtin-malloc; then
		CFLAGS="$CFLAGS -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free"
	fi
fi



pk_enable_openssl=0
pk_enable_gnutls=0

AC_ARG_ENABLE(openssl,
[AC_HELP_STRING([--enable-openssl],[Enable OpenSSL support.])
AC_HELP_STRING([--disable-openssl],[Disable OpenSSL support.])],
[cf_enable_openssl="$enableval"],
[cf_enable_openssl="auto"])

AC_ARG_ENABLE(gnutls,
[AC_HELP_STRING([--enable-gnutls],[Enable GNUTLS support.])
AC_HELP_STRING([--disable-gnutls],[Disable GNUTLS support.])],
[cf_enable_gnutls="$enableval"],
[cf_enable_gnutls="auto"])

dnl mbedTLS support
AC_ARG_ENABLE(mbedtls,
[AC_HELP_STRING([--enable-mbedtls], [Enable mbedTLS support.])
AC_HELP_STRING([--disable-mbedtls], [Disable mbedTLS support.])],
[cf_enable_mbedtls=$enableval],
[cf_enable_mbedtls="auto"])

AS_IF([test "x$cf_enable_openssl" = "xyes"], [cf_enable_gnutls="no" cf_enable_mbedtls="no"])
AS_IF([test "x$cf_enable_mbedtls" = "xyes"], [cf_enable_gnutls="no" cf_enable_openssl="no"])
AS_IF([test "x$cf_enable_gnutls" = "xyes"], [cf_enable_openssl="no" cf_enable_mbedtls="no"])

AS_IF([test "x$cf_enable_openssl" != "xno"], [PKG_CHECK_MODULES(OpenSSL, [libssl >= 0.9.8 libcrypto >= 0.9.8], [cf_enable_openssl="yes"], [cf_enable_openssl="no"])], [cf_enable_openssl=no])
AS_IF([test "x$cf_enable_mbedtls" != "xno"], [
	save_CPPFLAGS="$CPPFLAGS"
	save_LIBS="$LIBS"
	LIBS="$LIBS $MBEDTLS_LIBS"
	AC_CHECK_LIB(mbedtls, mbedtls_ssl_init, [MBEDTLS_LIBS="$MBEDTLS_LIBS -lmbedtls -lmbedcrypto -lmbedx509" cf_enable_mbedtls=yes], [cf_enable_mbedtls=no])
	LIBS="$save_LIBS"
	CPPFLAGS="$save_CPPFLAGS"])

AS_IF([test "x$cf_enable_gnutls" != "xno"], [PKG_CHECK_MODULES(gnutls, [gnutls], [cf_enable_gnutls="yes"], [cf_enable_gnutls="no"])], [cf_enable_gnutls=no])


if test x"$cf_enable_openssl" != xno; then
	AC_DEFINE(HAVE_OPENSSL,1,[Has OpenSSL])
	GNUTLS_CFLAGS=""
	GNUTLS_LIBS=""
	MBEDTLS_LIBS=""
	MBEDTLS_CFLAGS=""
	SSL_TYPE="openssl"
elif test x"$cf_enable_mbedtls" != xno; then
	AC_DEFINE(HAVE_MBEDTLS, 1, [Has mbedTLS])
	GNUTLS_CFLAGS=""
	GNUTLS_LIBS=""
	SSL_LIBS=""
	SSL_CFLAGS=""	
	SSL_TYPE="mbedtls"
elif test x"$cf_enable_gnutls" != xno; then
	AC_DEFINE(HAVE_GNUTLS, 1, [Has GnuTLS])
	GNUTLS_CFLAGS="$gnutls_CFLAGS"
	GNUTLS_LIBS="$gnutls_LIBS"
	SSL_LIBS=""
	SSL_CFLAGS=""	
	SSL_TYPE="gnutls"
fi




AC_MSG_CHECKING(for /dev/poll)
if test -c "/dev/poll"; then
        AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_DEVPOLL, [1], [Define to 1 if you have devpoll])
else
	AC_MSG_RESULT(no)	
fi



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

AC_SUBST(LDFLAGS)
AC_SUBST(PICFLAGS)
AC_SUBST(CFLAGS)
AC_SUBST(SEDOBJ)
AC_SUBST(OpenSSL_CFLAGS)
AC_SUBST(OpenSSL_LIBS)
AC_SUBST(GNUTLS_CFLAGS)
AC_SUBST(GNUTLS_LIBS)
AC_SUBST(MBEDTLS_CFLAGS)
AC_SUBST(MBEDTLS_LIBS)
AC_SUBST(EXTRA_WARNINGS)

if test "$prefix" = "NONE"; then 
	AC_DEFINE_UNQUOTED(RB_PREFIX, "$ac_default_prefix", [Prefix where libratbox is installed.])

else

dnl Don't get bitten by Cygwin's stupidity if the user specified
dnl a custom prefix with a trailing slash

	prefix=`echo $prefix | sed 's/\/$//'`
	AC_DEFINE_UNQUOTED(RB_PREFIX, "$prefix", [Prefix where libratbox is installed.])
	
fi


AC_SUBST(RB_PREFIX)

AC_CONFIG_COMMANDS([include/librb-config.h],
[
	outfile=include/librb-config.h.tmp
	cat > $outfile  <<\_______EOF
/*    
 * librb-config.h: libratbox config file. Please modify configure.ac
 */
 
#ifndef __LIBRB_CONFIG_H
#define __LIBRB_CONFIG_H

_______EOF 

if test "x$rb_have_strdup" = "xyes"; then
	echo "#define RB_HAVE_STRDUP 1" >> $outfile
fi
if test "x$rb_have_strndup" = "xyes"; then
	echo "#define RB_HAVE_STRNDUP 1" >> $outfile
fi
if test "x$rb_have_strlcpy" = "xyes"; then
	echo "#define RB_HAVE_STRLCPY 1" >> $outfile
fi
if test "x$rb_have_strlcat" = "xyes"; then
	echo "#define RB_HAVE_STRLCAT 1" >> $outfile
fi


if test "x$rb_have_ipv6" = "xyes"; then
	echo "#define RB_IPV6 1" >> $outfile
fi

echo "#define RB_SIZEOF_TIME_T $rb_sizeof_time_t" >> $outfile
echo "#define RB_SIZEOF_LONG $rb_sizeof_long" >> $outfile

if test "x$rb_alloca_h" = "xyes"; then
	echo '#define RB_HAVE_ALLOCA_H 1' >> $outfile
fi

if test "x$rb_header_stdc" = "xyes"; then
	echo '#include <stdlib.h>' >> $outfile
	echo '#include <stddef.h>' >> $outfile
elif test "x$rb_header_stdlib" = "xyes"; then
	echo '#include <stdlib.h>' >> $outfile
fi

if test "x$rb_header_string_h" = "xyes"; then
	echo '#include <string.h>' >> $outfile
fi

if test "x$rb_header_stdbool_h" = "xyes"; then
	echo '#include <stdbool.h>' >> $outfile
fi

if test "x$rb_stdint_h" = "xyes"; then
	echo '#include <stdint.h>' >> $outfile
fi

if test "x$rb_inttypes_h" = "xyes"; then
	echo '#include <inttypes.h>' >> $outfile
fi

if test "x$rb_sys_types_h" = "xyes"; then
	echo '#include <sys/types.h>' >> $outfile
fi
if test "x$rb_sys_time_h" = "xyes"; then
	echo '#include <sys/time.h>' >> $outfile
fi
if test "x$rb_sys_stat_h" = "xyes"; then
	echo '#include <sys/stat.h>' >> $outfile
fi
if test "x$rb_time_h" = "xyes"; then
	echo '#include <time.h>' >> $outfile
fi

if test "x$rb_sys_socket_h" = "xyes"; then
	echo '#include <sys/socket.h>' >> $outfile
fi

if test "x$rb_netinet_in_h" = "xyes"; then
	echo '#include <netinet/in.h>' >> $outfile
fi

if test "x$rb_netinet_tcp_h" = "xyes"; then
	echo '#include <netinet/tcp.h>' >> $outfile
fi

if test "x$rb_arpa_inet_h" = "xyes"; then
	echo '#include <arpa/inet.h>' >> $outfile
fi

if test "x$rb_unistd_h" = "xyes"; then
	echo '#include <unistd.h>' >> $outfile
fi

if test "x$rb_crypt_h" = "xyes"; then
	echo '#include <crypt.h>' >> $outfile
fi

if test "x$rb_errno_h" = "xyes"; then
	echo '#include <errno.h>' >> $outfile
fi

echo "typedef $rb_socklen_t rb_socklen_t;" >> $outfile


if test "x$rb_sockaddr_sa_len" = "xyes"; then
	echo '#define RB_SOCKADDR_HAS_SA_LEN 1' >> $outfile
fi

if test "x$rb_sockaddr_storage" = "xyes"; then
	echo '#define rb_sockaddr_storage sockaddr_storage' >> $outfile
else
	echo 'struct rb_sockaddr_storage { uint8_t _padding[[128]]; };' >> $outfile
fi

cat >> $outfile <<\_______EOF
#endif /* __LIBRB_CONFIG_H */
_______EOF

if cmp -s $outfile include/librb-config.h; then
	AC_MSG_NOTICE([include/librb-config.h is unchanged])
	${rb_rm} -f $outfile
else
	${rb_mv} $outfile include/librb-config.h
fi

],[
	rb_have_strdup=$ac_cv_func_strdup
	rb_have_strndup=$ac_cv_func_strndup
	rb_have_strlcat=$ac_cv_func_strlcat
	rb_have_strlcpy=$ac_cv_func_strlcpy

	rb_sizeof_time_t=$ac_cv_sizeof_time_t
	rb_sizeof_long=$ac_cv_sizeof_long
	if test x$ac_cv_header_stdc = xyes; then
		rb_header_stdc=yes
	fi
	if test x$ac_cv_header_stdlib_h = xyes; then
		rb_header_stdlib_h=yes
	fi
	if test x$ac_cv_header_stdbool_h = xyes; then
		rb_header_stdbool_h=yes
	fi
	if test x$ac_cv_header_string_h = xyes; then
		rb_header_string_h=yes
	fi
	if test x$ac_cv_header_memory_h = xyes; then
		rb_header_memory_h=yes
	fi
	if test "x${ac_cv_working_alloca_h+set}" = xset ; then
		rb_alloca_h="$ac_cv_working_alloca_h"
	else
		rb_alloc_h="$ac_cv_header_alloca_h"
	fi
	if test x$ac_cv_member_struct_sockaddr_sa_len = xyes; then
		rb_sockaddr_sa_len=yes
	fi
	if test x$ac_cv_header_sys_socket_h = xyes; then
		rb_sys_socket_h=yes
	fi
	if test x$ac_cv_header_arpa_inet_h = xyes; then
		rb_arpa_inet_h=yes
	fi
	if test x$ac_cv_header_sys_types_h = xyes; then
		rb_sys_types_h=yes
	fi
	if test x$ac_cv_header_sys_stat_h = xyes; then
		rb_sys_stat_h=yes
	fi
	if test x$ac_cv_header_sys_time_h = xyes; then
		rb_sys_time_h=yes
	fi
	if test x$ac_cv_header_time = xyes; then
		rb_time_h=yes
	fi

	if test x$ac_cv_header_stdint_h = xyes; then
		rb_stdint_h=yes
	fi
	if test x$ac_cv_header_inttypes_h = xyes; then
		rb_inttypes_h=yes
	fi
	if test x$ac_cv_header_netinet_in_h = xyes; then
		rb_netinet_in_h=yes
	fi
	if test x$ac_cv_header_netinet_tcp_h = xyes; then
		rb_netinet_tcp_h=yes
	fi

	if test x$ac_cv_header_crypt_h = xyes; then
		rb_crypt_h=yes
	fi
	if test x$ac_cv_header_errno_h = xyes; then
		rb_errno_h=yes
	fi
	if test x$ac_cv_header_unistd_h = xyes; then
		rb_unistd_h=yes
	fi
	if test x$ac_cv_header_windows_h = xyes; then
		rb_windows_h=yes
	fi
	if test x$ac_cv_header_winsock2_h = xyes; then
		rb_winsock2_h=yes
	fi

	rb_socklen_t=$rb_socklen_t

	if test "x$rb_have_sockaddr_storage" = "xyes"; then
		rb_sockaddr_storage="yes" 
	else
		rb_sockaddr_storage="no"
	fi
	
	rb_have_ipv6="$have_v6"
		
	rb_mv="$MV"
	rb_rm="$RM"
		
]
	

)


AC_CONFIG_FILES(		\
	src/Makefile		\
	Makefile		\
)

AC_OUTPUT

dnl Make it look sexay!

echo
echo "Compiling $PACKAGE_NAME $PACKAGE_VERSION"
echo

echo "Installing into: $prefix"

echo "IPv6 support ................... $have_v6"
echo "Assert debugging ............... $assert"
echo "SSL Type........................ $SSL_TYPE"
echo

