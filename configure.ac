AC_INIT([iptraf-ng], [1.0.0], [iptraf-ng@fedorahosted.org])
AC_CONFIG_HEADERS([config.h])

dnl checks for system type
AC_CANONICAL_SYSTEM
AC_DEFINE_UNQUOTED([PLATFORM], "${host}", [Define to platform])

AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AC_LANG_C
AC_HEADER_STDC
AC_PROG_LIBTOOL

dnl checks for libraries
PKG_CHECK_MODULES([ncurses],[ncurses])
PKG_CHECK_MODULES([libpanel],[panel])

dnl checks for header files
AC_CHECK_HEADERS([arpa/inet.h])
AC_CHECK_HEADERS([fcntl.h])
AC_CHECK_HEADERS([limits.h])
AC_CHECK_HEADERS([malloc.h])
AC_CHECK_HEADERS([netdb.h])
AC_CHECK_HEADERS([netinet/in.h])
AC_CHECK_HEADERS([sys/ioctl.h])
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([sys/time.h])

dnl checks for types
AC_TYPE_PID_T
AC_TYPE_SIZE_T

dnl checks for library functions
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([alarm])
AC_CHECK_FUNCS([bzero])
AC_CHECK_FUNCS([gethostbyaddr])
AC_CHECK_FUNCS([gethostbyname])
AC_CHECK_FUNCS([gettimeofday])
AC_CHECK_FUNCS([inet_ntoa])
AC_CHECK_FUNCS([memmove])
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([select])
AC_CHECK_FUNCS([setenv])
AC_CHECK_FUNCS([socket])
AC_CHECK_FUNCS([strcasecmp])
AC_CHECK_FUNCS([strchr])
AC_CHECK_FUNCS([strerror])
AC_CHECK_FUNCS([strtoul])


AC_CONFIG_FILES([
	Makefile
    support/Makefile
	src/Makefile
])

AC_OUTPUT
