AC_INIT([iptraf-ng],
	m4_esyscmd([./gen-version]),
	[iptraf-ng@fedorahosted.org])

AC_CONFIG_HEADERS([config.h])

dnl checks for system type
AC_CANONICAL_HOST
AC_DEFINE_UNQUOTED([PLATFORM], "${host}", [Define to platform])

AM_INIT_AUTOMAKE([-Wall -Werror foreign silent-rules])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC
AC_LANG_C
AC_HEADER_STDC

dnl checks for libraries ncurses[5,6]
dnl removed ncursesw[5,6]; iptraf-ng does not use it
AC_CHECK_PROG([ncurses5_config], [ncurses5-config], [yes])
AC_CHECK_PROG([ncurses6_config], [ncurses6-config], [yes])

if test "x$ncurses6_config" = "xyes"; then
    libncurses_CFLAGS=$("ncurses6-config" --cflags)
    libncurses_LIBS=$("ncurses6-config" --libs)
elif test "x$ncurses5_config" = "xyes"; then
    libncurses_CFLAGS=$("ncurses5-config" --cflags)
    libncurses_LIBS=$("ncurses5-config" --libs)
else
    AC_MSG_ERROR([Install ncurses5-dev or ncurses6-dev])
fi

libpanel_LIBS="-lpanel"

AC_SUBST([libncurses_CFLAGS])
AC_SUBST([libncurses_LIBS])
AC_SUBST([libpanel_LIBS])

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
AC_CHECK_HEADERS([locale.h])

dnl checks for types
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

dnl checks for library functions
AC_FUNC_FORK
AC_FUNC_MALLOC

regular_CFLAGS="-Wall -std=gnu99 -pedantic"
AC_SUBST([regular_CFLAGS])

AC_CONFIG_FILES([
    Makefile
    src/Makefile
])

AC_OUTPUT
