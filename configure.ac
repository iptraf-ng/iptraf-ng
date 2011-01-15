AC_INIT([iptraf-ng], [1.0.4], [iptraf-ng@fedorahosted.org])
AC_CONFIG_HEADERS([config.h])

dnl checks for system type
AC_CANONICAL_HOST
AC_DEFINE_UNQUOTED([PLATFORM], "${host}", [Define to platform])

AM_INIT_AUTOMAKE([-Wall -Werror foreign silent-rules])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CC
AC_LANG_C
AC_HEADER_STDC

dnl checks for libraries ncursesw/ncurses
AC_PATH_PROGS([ncurses_config],
	[ncursesw6-config ncursesw5-config ncurses6-config ncurses5-config])
if test -n "$ncurses_config"; then
	libncurses_CFLAGS=$("$ncurses_config" --cflags);
	libncurses_LIBS=$("$ncurses_config" --libs);
else
	AC_CHECK_LIB([ncursesw], [initscr], [ncurses_LIBS="-lncursesw"])
	if test -z "$ncurses_LIBS"; then
		AC_CHECK_LIB([ncurses], [initscr], [ncurses_LIBS="-lncurses"])
	fi
	if test -z "$ncurses_LIBS"; then
		AC_MSG_ERROR([At least one of ncursesw/ncurses library must be present])
	fi;
fi;
if echo "$ncurses_LIBS" | grep -q cursesw; then
	libpanel_LIBS="-lpanelw";
else
	libpanel_LIBS="-lpanel";
fi;
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
AC_CHECK_HEADERS([curses.h],, [AC_MSG_ERROR(curses.h header must be present)])

dnl checks for types
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

dnl checks for library functions
AC_FUNC_FORK
AC_FUNC_MALLOC

regular_CFLAGS="$CFLAGS -Wall -std=gnu99 -pedantic"
AC_SUBST([regular_CFLAGS])

AC_CONFIG_FILES([
    Makefile
    src/Makefile
])

AC_OUTPUT
