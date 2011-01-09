# -*- Makefile -*-

AM_CFLAGS = ${regular_CFLAGS}

bin_PROGRAMS = iptraf rvnamed rawtime

NULL =
TUI_C =
TUI_H =
LIB_H =
LIB_C =

TUI_H += tui/input.h
TUI_H += tui/labels.h
TUI_H += tui/listbox.h
TUI_H += tui/menurt.h
TUI_H += tui/msgboxes.h
TUI_H += tui/winops.h

TUI_C += tui/input.c
TUI_C += tui/labels.c
TUI_C += tui/listbox.c
TUI_C += tui/menurt.c
TUI_C += tui/msgboxes.c
TUI_C += tui/txbox.c
TUI_C += tui/winops.c

LIB_H += iptraf-ng-compat.h
LIB_H += parse-options.h
LIB_H += strbuf.h
LIB_H += packet.h
LIB_H += tcptable.h
LIB_H += othptab.h
LIB_H += ifstats.h
LIB_H += deskman.h
LIB_H += ipcsum.h
LIB_H += hostmon.h
LIB_H += fltedit.h
LIB_H += cidr.h
LIB_H += fltselect.h
LIB_H += ipfilter.h
LIB_H += fltmgr.h
LIB_H += ipfrag.h
LIB_H += serv.h
LIB_H += servname.h
LIB_H += instances.h
LIB_H += timer.h
LIB_H += ifaces.h
LIB_H += error.h
LIB_H += revname.h
LIB_H += log.h
LIB_H += pktsize.h
LIB_H += mode.h
LIB_H += landesc.h
LIB_H += dirs.h
LIB_H += getpath.h
LIB_H += isdntab.h
LIB_H += bar.h
LIB_H += options.h
LIB_H += promisc.h
LIB_H += parseproto.h
LIB_H += addproto.h
LIB_H += links.h
LIB_H += tcptimeout.h
LIB_H += arphdr.h
LIB_H += descrec.h
LIB_H += externs.h
LIB_H += ospf.h
LIB_H += attrs.h
LIB_H += fltdefs.h
LIB_H += logvars.h
LIB_H += tr.h

LIB_C += error.c
LIB_C += log.c
LIB_C += mode.c
LIB_C += getpath.c
LIB_C += bar.c
LIB_C += parseproto.c
LIB_C += fltselect.c
LIB_C += ipfilter.c
LIB_C += fltmgr.c
LIB_C += ipfrag.c
LIB_C += serv.c
LIB_C += servname.c
LIB_C += instances.c
LIB_C += timer.c
LIB_C += revname.c
LIB_C += pktsize.c
LIB_C += landesc.c
LIB_C += isdntab.c
LIB_C += options.c
LIB_C += promisc.c
LIB_C += ifaces.c
LIB_C += usage.c
LIB_C += iptraf.c
LIB_C += itrafmon.c
LIB_C += wrapper.c
LIB_C += parse-options.c
LIB_C += strbuf.c
LIB_C += packet.c
LIB_C += tcptable.c
LIB_C += othptab.c
LIB_C += ifstats.c
LIB_C += deskman.c
LIB_C += ipcsum.c
LIB_C += hostmon.c
LIB_C += fltedit.c
LIB_C += tr.c
LIB_C += cidr.c

iptraf_SOURCES = \
    $(TUI_C) $(TUI_H) \
    $(LIB_C) $(LIB_H) \
    $(NULL)

iptraf_CFLAGS =	${AM_CFLAGS} -I$(srcdir)/tui
iptraf_LDFLAGS = $(libncurses_LIBS) $(libpanel_LIBS)

man_MANS = iptraf.8 rvnamed.8

rvnamed_SOURCES = rvnamed.c rvnamed.h getpath.c dirs.h getpath.h
rvnamed_CFLAGS = ${AM_CFLAGS} -I$(srcdir)/tui

rawtime_SOURCES = rawtime.c

EXTRA_DIST = $(man_MANS)
