bin_PROGRAMS = iptraf rvnamed rawtime

iptraf_SOURCES = \
    iptraf.c \
    itrafmon.c \
    xfuncs.c \
    packet.c packet.h \
    tcptable.c tcptable.h \
    othptab.c othptab.h \
    ifstats.c ifstats.h \
    deskman.c deskman.h \
    ipcsum.c ipcsum.h \
    hostmon.c hostmon.h \
    fltedit.c fltedit.h \
    tr.c tr.h \
    cidr.c cidr.h \
    fltselect.c	fltselect.h \
    ipfilter.c ipfilter.h \
    fltmgr.c fltmgr.h \
    ipfrag.c ipfrag.h \
    serv.c serv.h \
    servname.c servname.h \
    instances.c instances.h \
    timer.c timer.h \
    revname.c revname.h	\
    pktsize.c pktsize.h	\
    landesc.c landesc.h	\
    isdntab.c isdntab.h	\
    options.c options.h	\
    promisc.c promisc.h	\
    ifaces.c ifaces.h \
    error.c error.h \
    log.c log.h	\
    mode.c mode.h \
    getpath.c dirs.h getpath.h \
    bar.c bar.h	\
    parseproto.c parseproto.h \
    addproto.h links.h tcptimeout.h \
    arphdr.h descrec.h  externs.h \
    ospf.h attrs.h fltdefs.h logvars.h

iptraf_CFLAGS =	-I$(srcdir)/../support
iptraf_LDFLAGS = -l$(ncurses_lib) -l$(panel_lib)
iptraf_LDADD   = ../support/libtextbox.la

man_MANS = iptraf.8 rvnamed.8

rvnamed_SOURCES = rvnamed.c rvnamed.h getpath.c dirs.h getpath.h
rvnamed_CFLAGS = -I$(srcdir)/../support

rawtime_SOURCES = rawtime.c
rawtime_CFLAGS = -I$(srcdir)/../support

EXTRA_DIST = $(man_MANS)
