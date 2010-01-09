bin_PROGRAMS = iptraf-ng rvnamed-ng rawtime-ng

iptraf_ng_SOURCES = iptraf.c		\
					itrafmon.c		\
					packet.c		\
					tcptable.c		\
					othptab.c		\
					ifstats.c		\
					deskman.c		\
					ipcsum.c		\
					hostmon.c		\
					fltedit.c		\
					tr.c			\
					cidr.c			\
					fltselect.c		\
					ipfilter.c		\
					fltmgr.c		\
					ipfrag.c		\
					serv.c			\
					servname.c		\
					instances.c		\
					timer.c			\
					revname.c		\
					pktsize.c		\
					landesc.c		\
					isdntab.c		\
					options.c		\
					promisc.c		\
					ifaces.c		\
					error.c			\
					log.c			\
					mode.c			\
					getpath.c		\
					bar.c			\
					parseproto.c

iptraf_ng_CFLAGS =	$(CFLAGS) \
					-Wall \
					-std=gnu99 \
					-pedantic \
					-I$(srcdir)/../support

iptraf_ng_LDFLAGS = $(ncurses_LIBS) $(libpanel_LIBS) ../support/libtextbox.la

rvnamed_ng_SOURCES = rvnamed.c getpath.c

rvnamed_ng_CFLAGS = $(CFLAGS) \
					-Wall \
					-std=gnu99 \
					-pedantic \
					-I$(srcdir)/../support

rawtime_ng_SOURCES = rawtime.c

rawtime_ng_CFLAGS = $(CFLAGS) \
					-Wall \
					-std=gnu99 \
					-pedantic \
					-I$(srcdir)/../support
