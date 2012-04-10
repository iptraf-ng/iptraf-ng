/*
    Copyright (C) 2010  Nikola Pajkovsky (npajkovs@redhat.com)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#ifndef IPTRAF_NG_COMPAT_H
#define IPTRAF_NG_COMPAT_H

#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <ctype.h>
#include <netdb.h>
#include <curses.h>
#include <panel.h>
#include <assert.h>
#include <stddef.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>

#include <arpa/inet.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_fddi.h>
#include <linux/if_tr.h>
#include <linux/types.h>
#include <linux/isdn.h>

#include <linux/if.h>
#include <linux/if_arp.h>

/* move it out! */
#include "tui/labels.h"
#include "tui/listbox.h"
#include "tui/input.h"
#include "tui/menurt.h"
#include "tui/winops.h"
#include "tui/msgboxes.h"
//#include "txbox.h"

#define debug(...)							\
	do {								\
                fprintf(stderr, "%s:%s():%d:",				\
			__FILE__, __func__, __LINE__);			\
                fprintf(stderr, __VA_ARGS__);				\
                fprintf(stderr, "\n");					\
	} while(0)

#define KBITS 0

#define dispmode(mode)				\
	(((mode) == KBITS) ? "kbps": "kBps")

#define __noreturn __attribute__((noreturn))
#define UNUSED __attribute__((unused))

extern void *xmalloc(size_t size);
extern void *xcalloc(size_t nmemb, size_t size);
extern void *xrealloc(void *ptr, size_t size);
extern char *xvasprintf(const char *format, va_list p);
extern void *xmallocz(size_t size);
extern char *xstrdup(const char *s);

extern int xsocket(int domain, int type, int protocol);
extern int xsocket_raw_eth_p_all(void);
extern int socket_bind_to_iface(const int fd, const int ifindex);
extern int socket_bind_to_iface_by_name(const int fd, const char const *ifname);

extern void die(const char *err, ...);
extern void die_errno(const char *err) __noreturn;
extern void error(const char *err, ...);

static inline char *skip_whitespace(const char *str)
{
	while (isspace(*str))
		++str;

	return (char *) str;
}

#if 0
static inline int strtoul_ui(char const *s, int base, unsigned int *result)
{
	unsigned long ul;
	char *p;

	errno = 0;
	ul = strtoul(s, &p, base);
	if (errno || *p || p == s || (unsigned int) ul != ul)
		return -1;
	*result = ul;
	return 0;
}

static inline int strtol_i(char const *s, int base, int *result)
{
	long ul;
	char *p;

	errno = 0;
	ul = strtol(s, &p, base);
	if (errno || *p || p == s || (int) ul != ul)
		return -1;
	*result = ul;
	return 0;
}
#endif

#endif	/* IPTRAF_NG_COMPAT_H */
