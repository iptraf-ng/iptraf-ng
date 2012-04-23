/*
    Copyright (C) 2011  Nikola Pajkovsky (npajkovs@redhat.com)

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

#define _GNU_SOURCE
#include "iptraf-ng-compat.h"

// Die if we can't allocate size bytes of memory.
void *xmalloc(size_t size)
{
	void *ptr = malloc(size);

	if (ptr == NULL && size != 0)
		die("Out of memory, xmalloc failed");
	return ptr;
}

void *xmallocz(size_t size)
{
	void *ptr = xmalloc(size);

	memset(ptr, 0, size);
	return ptr;
}

void *xcalloc(size_t nmemb, size_t size)
{
	void *ptr = calloc(nmemb, size);

	if (!ptr && (!nmemb || !size))
		die("Out of memory, xcalloc failed");
	return ptr;
}

void *xrealloc(void *ptr, size_t size)
{
	void *ret = realloc(ptr, size);

	if (!ret && !size)
		die("Out of memory, xrealloc failed");
	return ret;
}

char *xvasprintf(const char *format, va_list p)
{
	int r;
	char *string_ptr;

	// GNU extension
	r = vasprintf(&string_ptr, format, p);
	if (r < 0)
		die("Out of memory, xvasprintf failed");
	return string_ptr;
}

// Die if we can't copy a string to freshly allocated memory.
char *xstrdup(const char *s)
{
	if (!s)
		return NULL;

	char *t = strdup(s);

	if (!t)
		die("Out of memory, %s failed", __func__);

	return t;
}

int socket_bind_to_iface(const int fd, const int ifindex)
{
	struct sockaddr_ll fromaddr;
	socklen_t addrlen = sizeof(fromaddr);

	fromaddr.sll_family = AF_PACKET;
	fromaddr.sll_protocol = htons(ETH_P_ALL);
	fromaddr.sll_ifindex = ifindex;
	return bind(fd, (struct sockaddr *) &fromaddr, addrlen);
}

int socket_bind_to_iface_by_name(const int fd, const char const *ifname)
{
	int ir;
	struct ifreq ifr;

	strcpy(ifr.ifr_name, ifname);
	ir = ioctl(fd, SIOCGIFINDEX, &ifr);
	if(ir != 0)
		return(ir);

	return socket_bind_to_iface(fd, ifr.ifr_ifindex);
}
