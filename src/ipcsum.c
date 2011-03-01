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

#include "iptraf-ng-compat.h"

/* code taken from http://www.faqs.org/rfcs/rfc1071.html. See section 4.1 "C"  */
int in_cksum(u_short *addr, int len)
{
	register int sum = 0;

        while (len > 1) {
		sum += *(u_short *)addr++;
		len -= 2;
	}

	if (len > 1)
		sum += *(unsigned char *) addr;

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return (u_short)(~sum);
}
