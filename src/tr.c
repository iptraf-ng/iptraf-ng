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

// TODO: full rewrite

#include "iptraf-ng-compat.h"

unsigned int get_tr_ip_offset(unsigned char *pkt)
{
    struct trh_hdr *trh;
    unsigned int riflen = 0;

    trh = (struct trh_hdr *) pkt;

    /*
     * Check if this packet has TR routing information and get
     * its length.
     */
    if (trh->saddr[0] & TR_RII)
        riflen = (ntohs(trh->rcf) & TR_RCF_LEN_MASK) >> 8;

    return sizeof(struct trh_hdr) - TR_MAXRIFLEN + riflen +
        sizeof(struct trllc);
}
