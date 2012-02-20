#ifndef IPTRAF_NG_LANDESC_H
#define IPTRAF_NG_LANDESC_H

/***

ethdesc.c	- Ethernet host description management module

Copyright (c) Gerard Paul Java 1998

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

***/

#include "list.h"

#define WITHETCETHERS 1
#define WITHOUTETCETHERS 0

struct eth_desc {
	struct list_head hd_list;
	char hd_mac[18];
	char *hd_desc;
};

struct eth_desc *load_eth_desc(unsigned link_type);

void free_eth_desc(struct eth_desc *hd);

void manage_eth_desc(unsigned int linktype);

#endif	/* IPTRAF_NG_LANDESC_H */
