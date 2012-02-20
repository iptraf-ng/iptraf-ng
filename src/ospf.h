#ifndef IPTRAF_NG_OSPF_H
#define IPTRAF_NG_OSPF_H

/***

ospf.h - a small header declaration for OSPF packets

Extracted from tcpdump

***/

struct ospfhdr {
	u_char ospf_version;
	u_char ospf_type;
	u_short ospf_len;
	struct in_addr ospf_routerid;
	struct in_addr ospf_areaid;
	u_short ospf_chksum;
	u_short ospf_authtype;
}

#endif	/* IPTRAF_NG_OSPF_H */
