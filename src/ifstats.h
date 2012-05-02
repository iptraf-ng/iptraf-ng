#ifndef IPTRAF_NG_IFSTATS_H
#define IPTRAF_NG_IFSTATS_H

/***

ifstats.h - structure definitions for interface counts

***/

struct pkt_counter {
	unsigned long long pc_packets;
	unsigned long long pc_bytes;
};

struct proto_counter {
	struct pkt_counter proto_total;
	struct pkt_counter proto_in;
	struct pkt_counter proto_out;
};

#endif	/* IPTRAF_NG_IFSTATS_H */
