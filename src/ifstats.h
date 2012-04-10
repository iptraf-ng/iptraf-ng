#ifndef IPTRAF_NG_IFSTATS_H
#define IPTRAF_NG_IFSTATS_H

/***

ifstats.h - structure definitions for interface counts

***/

struct iflist {
	char ifname[IFNAMSIZ];
	int ifindex;
	unsigned int encap;
	unsigned long long iptotal;
	unsigned long long ip6total;
	unsigned long badtotal;
	unsigned long long noniptotal;
	unsigned long long total;
	unsigned int spanbr;
	unsigned long br;
	float rate;
	float peakrate;
	unsigned int index;
	struct iflist *prev_entry;
	struct iflist *next_entry;
};

struct iftab {
	struct iflist *head;
	struct iflist *tail;
	struct iflist *firstvisible;
	struct iflist *lastvisible;
	WINDOW *borderwin;
	PANEL *borderpanel;
	WINDOW *statwin;
	PANEL *statpanel;
};

struct pkt_counter {
	unsigned long long pc_packets;
	unsigned long long pc_bytes;
};

struct proto_counter {
	struct pkt_counter proto_total;
	struct pkt_counter proto_in;
	struct pkt_counter proto_out;
};

struct ifcounts {
	struct proto_counter total;
	struct pkt_counter bcast;
	struct pkt_counter bad;
	struct proto_counter ipv4;
	struct proto_counter ipv6;
	struct proto_counter nonip;

	struct proto_counter tcp;
	struct proto_counter udp;
	struct proto_counter icmp;
	struct proto_counter other;
};

#endif	/* IPTRAF_NG_IFSTATS_H */
