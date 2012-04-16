#ifndef IPTRAF_NG_PACKET_H
#define IPTRAF_NG_PACKET_H

/***

packet.h - external declarations for packet.c

Written by Gerard Paul Java

***/

/*
 * Number of bytes from captured packet to move into an aligned buffer.
 * 96 bytes should be enough for the IP header, TCP/UDP/ICMP/whatever header
 * with reasonable numbers of options.
 */

#define MAX_PACKET_SIZE 256	/* 256B should be enough to see all headers */

#define INVALID_PACKET 0
#define PACKET_OK 1
#define CHECKSUM_ERROR 2
#define PACKET_FILTERED 3
#define MORE_FRAGMENTS 4

extern int isdnfd;

void open_socket(int *fd);
void getpacket(int fd, char *buf, struct sockaddr_ll *fromaddr, int *ch,
	       int *br, WINDOW * win);
int processpacket(char *tpacket, char **packet, unsigned int *br,
		  unsigned int *total_br, unsigned int *sport,
		  unsigned int *dport, struct sockaddr_ll *fromaddr,
		  struct filterstate *ofilter,
		  int match_opposite, int v6inv4asv6);
void pkt_cleanup(void);

#endif	/* IPTRAF_NG_PACKET_H */
