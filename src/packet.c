/***

packet.c - routines to open the raw socket, read socket data and
           adjust the initial packet pointer

Written by Gerard Paul Java
Copyright (c) Gerard Paul Java 1997-2002

This software is open source; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed WITHOUT ANY WARRANTY; without even the
implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License in the included COPYING file for
details.

***/

#include "iptraf-ng-compat.h"

#include "deskman.h"
#include "error.h"
#include "options.h"
#include "fltdefs.h"
#include "fltselect.h"
#include "isdntab.h"
#include "ifaces.h"
#include "packet.h"
#include "ipfrag.h"
#include "tr.h"


/* Reimplement again
 * Removed PPP, LINK_ISDN, PLIP
 */

extern int daemonized;

/*
int isdnfd;
struct isdntab isdntable;
*/

/* code taken from http://www.faqs.org/rfcs/rfc1071.html. See section 4.1 "C"  */
static int in_cksum(u_short * addr, int len)
{
	register int sum = 0;

	while (len > 1) {
		sum += *(u_short *) addr++;
		len -= 2;
	}

	if (len > 1)
		sum += *(unsigned char *) addr;

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return (u_short) (~sum);
}

static void adjustpacket(char *tpacket, struct sockaddr_ll *fromaddr,
			 char **packet, unsigned int *readlen)
{
	unsigned int dataoffset;

	switch (fromaddr->sll_hatype) {
	case ARPHRD_ETHER:
	case ARPHRD_LOOPBACK:
		*packet = tpacket + ETH_HLEN;
		*readlen -= ETH_HLEN;
		if (fromaddr->sll_protocol == ETH_P_8021Q) {
			/* strip 0x8100 802.1Q VLAN Extended Header  */
			*packet += 4;
			*readlen -= 4;
			/* update network protocol */
			fromaddr->sll_protocol = *((unsigned short *) *packet);
		}
		break;
	case ARPHRD_SLIP:
	case ARPHRD_CSLIP:
	case ARPHRD_SLIP6:
	case ARPHRD_PPP:
	case ARPHRD_CSLIP6:
	case ARPHRD_TUNNEL:
	case ARPHRD_NONE:
	case ARPHRD_IPGRE:
		*packet = tpacket;
		break;
	case ARPHRD_FRAD:
	case ARPHRD_DLCI:
		*packet = tpacket + 4;
		*readlen -= 4;
		break;
	case ARPHRD_FDDI:
		*packet = tpacket + sizeof(struct fddihdr);
		*readlen -= sizeof(struct fddihdr);
		break;
	case ARPHRD_IEEE802_TR:
	case ARPHRD_IEEE802:
		/*
		 * Token Ring patch supplied by Tomas Dvorak
		 */

		/*
		 * Get the start of the IP packet from the Token Ring frame.
		 */
		dataoffset = get_tr_ip_offset((unsigned char *) tpacket);
		*packet = tpacket + dataoffset;
		*readlen -= dataoffset;
		break;
	default:
		*packet = (char *) NULL;	/* return a NULL packet to signal */
		break;		/* an unrecognized link protocol */
	}			/* to the caller.  Hopefully, this */
}				/* switch statement will grow. */

/*
 * IPTraf input function; reads both keystrokes and network packets.
 */

void getpacket(int fd, char *buf, struct sockaddr_ll *fromaddr, int *ch,
	       int *br, char *ifname, WINDOW * win)
{
	socklen_t fromlen;
	fd_set set;
	struct timeval tv;
	int ss;
	struct ifreq ifr;

	FD_ZERO(&set);

	/*
	 * Monitor stdin only if in interactive, not daemon mode.
	 */

	if (!daemonized)
		FD_SET(0, &set);

	/*
	 * Monitor raw socket
	 */

	FD_SET(fd, &set);

	tv.tv_sec = 0;
	tv.tv_usec = DEFAULT_UPDATE_DELAY;

	do {
		ss = select(fd + 1, &set, 0, 0, &tv);
	} while ((ss < 0) && (errno == EINTR));

	*br = 0;
	*ch = ERR;

	if (FD_ISSET(fd, &set)) {
		fromlen = sizeof(struct sockaddr_ll);
		*br = recvfrom(fd, buf, MAX_PACKET_SIZE, 0,
			       (struct sockaddr *) fromaddr, &fromlen);
		ifr.ifr_ifindex = fromaddr->sll_ifindex;
		ioctl(fd, SIOCGIFNAME, &ifr);
		strcpy(ifname, ifr.ifr_name);
	}
	if (!daemonized && FD_ISSET(0, &set))
		*ch = wgetch(win);
}

int processpacket(char *tpacket, char **packet, unsigned int *br,
		  unsigned int *total_br, unsigned int *sport,
		  unsigned int *dport, struct sockaddr_ll *fromaddr,
		  struct filterstate *filter,
		  int match_opposite, char *ifname, int v6inv4asv6)
{
#if 0				/* reenable isdn */
	/*
	 * Prepare ISDN reference descriptor and table.
	 */

	memset(&isdntable, 0, sizeof(struct isdntab));
	isdn_iface_check(&isdnfd, ifname);
#endif
	/*
	 * Get IPTraf link type based on returned information and move past
	 * data link header.
	 */
	fromaddr->sll_protocol = ntohs(fromaddr->sll_protocol);
	adjustpacket(tpacket, fromaddr, packet, br);

	if (*packet == NULL)
		return INVALID_PACKET;

again:	if (fromaddr->sll_protocol == ETH_P_IP) {
		struct iphdr *ip;
		int hdr_check;
		register int ip_checksum;
		register int iphlen;
		unsigned int f_sport = 0, f_dport = 0;

		/*
		 * At this point, we're now processing IP packets.  Start by getting
		 * IP header and length.
		 */
		ip = (struct iphdr *) (*packet);
		iphlen = ip->ihl * 4;

		/*
		 * Compute and verify IP header checksum.
		 */

		ip_checksum = ip->check;
		ip->check = 0;
		hdr_check = in_cksum((u_short *) ip, iphlen);

		if ((hdr_check != ip_checksum))
			return CHECKSUM_ERROR;

		if ((ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP)
		    && (sport != NULL && dport != NULL)) {
			unsigned int sport_tmp, dport_tmp;

			/*
			 * Process TCP/UDP fragments
			 */
			if ((ntohs(ip->frag_off) & 0x3fff) != 0) {
				int firstin;

				/*
				 * total_br contains total byte count of all fragments
				 * not yet retrieved.  Will differ only if fragments
				 * arrived before the first fragment, in which case
				 * the total accumulated fragment sizes will be returned
				 * once the first fragment arrives.
				 */

				if (total_br != NULL)
					*total_br =
					    processfragment(ip, &sport_tmp,
							    &dport_tmp,
							    &firstin);

				if (!firstin)
					return MORE_FRAGMENTS;
			} else {
				struct tcphdr *tcp;
				struct udphdr *udp;
				char *ip_payload = (char *) ip + iphlen;

				switch (ip->protocol) {
				case IPPROTO_TCP:
					tcp = (struct tcphdr *) ip_payload;
					sport_tmp = tcp->source;
					dport_tmp = tcp->dest;
					break;
				case IPPROTO_UDP:
					udp = (struct udphdr *) ip_payload;
					sport_tmp = udp->source;
					dport_tmp = udp->dest;
					break;
				default:
					sport_tmp = 0;
					dport_tmp = 0;
					break;
				}

				if (total_br != NULL)
					*total_br = *br;
			}

			if (sport != NULL)
				*sport = sport_tmp;

			if (dport != NULL)
				*dport = dport_tmp;

			/*
			 * Process IP filter
			 */
			f_sport = ntohs(sport_tmp);
			f_dport = ntohs(dport_tmp);
		}
		if ((filter->filtercode != 0)
		    &&
		    (!ipfilter
		     (ip->saddr, ip->daddr, f_sport, f_dport, ip->protocol,
		      match_opposite, &(filter->fl))))
			return PACKET_FILTERED;
		if (v6inv4asv6 && (ip->protocol == IPPROTO_IPV6)) {
			fromaddr->sll_protocol = ETH_P_IPV6;
			*packet += iphlen;
			*br -= iphlen;
			goto again;
		}
		return PACKET_OK;
	} else if (fromaddr->sll_protocol == ETH_P_IPV6) {
		struct tcphdr *tcp;
		struct udphdr *udp;
		struct ip6_hdr *ip6 = (struct ip6_hdr *) *packet;
		char *ip_payload = (char *) ip6 + 40;

		//TODO: Filter packets
		switch (ip6->ip6_nxt) {	/* FIXME: extension headers ??? */
		case IPPROTO_TCP:
			tcp = (struct tcphdr *) ip_payload;
			if (sport)
				*sport = tcp->source;
			if (dport)
				*dport = tcp->dest;
			break;
		case IPPROTO_UDP:
			udp = (struct udphdr *) ip_payload;
			if (sport)
				*sport = udp->source;
			if (dport)
				*dport = udp->dest;
			break;
		default:
			if (sport)
				*sport = 0;
			if (dport)
				*dport = 0;
			break;
		}
	} else {
		/* not IPv4 and not IPv6: apply non-IP packet filter */
		if (!nonipfilter(filter, fromaddr->sll_protocol)) {
			return PACKET_FILTERED;
		}
	}
	return PACKET_OK;
}

void pkt_cleanup(void)
{
	// close(isdnfd);
	// isdnfd = -1;
	destroyfraglist();
	// destroy_isdn_table(&isdntable);
}
