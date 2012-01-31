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
#include "ipcsum.h"
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


static void adjustpacket(char *tpacket, struct sockaddr_ll *fromaddr,
			 char **packet, char *aligned_buf,
			 unsigned int *readlen)
{
	unsigned int dataoffset;

	switch (fromaddr->sll_hatype) {
	case ARPHRD_ETHER:
	case ARPHRD_LOOPBACK:
		if (fromaddr->sll_protocol == ETH_P_8021Q) {
			/* 0x8100 802.1Q VLAN Extended Header  */
			*packet = tpacket + VLAN_ETH_HLEN;
			readlen -= VLAN_ETH_HLEN;
			/*
			 * Move IP datagram into an aligned buffer.
			 */
			memmove(aligned_buf, *packet,
				min(SNAPSHOT_LEN, *readlen));
			*packet = aligned_buf;
			break;
		}

		*packet = tpacket + ETH_HLEN;
		*readlen -= ETH_HLEN;

		/*
		 * Move IP data into an aligned buffer.  96 bytes should be sufficient
		 * for IP and TCP headers with reasonable numbers of options and some
		 * data.
		 */

		memmove(aligned_buf, *packet, min(SNAPSHOT_LEN, *readlen));
		*packet = aligned_buf;
		break;
	case ARPHRD_SLIP:
	case ARPHRD_CSLIP:
	case ARPHRD_SLIP6:
	case ARPHRD_CSLIP6:
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

		/*
		 * Move IP data into an aligned buffer.  96 bytes should be sufficient
		 * for IP and TCP headers with reasonable numbers of options and some
		 * data.
		 */

		memmove(aligned_buf, *packet, min(SNAPSHOT_LEN, *readlen));
		*packet = aligned_buf;
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
		/*
		 * Move IP datagram into an aligned buffer.
		 */
		memmove(aligned_buf, *packet, min(SNAPSHOT_LEN, *readlen));
		*packet = aligned_buf;
		break;
	case ARPHRD_TUNNEL:
		*packet = tpacket;
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
		fromlen = sizeof(struct sockaddr_pkt);
		*br =
		    recvfrom(fd, buf, MAX_PACKET_SIZE, 0,
			     (struct sockaddr *) fromaddr, &fromlen);
		ifr.ifr_ifindex = fromaddr->sll_ifindex;
		ioctl(fd, SIOCGIFNAME, &ifr);
		strcpy(ifname, ifr.ifr_name);
	}
	if (!daemonized) {
		if (FD_ISSET(0, &set))
			*ch = wgetch(win);
	} else
		*ch = ERR;
}

int processpacket(char *tpacket, char **packet, unsigned int *br,
		  unsigned int *total_br, unsigned int *sport,
		  unsigned int *dport, struct sockaddr_ll *fromaddr,
		  unsigned short *linktype, struct filterstate *filter,
		  int match_opposite, char *ifname, char *ifptr)
{
	static char aligned_buf[ALIGNED_BUF_LEN];
	struct iphdr *ip;
	struct ip6_hdr *ip6;
	int hdr_check;
	register int ip_checksum;
	register int iphlen;

	unsigned int sport_tmp, dport_tmp;
	unsigned int f_sport, f_dport;

	int firstin;

	union {
		struct tcphdr *tcp;
		struct udphdr *udp;
	} in_ip;

	/*
	 * Does returned interface (ifname) match the specified interface name
	 * (ifptr)?
	 */
	if (ifptr && strcmp(ifptr, ifname) != 0)
		return INVALID_PACKET;

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
	if (fromaddr->sll_protocol == ETH_P_8021Q)
		fromaddr->sll_protocol =
		    ntohs(*((unsigned short *) (tpacket + ETH_HLEN + 2)));


	adjustpacket(tpacket, fromaddr, packet, aligned_buf, br);

	if (*packet == NULL)
		return INVALID_PACKET;

	/*
	 * Apply non-IP packet filter
	 */

	if ((fromaddr->sll_protocol != ETH_P_IP)
	    && (fromaddr->sll_protocol != ETH_P_IPV6)) {
		if ((fromaddr->sll_protocol == ETH_P_ARP)
		    || (fromaddr->sll_protocol == ETH_P_RARP)) {
			if (!nonipfilter(filter, fromaddr->sll_protocol)) {
				return PACKET_FILTERED;
			}
		} else {
			if (!nonipfilter(filter, 0)) {
				return PACKET_FILTERED;
			}
		}
		return PACKET_OK;
	}

	if (fromaddr->sll_protocol == ETH_P_IP) {

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
			/*
			 * Process TCP/UDP fragments
			 */
			if ((ntohs(ip->frag_off) & 0x3fff) != 0) {
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
				if (ip->protocol == IPPROTO_TCP) {
					in_ip.tcp =
					    (struct tcphdr *) ((char *) ip +
							       iphlen);
					sport_tmp = in_ip.tcp->source;
					dport_tmp = in_ip.tcp->dest;
				} else if (ip->protocol == IPPROTO_UDP) {
					in_ip.udp =
					    (struct udphdr *) ((char *) ip +
							       iphlen);
					sport_tmp = in_ip.udp->source;
					dport_tmp = in_ip.udp->dest;
				} else {
					sport_tmp = 0;
					dport_tmp = 0;
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

			if ((filter->filtercode != 0)
			    &&
			    (!ipfilter
			     (ip->saddr, ip->daddr, f_sport, f_dport,
			      ip->protocol, match_opposite, &(filter->fl))))
				return PACKET_FILTERED;
		} else {
			if ((filter->filtercode != 0)
			    &&
			    (!ipfilter
			     (ip->saddr, ip->daddr, 0, 0, ip->protocol,
			      match_opposite, &(filter->fl))))
				return PACKET_FILTERED;
		}
		return PACKET_OK;
	} else if (fromaddr->sll_protocol == ETH_P_IPV6) {
		ip6 = (struct ip6_hdr *) (*packet);
		iphlen = 40;
		//TODO: Filter packets
		if (ip6->ip6_nxt == IPPROTO_TCP) {
			in_ip.tcp = (struct tcphdr *) ((char *) ip6 + iphlen);
			if (sport != NULL)
				*sport = in_ip.tcp->source;
			if (dport != NULL)
				*dport = in_ip.tcp->dest;
		} else if (ip6->ip6_nxt == IPPROTO_UDP) {
			in_ip.udp = (struct udphdr *) ((char *) ip6 + iphlen);
			if (sport != NULL)
				*sport = in_ip.udp->source;
			if (dport != NULL)
				*dport = in_ip.udp->dest;
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
