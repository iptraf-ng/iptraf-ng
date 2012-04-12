/***

detstats.c	- the interface statistics module
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
#include "tui/tui.h"

#include "ifstats.h"
#include "ifaces.h"
#include "isdntab.h"
#include "fltdefs.h"
#include "fltselect.h"
#include "packet.h"
#include "options.h"
#include "log.h"
#include "dirs.h"
#include "deskman.h"
#include "attrs.h"
#include "serv.h"
#include "timer.h"
#include "instances.h"
#include "logvars.h"
#include "promisc.h"
#include "error.h"

extern int exitloop;
extern int daemonized;

/* from log.c, applicable only to this module */
void writedstatlog(char *ifname, int unit,
		   float peakactivity, float peakpps, float peakactivity_in,
		   float peakpps_in, float peakactivity_out, float peakpps_out,
		   struct ifcounts *ts, unsigned long nsecs, FILE * logfile);

/* USR1 log-rotation signal handlers */
static void rotate_dstat_log(int s __unused)
{
	rotate_flag = 1;
	strcpy(target_logname, current_logfile);
	signal(SIGUSR1, rotate_dstat_log);
}

static void printdetlabels(WINDOW * win)
{
	wattrset(win, BOXATTR);
	mvwprintw(win, 2, 14,
		  "  Total      Total    Incoming   Incoming    Outgoing   Outgoing");
	mvwprintw(win, 3, 14,
		  "Packets      Bytes     Packets      Bytes     Packets      Bytes");
	wattrset(win, STDATTR);
	mvwprintw(win, 4, 2, "Total:");
	mvwprintw(win, 5, 2, "IPv4:");
	mvwprintw(win, 6, 2, "IPv6:");
	mvwprintw(win, 7, 2, "TCP:");
	mvwprintw(win, 8, 2, "UDP:");
	mvwprintw(win, 9, 2, "ICMP:");
	mvwprintw(win, 10, 2, "Other IP:");
	mvwprintw(win, 11, 2, "Non-IP:");
	mvwprintw(win, 14, 2, "Total rates:");
	mvwprintw(win, 17, 2, "Incoming rates:");
	mvwprintw(win, 20, 2, "Outgoing rates:");

	mvwprintw(win, 14, 45, "Broadcast packets:");
	mvwprintw(win, 15, 45, "Broadcast bytes:");
	mvwprintw(win, 19, 45, "IP checksum errors:");

	update_panels();
	doupdate();
}

static void printstatrow(WINDOW * win, int row, unsigned long long total,
		  unsigned long long btotal, unsigned long long total_in,
		  unsigned long long btotal_in, unsigned long long total_out,
		  unsigned long long btotal_out)
{
	wmove(win, row, 12);
	printlargenum(total, win);
	wmove(win, row, 23);
	printlargenum(btotal, win);
	wmove(win, row, 35);
	printlargenum(total_in, win);
	wmove(win, row, 46);
	printlargenum(btotal_in, win);
	wmove(win, row, 58);
	printlargenum(total_out, win);
	wmove(win, row, 69);
	printlargenum(btotal_out, win);
}

static void printstatrow_proto(WINDOW *win, int row, struct proto_counter *proto_counter)
{
	printstatrow(win, row,
		     proto_counter->proto_total.pc_packets,
		     proto_counter->proto_total.pc_bytes,
		     proto_counter->proto_in.pc_packets,
		     proto_counter->proto_in.pc_bytes,
		     proto_counter->proto_out.pc_packets,
		     proto_counter->proto_out.pc_bytes);
}

static void printdetails(struct ifcounts *ifcounts, WINDOW * win)
{
	wattrset(win, HIGHATTR);
	/* Print totals on the IP protocols */
	printstatrow_proto(win, 4, &ifcounts->total);
	printstatrow_proto(win, 5, &ifcounts->ipv4);
	printstatrow_proto(win, 6, &ifcounts->ipv6);
	printstatrow_proto(win, 7, &ifcounts->tcp);
	printstatrow_proto(win, 8, &ifcounts->udp);
	printstatrow_proto(win, 9, &ifcounts->icmp);
	printstatrow_proto(win, 10, &ifcounts->other);

	/* Print non-IP totals */

	printstatrow_proto(win, 11, &ifcounts->nonip);

	/* Broadcast totals */
	wmove(win, 14, 67);
	printlargenum(ifcounts->bcast.pc_packets, win);
	wmove(win, 15, 67);
	printlargenum(ifcounts->bcast.pc_bytes, win);

	/* Bad packet count */

	mvwprintw(win, 19, 68, "%8lu", ifcounts->bad.pc_packets);
}

static void update_counter(struct pkt_counter *count, int bytes)
{
	if (count) {
		count->pc_packets++;
		count->pc_bytes += bytes;
	}
}

static void update_proto_counter(struct proto_counter *proto_counter, int outgoing, int bytes)
{
	if (proto_counter) {
		update_counter(&proto_counter->proto_total, bytes);
		if (outgoing)
			update_counter(&proto_counter->proto_out, bytes);
		else
			update_counter(&proto_counter->proto_in, bytes);
	}
}


/*
 * The detailed interface statistics function
 */
void detstats(char *iface, const struct OPTIONS *options, time_t facilitytime,
	      struct filterstate *ofilter)
{
	int logging = options->logging;

	WINDOW *statwin;
	PANEL *statpanel;

	char buf[MAX_PACKET_SIZE];
	char *packet;
	struct iphdr *ipacket = NULL;
	struct ip6_hdr *ip6packet = NULL;

	struct sockaddr_ll fromaddr;

	int br;
	int framelen = 0;
	int pkt_result = 0;

	FILE *logfile = NULL;

	unsigned int iplen = 0;

	struct ifcounts ifcounts;

	int ch;

	struct timeval tv;
	time_t updtime = 0;
	unsigned long long updtime_usec = 0;
	time_t starttime;
	time_t now;
	time_t statbegin;
	time_t startlog;
	time_t rate_interval;
	unsigned long long unow;

	struct proto_counter span;

	float activity = 0;
	float activity_in = 0;
	float activity_out = 0;
	float peakactivity = 0;
	float peakactivity_in = 0;
	float peakactivity_out = 0;

	float pps = 0;
	float peakpps = 0;
	float pps_in = 0;
	float pps_out = 0;
	float peakpps_in = 0;
	float peakpps_out = 0;

	struct promisc_states *promisc_list;
	int fd;

	/*
	 * Mark this facility
	 */

	if (!facility_active(DSTATIDFILE, iface))
		mark_facility(DSTATIDFILE, "detailed interface statistics",
			      iface);
	else {
		write_error("Detailed interface stats already monitoring %s", iface);
		return;
	}

	if (!iface_up(iface)) {
		err_iface_down();
		unmark_facility(DSTATIDFILE, iface);
		return;
	}

	if ((first_active_facility()) && (options->promisc)) {
		init_promisc_list(&promisc_list);
		save_promisc_list(promisc_list);
		srpromisc(1, promisc_list);
		destroy_promisc_list(&promisc_list);
	}

	adjust_instance_count(PROCCOUNTFILE, 1);

	move(LINES - 1, 1);
	stdexitkeyhelp();
	statwin = newwin(LINES - 2, COLS, 1, 0);
	statpanel = new_panel(statwin);
	tx_stdwinset(statwin);
	wtimeout(statwin, -1);
	wattrset(statwin, BOXATTR);
	tx_colorwin(statwin);
	tx_box(statwin, ACS_VLINE, ACS_HLINE);
	wmove(statwin, 0, 1);
	wprintw(statwin, " Statistics for %s ", iface);
	wattrset(statwin, STDATTR);
	update_panels();
	doupdate();

	memset(&ifcounts, 0, sizeof(struct ifcounts));

	if (logging) {
		if (strcmp(current_logfile, "") == 0) {
			snprintf(current_logfile, 64, "%s-%s.log", DSTATLOG,
				 iface);

			if (!daemonized)
				input_logfile(current_logfile, &logging);
		}
	}

	if (logging) {
		opentlog(&logfile, current_logfile);

		if (logfile == NULL)
			logging = 0;
	}
	if (logging)
		signal(SIGUSR1, rotate_dstat_log);

	rotate_flag = 0;
	writelog(logging, logfile,
		 "******** Detailed interface statistics started ********");

	printdetlabels(statwin);
	printdetails(&ifcounts, statwin);
	update_panels();
	doupdate();

	memset(&span, 0, sizeof(span));

	gettimeofday(&tv, NULL);
	starttime = startlog = statbegin = tv.tv_sec;

	leaveok(statwin, TRUE);

	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(fd == -1) {
		write_error("Unable to obtain monitoring socket");
		goto err;
	}
	if(socket_bind_to_iface_by_name(fd, iface) == -1) {
		write_error("Unable to bind interface on the socket");
		goto err_close;
	}

	//isdnfd = -1;
	exitloop = 0;

	/*
	 * Data-gathering loop
	 */

	while (!exitloop) {
		gettimeofday(&tv, NULL);
		now = tv.tv_sec;
		unow = tv.tv_sec * 1000000ULL + tv.tv_usec;

		rate_interval = now - starttime;

		if (rate_interval >= 5) {
			wattrset(statwin, BOXATTR);
			printelapsedtime(statbegin, now, LINES - 3, 1, statwin);
			if (options->actmode == KBITS) {
				activity =
				    (float) (span.proto_total.pc_bytes * 8 / 1000) /
				    (float) rate_interval;
				activity_in =
				    (float) (span.proto_in.pc_bytes * 8 / 1000) /
				    (float) rate_interval;
				activity_out =
				    (float) (span.proto_out.pc_bytes * 8 / 1000) /
				    (float) rate_interval;
			} else {
				activity =
				    (float) (span.proto_total.pc_bytes / 1024) /
				    (float) rate_interval;
				activity_in =
				    (float) (span.proto_in.pc_bytes / 1024) /
				    (float) rate_interval;
				activity_out =
				    (float) (span.proto_out.pc_bytes / 1024) /
				    (float) rate_interval;
			}

			pps = (float) (span.proto_total.pc_packets) / (float) rate_interval;
			pps_in = (float) (span.proto_in.pc_packets) / (float) rate_interval;
			pps_out = (float) (span.proto_out.pc_packets) / (float) rate_interval;

			memset(&span, 0, sizeof(span));
			starttime = now;

			wattrset(statwin, HIGHATTR);
			mvwprintw(statwin, 14, 19, "%8.1f %s", activity,
				  dispmode(options->actmode));
			mvwprintw(statwin, 15, 19, "%8.1f pps", pps);
			mvwprintw(statwin, 17, 19, "%8.1f %s", activity_in,
				  dispmode(options->actmode));
			mvwprintw(statwin, 18, 19, "%8.1f pps", pps_in);
			mvwprintw(statwin, 20, 19, "%8.1f %s", activity_out,
				  dispmode(options->actmode));
			mvwprintw(statwin, 21, 19, "%8.1f pps",
				  pps_out);

			if (activity > peakactivity)
				peakactivity = activity;

			if (activity_in > peakactivity_in)
				peakactivity_in = activity_in;

			if (activity_out > peakactivity_out)
				peakactivity_out = activity_out;

			if (pps > peakpps)
				peakpps = pps;

			if (pps_in > peakpps_in)
				peakpps_in = pps_in;

			if (pps_out > peakpps_out)
				peakpps_out = pps_out;
		}
		if ((now - startlog) >= options->logspan && logging) {
			writedstatlog(iface, options->actmode,
				      peakactivity, peakpps, peakactivity_in,
				      peakpps_in, peakactivity_out, peakpps_out,
				      &ifcounts,
				      time((time_t *) NULL) - statbegin,
				      logfile);

			startlog = now;
		}

		if (((options->updrate == 0)
		     && (unow - updtime_usec >= DEFAULT_UPDATE_DELAY))
		    || ((options->updrate != 0)
			&& (now - updtime >= options->updrate))) {
			printdetails(&ifcounts, statwin);
			update_panels();
			doupdate();
			updtime_usec = unow;
			updtime = now;
		}
		check_rotate_flag(&logfile, logging);

		if ((facilitytime != 0)
		    && (((now - statbegin) / 60) >= facilitytime))
			exitloop = 1;

		getpacket(fd, buf, &fromaddr, &ch, &br, statwin);

		switch (ch) {
		case ERR:
			/* no key ready, do nothing */
			break;
		case 12:
		case 'l':
		case 'L':
			tx_refresh_screen();
			break;

		case 'Q':
		case 'q':
		case 'X':
		case 'x':
		case 24:
		case 27:
			exitloop = 1;
			break;
		}
		if (br > 0) {
			int outgoing;
			short ipproto;

			framelen = br;
			pkt_result =
			    processpacket(buf, &packet, (unsigned int *) &br,
					  NULL, NULL, NULL, &fromaddr,
					  ofilter,
					  MATCH_OPPOSITE_USECONFIG,
					  options->v6inv4asv6);

			if (pkt_result != PACKET_OK
			    && pkt_result != MORE_FRAGMENTS)
				continue;

			outgoing = (fromaddr.sll_pkttype == PACKET_OUTGOING);
			update_proto_counter(&ifcounts.total, outgoing, framelen);
			if (fromaddr.sll_pkttype == PACKET_BROADCAST) {
				update_counter(&ifcounts.bcast, framelen);
			}

			update_proto_counter(&span, outgoing, framelen);

			/* account network layer protocol */
			switch(fromaddr.sll_protocol) {
			case ETH_P_IP:
				if (pkt_result == CHECKSUM_ERROR) {
					update_counter(&ifcounts.bad, framelen);
					continue;
				}

				ipacket = (struct iphdr *) packet;
				iplen = ntohs(ipacket->tot_len);
				ipproto = ipacket->protocol;

				update_proto_counter(&ifcounts.ipv4, outgoing, iplen);
				break;
			case ETH_P_IPV6:
				ip6packet = (struct ip6_hdr *) packet;
				iplen = ntohs(ip6packet->ip6_plen) + 40;
				ipproto = ip6packet->ip6_nxt;

				update_proto_counter(&ifcounts.ipv6, outgoing, iplen);
				break;
			default:
				update_proto_counter(&ifcounts.nonip, outgoing, iplen);
				continue;
			}

			/* account transport layer protocol */
			switch (ipproto) {
			case IPPROTO_TCP:
				update_proto_counter(&ifcounts.tcp, outgoing, iplen);
				break;
			case IPPROTO_UDP:
				update_proto_counter(&ifcounts.udp, outgoing, iplen);
				break;
			case IPPROTO_ICMP:
			case IPPROTO_ICMPV6:
				update_proto_counter(&ifcounts.icmp, outgoing, iplen);
				break;
			default:
				update_proto_counter(&ifcounts.other, outgoing, iplen);
				break;
			}
		}
	}

err_close:
	close(fd);

err:
	if ((options->promisc) && (is_last_instance())) {
		load_promisc_list(&promisc_list);
		srpromisc(0, promisc_list);
		destroy_promisc_list(&promisc_list);
	}

	adjust_instance_count(PROCCOUNTFILE, -1);

	if (logging) {
		signal(SIGUSR1, SIG_DFL);
		writedstatlog(iface, options->actmode,
			      peakactivity, peakpps, peakactivity_in,
			      peakpps_in, peakactivity_out, peakpps_out,
			      &ifcounts, time((time_t *) NULL) - statbegin,
			      logfile);
		writelog(logging, logfile,
			 "******** Detailed interface statistics stopped ********");
		fclose(logfile);
	}

	del_panel(statpanel);
	delwin(statwin);
	unmark_facility(DSTATIDFILE, iface);
	strcpy(current_logfile, "");
	pkt_cleanup();
	update_panels();
	doupdate();
}