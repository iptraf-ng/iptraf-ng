
/***

log.c - the iptraf logging facility
Written by Gerard Paul Java
Copyright (c) Gerard Paul Java 1997, 1998

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

#include "attrs.h"
#include "deskman.h"
#include "dirs.h"
#include "options.h"
#include "tcptable.h"
#include "othptab.h"
#include "ifstats.h"
#include "serv.h"
#include "pktsize.h"
#include "hostmon.h"

#define MSGSTRING_MAX		240
#define TARGET_LOGNAME_MAX	160
#define TIME_TARGET_MAX		30

int rotate_flag;
char target_logname[TARGET_LOGNAME_MAX];
char current_logfile[TARGET_LOGNAME_MAX];
char graphing_logfile[TARGET_LOGNAME_MAX];

/*
 * Generates a log file based on a template for a particular instance of
 * a facility.   Used by the IP Traffic Monitor and LAN Station Monitor.
 */

char *gen_instance_logname(char *template, int instance_num)
{
	static char filename[80];

	snprintf(filename, 80, "%s-%d.log", template, instance_num);
	return filename;
}

void input_logfile(char *target, int *logging)
{
	WINDOW *dlgwin;
	PANEL *dlgpanel;
	struct FIELDLIST fieldlist;
	int aborted;

	dlgwin = newwin(11, 60, (LINES - 11) / 2, (COLS - 60) / 2);
	dlgpanel = new_panel(dlgwin);

	wattrset(dlgwin, DLGBOXATTR);
	tx_colorwin(dlgwin);
	tx_box(dlgwin, ACS_VLINE, ACS_HLINE);
	mvwprintw(dlgwin, 0, 1, " Logging Enabled ");
	wattrset(dlgwin, DLGTEXTATTR);
	mvwprintw(dlgwin, 2, 2,
		  "Enter the name of the file to which to write the log.");
	mvwprintw(dlgwin, 4, 2,
		  "If you don't specify a path, the log file will");
	mvwprintw(dlgwin, 5, 2, "be placed in %s.", LOGDIR);
	wmove(dlgwin, 9, 2);
	stdkeyhelp(dlgwin);
	wprintw(dlgwin, " (turns logging off)");

	tx_initfields(&fieldlist, 1, 50, (LINES - 1) / 2 + 2,
		      (COLS - 50) / 2 - 3, DLGTEXTATTR, FIELDATTR);
	tx_addfield(&fieldlist, 48, 0, 0, target);
	tx_fillfields(&fieldlist, &aborted);

	if (!aborted) {
		if (strchr(fieldlist.list->buf, '/') == NULL)
			snprintf(target, 48, "%s/%s", LOGDIR,
				 fieldlist.list->buf);
		else
			strncpy(target, fieldlist.list->buf, 48);
	}

	*logging = !aborted;

	tx_destroyfields(&fieldlist);
	del_panel(dlgpanel);
	delwin(dlgwin);
	update_panels();
	doupdate();
}

void opentlog(FILE ** fd, char *logfilename)
{
	*fd = fopen(logfilename, "a");

	if (*fd == NULL)
		tui_error(ANYKEY_MSG, "Unable to open log file");

	rotate_flag = 0;
	strcpy(target_logname, "");
}

void genatime(time_t now, char *atime)
{
	memset(atime, 0, TIME_TARGET_MAX);
	strncpy(atime, ctime(&now), 26);
	atime[strlen(atime) - 1] = '\0';
}

void writelog(int logging, FILE * fd, char *msg)
{
	char atime[TIME_TARGET_MAX];

	if (logging) {
		genatime(time((time_t *) NULL), atime);
		fprintf(fd, "%s; %s\n", atime, msg);
	}

	fflush(fd);
}

void write_daemon_err(char *msg)
{
	char atime[TIME_TARGET_MAX];
	FILE *fd;

	genatime(time((time_t *) NULL), atime);
	fd = fopen(DAEMONLOG, "a");
	fprintf(fd, "%s iptraf[%u]: %s\n", atime, getpid(), msg);
	fclose(fd);
}

void writetcplog(int logging, FILE * fd, struct tcptableent *entry,
		 unsigned int pktlen, int mac, char *message)
{
	char msgbuf[MSGSTRING_MAX];

	if (logging) {
		if (mac) {
			snprintf(msgbuf, MSGSTRING_MAX,
				 "TCP; %s; %u bytes; from %s:%s to %s:%s (source MAC addr %s); %s",
				 entry->ifname, pktlen, entry->s_fqdn,
				 entry->s_sname, entry->d_fqdn, entry->d_sname,
				 entry->smacaddr, message);
		} else {
			snprintf(msgbuf, MSGSTRING_MAX,
				 "TCP; %s; %u bytes; from %s:%s to %s:%s; %s",
				 entry->ifname, pktlen, entry->s_fqdn,
				 entry->s_sname, entry->d_fqdn, entry->d_sname,
				 message);
		}

		writelog(logging, fd, msgbuf);
	}
}

void write_tcp_unclosed(int logging, FILE * fd, struct tcptable *table)
{
	char msgbuf[MSGSTRING_MAX];

	struct tcptableent *entry = table->head;

	while (entry != NULL) {
		if ((entry->finsent == 0) && ((entry->stat & FLAG_RST) == 0)
		    && (!(entry->inclosed))) {
			sprintf(msgbuf,
				"TCP; %s; active; from %s:%s to %s:%s; %lu packets, %lu bytes",
				entry->ifname, entry->s_fqdn, entry->s_sname,
				entry->d_fqdn, entry->d_sname, entry->pcount,
				entry->bcount);
			writelog(logging, fd, msgbuf);
		}
		entry = entry->next_entry;
	}
}

void writeothplog(int logging, FILE * fd, char *protname, char *description,
		  char *additional, int is_ip, int withmac,
		  struct othptabent *entry)
{
	char msgbuffer[MSGSTRING_MAX];
	char scratchpad[MSGSTRING_MAX];

	if (logging) {
		memset(msgbuffer, 0, MSGSTRING_MAX);

		strcpy(msgbuffer, protname);
		strcat(msgbuffer, "; ");
		strcat(msgbuffer, entry->iface);
		sprintf(scratchpad, "; %u bytes;", entry->pkt_length);
		strcat(msgbuffer, scratchpad);

		if ((entry->smacaddr[0] != '\0') && (withmac)) {
			sprintf(scratchpad, " source MAC address %s;",
				entry->smacaddr);
			strcat(msgbuffer, scratchpad);
		}

		if (is_ip) {
			if (((entry->protocol == IPPROTO_UDP)
			     && (!(entry->fragment)))
			    || (entry->protocol == IPPROTO_TCP))
				sprintf(scratchpad, " from %s:%s to %s:%s",
					entry->s_fqdn, entry->un.udp.s_sname,
					entry->d_fqdn, entry->un.udp.d_sname);
			else
				sprintf(scratchpad, " from %s to %s",
					entry->s_fqdn, entry->d_fqdn);
		} else
			sprintf(scratchpad, " from %s to %s ", entry->smacaddr,
				entry->dmacaddr);

		strcat(msgbuffer, scratchpad);
		strcpy(scratchpad, "");
		if (strcmp(description, "") != 0) {
			sprintf(scratchpad, "; %s", description);
			strcat(msgbuffer, scratchpad);
		}
		strcpy(scratchpad, "");
		if (strcmp(additional, "") != 0) {
			sprintf(scratchpad, " (%s)", additional);
			strcat(msgbuffer, scratchpad);
		}
		writelog(logging, fd, msgbuffer);
	}
}

void writegstatlog(struct iftab *table, int unit, unsigned long nsecs,
		   FILE * fd)
{
	struct iflist *ptmp = table->head;
	char atime[TIME_TARGET_MAX];

	genatime(time((time_t *) NULL), atime);
	fprintf(fd, "\n*** General interface statistics log generated %s\n\n",
		atime);

	while (ptmp != NULL) {

		fprintf(fd,
			"%s: %llu total, %llu IP, %llu non-IP, %lu IP checksum errors",
			ptmp->ifname, ptmp->total, ptmp->iptotal,
			ptmp->noniptotal, ptmp->badtotal);

		if (nsecs > 5) {
			if (unit == KBITS) {
				fprintf(fd, ", average activity %.2f %s",
					(float) (ptmp->br * 8 / 1000) /
					(float) nsecs, dispmode(unit));
			} else {
				fprintf(fd, ", average activity %.2f %s",
					(float) (ptmp->br / 1024) /
					(float) nsecs, dispmode(unit));
			}

			fprintf(fd, ", peak activity %.2f %s", ptmp->peakrate,
				dispmode(unit));
			fprintf(fd, ", last 5-second activity %.2f %s",
				ptmp->rate, dispmode(unit));
		}
		fprintf(fd, "\n");

		ptmp = ptmp->next_entry;
	}

	fprintf(fd, "\n%lu seconds running time\n", nsecs);
	fflush(fd);
}

void writedstatlog(char *ifname, int unit, float activity, float pps,
		   float peakactivity, float peakpps, float peakactivity_in,
		   float peakpps_in, float peakactivity_out, float peakpps_out,
		   struct ifcounts *ts, unsigned long nsecs, FILE * fd)
{
	char atime[TIME_TARGET_MAX];

	genatime(time((time_t *) NULL), atime);

	fprintf(fd,
		"\n*** Detailed statistics for interface %s, generated %s\n\n",
		ifname, atime);

	fprintf(fd, "Total: \t%llu packets, %llu bytes\n",
		ts->total.proto_total.pc_packets,
		ts->total.proto_total.pc_bytes);
	fprintf(fd,
		"\t(incoming: %llu packets, %llu bytes; outgoing: %llu packets, %llu bytes)\n",
		ts->total.proto_in.pc_packets,
		ts->total.proto_in.pc_bytes,
		ts->total.proto_out.pc_packets,
		ts->total.proto_out.pc_bytes);
	fprintf(fd, "IP: \t%llu packets, %llu bytes\n",
		ts->ipv4.proto_total.pc_packets,
		ts->ipv4.proto_total.pc_bytes);
	fprintf(fd,
		"\t(incoming: %llu packets, %llu bytes; outgoing: %llu packets, %llu bytes)\n",
		ts->ipv4.proto_in.pc_packets,
		ts->ipv4.proto_in.pc_bytes,
		ts->ipv4.proto_out.pc_packets,
		ts->ipv4.proto_out.pc_bytes);
	fprintf(fd, "TCP: %llu packets, %llu bytes\n",
		ts->tcp.proto_total.pc_packets,
		ts->tcp.proto_total.pc_bytes);
	fprintf(fd,
		"\t(incoming: %llu packets, %llu bytes; outgoing: %llu packets, %llu bytes)\n",
		ts->tcp.proto_in.pc_packets,
		ts->tcp.proto_in.pc_bytes,
		ts->tcp.proto_out.pc_packets,
		ts->tcp.proto_out.pc_bytes);
	fprintf(fd, "UDP: %llu packets, %llu bytes\n",
		ts->udp.proto_total.pc_packets,
		ts->udp.proto_total.pc_bytes);
	fprintf(fd,
		"\t(incoming: %llu packets, %llu bytes; outgoing: %llu packets, %llu bytes)\n",
		ts->udp.proto_in.pc_packets,
		ts->udp.proto_in.pc_bytes,
		ts->udp.proto_out.pc_packets,
		ts->udp.proto_out.pc_bytes);
	fprintf(fd, "ICMP: %llu packets, %llu bytes\n",
		ts->icmp.proto_total.pc_packets,
		ts->icmp.proto_total.pc_bytes);
	fprintf(fd,
		"\t(incoming: %llu packets, %llu bytes; outgoing: %llu packets, %llu bytes)\n",
		ts->icmp.proto_in.pc_packets,
		ts->icmp.proto_in.pc_bytes,
		ts->icmp.proto_out.pc_packets,
		ts->icmp.proto_out.pc_bytes);
	fprintf(fd, "Other IP: %llu packets, %llu bytes\n",
		ts->other.proto_total.pc_packets,
		ts->other.proto_total.pc_bytes);
	fprintf(fd,
		"\t(incoming: %llu packets, %llu bytes; outgoing: %llu packets, %llu bytes)\n",
		ts->other.proto_in.pc_packets,
		ts->other.proto_in.pc_bytes,
		ts->other.proto_out.pc_packets,
		ts->other.proto_out.pc_bytes);
	fprintf(fd, "Non-IP: %llu packets, %llu bytes\n",
		ts->nonip.proto_total.pc_packets,
		ts->nonip.proto_total.pc_bytes);
	fprintf(fd,
		"\t(incoming: %llu packets, %llu bytes; outgoing: %llu packets, %llu bytes)\n",
		ts->nonip.proto_in.pc_packets,
		ts->nonip.proto_in.pc_bytes,
		ts->nonip.proto_out.pc_packets,
		ts->nonip.proto_out.pc_bytes);
	fprintf(fd, "Broadcast: %llu packets, %llu bytes\n",
		ts->bcast.pc_packets,
		ts->bcast.pc_bytes);

	if (nsecs > 5) {
		fprintf(fd, "\nAverage rates:\n");

		if (unit == KBITS) {
			fprintf(fd, "  Total:\t%.2f kbits/s, %.2f packets/s\n",
				((float) (ts->total.proto_total.pc_bytes * 8 / 1000) /
				 (float) nsecs),
				((float) (ts->total.proto_total.pc_packets) / (float) nsecs));
			fprintf(fd,
				"  Incoming:\t%.2f kbits/s, %.2f packets/s\n",
				(float) (ts->total.proto_in.pc_bytes * 8 / 1000) /
				(float) (nsecs),
				(float) (ts->total.proto_in.pc_packets) / (float) (nsecs));
			fprintf(fd,
				"  Outgoing:\t%.2f kbits/s, %.2f packets/s\n",
				(float) (ts->total.proto_out.pc_bytes * 8 / 1000) /
				(float) (nsecs),
				(float) (ts->total.proto_out.pc_packets) / (float) (nsecs));
		} else {
			fprintf(fd, "%.2f kbytes/s, %.2f packets/s\n",
				((float) (ts->total.proto_total.pc_bytes / 1024) /
				 (float) nsecs),
				((float) (ts->total.proto_total.pc_packets) / (float) nsecs));
			fprintf(fd,
				"Incoming:\t%.2f kbytes/s, %.2f packets/s\n",
				(float) (ts->total.proto_in.pc_bytes / 1024) /
				(float) (nsecs),
				(float) (ts->total.proto_in.pc_packets) / (float) (nsecs));
			fprintf(fd,
				"Outgoing:\t%.2f kbytes/s, %.2f packets/s\n",
				(float) (ts->total.proto_out.pc_bytes / 1024) /
				(float) (nsecs),
				(float) (ts->total.proto_out.pc_packets) / (float) (nsecs));

		}
		fprintf(fd,
			"\nPeak total activity: %.2f %s, %.2f packets/s\n",
			peakactivity, dispmode(unit), peakpps);
		fprintf(fd, "Peak incoming rate: %.2f %s, %.2f packets/s\n",
			peakactivity_in, dispmode(unit), peakpps_in);
		fprintf(fd, "Peak outgoing rate: %.2f %s, %.2f packets/s\n\n",
			peakactivity_out, dispmode(unit), peakpps_out);
	}
	fprintf(fd, "IP checksum errors: %llu\n\n", ts->bad.pc_packets);
	fprintf(fd, "Running time: %lu seconds\n", nsecs);
	fflush(fd);
}

void writeutslog(struct portlistent *list, unsigned long nsecs, int units,
		 FILE * fd)
{
	char atime[TIME_TARGET_MAX];
	struct portlistent *ptmp = list;
	float inrate, outrate, totalrate;
	time_t now = time(NULL);

	genatime(time((time_t *) NULL), atime);

	fprintf(fd, "\n*** TCP/UDP traffic log, generated %s\n\n", atime);

	while (ptmp != NULL) {
		if (now - ptmp->proto_starttime < 5)
			inrate = outrate = totalrate = -1.0;
		else {
			if (units == KBITS) {
				inrate =
				    (float) (ptmp->ibcount * 8 / 1000) /
				    (float) (now - ptmp->proto_starttime);
				outrate =
				    (float) (ptmp->obcount * 8 / 1000) /
				    (float) (now - ptmp->proto_starttime);
				totalrate =
				    (float) (ptmp->bcount * 8 / 1000) /
				    (float) (now - ptmp->proto_starttime);
			} else {
				inrate =
				    (float) (ptmp->obcount / 1024) /
				    (float) (now - ptmp->proto_starttime);
				outrate =
				    (float) (ptmp->obcount / 1024) /
				    (float) (now - ptmp->proto_starttime);
				totalrate =
				    (float) (ptmp->obcount / 1024) /
				    (float) (now - ptmp->proto_starttime);
			}
		}

		if (ptmp->protocol == IPPROTO_TCP)
			fprintf(fd, "TCP/%s: ", ptmp->servname);
		else
			fprintf(fd, "UDP/%s: ", ptmp->servname);

		fprintf(fd, "%llu packets, %llu bytes total", ptmp->count,
			ptmp->bcount);

		if (totalrate >= 0.0)
			fprintf(fd, ", %.2f %s", totalrate, dispmode(units));

		fprintf(fd, "; %llu packets, %llu bytes incoming", ptmp->icount,
			ptmp->ibcount);

		if (inrate >= 0.0)
			fprintf(fd, ", %.2f %s", inrate, dispmode(units));

		fprintf(fd, "; %llu packets, %llu bytes outgoing", ptmp->ocount,
			ptmp->obcount);

		if (outrate >= 0.0)
			fprintf(fd, ", %.2f %s", outrate, dispmode(units));

		fprintf(fd, "\n\n");
		ptmp = ptmp->next_entry;
	}

	fprintf(fd, "\nRunning time: %lu seconds\n", nsecs);
	fflush(fd);
}

void writeethlog(struct ethtabent *list, int unit, unsigned long nsecs,
		 FILE * fd)
{
	char atime[TIME_TARGET_MAX];
	struct ethtabent *ptmp = list;

	genatime(time((time_t *) NULL), atime);

	fprintf(fd, "\n*** LAN traffic log, generated %s\n\n", atime);

	while (ptmp != NULL) {
		if (ptmp->type == 0) {
			if (ptmp->un.desc.linktype == ARPHRD_ETHER)
				fprintf(fd, "\nEthernet address: %s",
					ptmp->un.desc.ascaddr);
/* fix this
            else if (ptmp->un.desc.linktype == LINK_PLIP)
                fprintf(fd, "\nPLIP address: %s", ptmp->un.desc.ascaddr);
*/
			else if (ptmp->un.desc.linktype == ARPHRD_FDDI)
				fprintf(fd, "\nFDDI address: %s",
					ptmp->un.desc.ascaddr);

			if (ptmp->un.desc.withdesc)
				fprintf(fd, " (%s)", ptmp->un.desc.desc);

			fprintf(fd, "\n");
		} else {
			fprintf(fd,
				"\tIncoming total %llu packets, %llu bytes; %llu IP packets\n",
				ptmp->un.figs.inpcount, ptmp->un.figs.inbcount,
				ptmp->un.figs.inippcount);
			fprintf(fd,
				"\tOutgoing total %llu packets, %llu bytes; %llu IP packets\n",
				ptmp->un.figs.outpcount,
				ptmp->un.figs.outbcount,
				ptmp->un.figs.outippcount);

			fprintf(fd, "\tAverage rates: ");
			if (unit == KBITS)
				fprintf(fd,
					"%.2f kbits/s incoming, %.2f kbits/s outgoing\n",
					(float) (ptmp->un.figs.inbcount * 8 /
						 1000) / (float) nsecs,
					(float) (ptmp->un.figs.outbcount * 8 /
						 1000) / (float) nsecs);
			else
				fprintf(fd,
					"%.2f kbytes/s incoming, %.2f kbytes/s outgoing\n",
					(float) (ptmp->un.figs.inbcount /
						 1024) / (float) nsecs,
					(float) (ptmp->un.figs.outbcount /
						 1024) / (float) nsecs);

			if (nsecs > 5)
				fprintf(fd,
					"\tLast 5-second rates: %.2f %s incoming, %.2f %s outgoing\n",
					ptmp->un.figs.inrate, dispmode(unit),
					ptmp->un.figs.outrate, dispmode(unit));
		}

		ptmp = ptmp->next_entry;
	}

	fprintf(fd, "\nRunning time: %lu seconds\n", nsecs);
	fflush(fd);
}

void write_size_log(struct ifstat_brackets *brackets, unsigned long nsecs,
		    char *ifname, unsigned int mtu, FILE * logfile)
{
	char atime[TIME_TARGET_MAX];
	int i;

	genatime(time((time_t *) NULL), atime);
	fprintf(logfile, "*** Packet Size Distribution, generated %s\n\n",
		atime);
	fprintf(logfile, "Interface: %s   MTU: %u\n\n", ifname, mtu);
	fprintf(logfile, "Packet Size (bytes)\tCount\n");

	for (i = 0; i <= 19; i++) {
		fprintf(logfile, "%u to %u:\t\t%lu\n", brackets[i].floor,
			brackets[i].ceil, brackets[i].count);
	}
	fprintf(logfile, "\nRunning time: %lu seconds\n", nsecs);
	fflush(logfile);
}


void rotate_logfile(FILE ** fd, char *name)
{
	fclose(*fd);
	*fd = fopen(name, "a");
	rotate_flag = 0;
}


void announce_rotate_prepare(FILE * fd)
{
	writelog(1, fd,
		 "***** USR1 signal received, preparing to reopen log file *****");
}

void announce_rotate_complete(FILE * fd)
{
	writelog(1, fd, "***** Logfile reopened *****");
}

void check_rotate_flag(FILE ** logfile, int logging)
{
	if ((rotate_flag == 1) && (logging)) {
		announce_rotate_prepare(*logfile);
		rotate_logfile(logfile, target_logname);
		announce_rotate_complete(*logfile);
		rotate_flag = 0;
	}
}
