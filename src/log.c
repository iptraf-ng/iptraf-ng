
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
#include "log.h"

#define MSGSTRING_MAX		240
#define TARGET_LOGNAME_MAX	160

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

void write_daemon_err(char *msg, va_list vararg)
{
	char atime[TIME_TARGET_MAX];
	FILE *fd;

	genatime(time((time_t *) NULL), atime);
	fd = fopen(DAEMONLOG, "a");
	fprintf(fd, "%s iptraf[%u]: ", atime, getpid());
	vfprintf(fd, msg, vararg);
	fprintf(fd, "\n");
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
