/* For terms of usage/redistribution/modification see the LICENSE file */
/* For authors and contributors see the AUTHORS file */

/***

pktsize.c	- the packet size breakdown facility

***/

#include "iptraf-ng-compat.h"

#include "tui/winops.h"

#include "attrs.h"
#include "dirs.h"
#include "fltdefs.h"
#include "ifaces.h"
#include "packet.h"
#include "deskman.h"
#include "error.h"
#include "pktsize.h"
#include "options.h"
#include "timer.h"
#include "log.h"
#include "logvars.h"
#include "promisc.h"

struct ifstat_brackets {
	unsigned int floor;
	unsigned int ceil;
	unsigned long count;
};

struct psizetab {
	WINDOW *win;
	PANEL *panel;
	WINDOW *borderwin;
	PANEL *borderpanel;

	struct ifstat_brackets brackets[20];
	unsigned int interval;

	int mtu;
};

static void rotate_size_log(int s __unused)
{
	rotate_flag = 1;
	strcpy(target_logname, current_logfile);
	signal(SIGUSR1, rotate_size_log);
}

static void write_size_log(struct psizetab *table, unsigned long nsecs,
			   char *ifname, FILE *logfile)
{
	char atime[TIME_TARGET_MAX];
	int i;

	genatime(time(NULL), atime);
	fprintf(logfile, "*** Packet Size Distribution, generated %s\n\n",
		atime);
	fprintf(logfile, "Interface: %s   MTU: %u\n\n", ifname, table->mtu);
	fprintf(logfile, "Packet Size (bytes)\tCount\n");

	for (i = 0; i <= 19; i++) {
		fprintf(logfile, "%u to %u:\t\t%lu\n", table->brackets[i].floor,
			table->brackets[i].ceil, table->brackets[i].count);
	}
	fprintf(logfile, "\nRunning time: %lu seconds\n", nsecs);
	fflush(logfile);
}

static void psizetab_init(struct psizetab *table, char *ifname)
{
	table->borderwin = newwin(LINES - 2, COLS, 1, 0);
	table->borderpanel = new_panel(table->borderwin);

	wattrset(table->borderwin, BOXATTR);
	tx_box(table->borderwin, ACS_VLINE, ACS_HLINE);
	mvwprintw(table->borderwin, 0, 1, " Packet Distribution by Size ");

	table->win = newwin(LINES - 4, COLS - 2, 2, 1);
	table->panel = new_panel(table->win);

	tx_stdwinset(table->win);
	wtimeout(table->win, -1);
	wattrset(table->win, STDATTR);
	tx_colorwin(table->win);

	mvwprintw(table->win, 1, 1, "Packet size brackets for interface %s", ifname);
	wattrset(table->win, BOXATTR);
	mvwprintw(table->win, 4, 1, "Packet Size (bytes)");
	mvwprintw(table->win, 4, 26, "Count");
	mvwprintw(table->win, 4, 36, "Packet Size (bytes)");
	mvwprintw(table->win, 4, 60, "Count");
	wattrset(table->win, HIGHATTR);

	move(LINES - 1, 1);
	stdexitkeyhelp();

	update_panels();
	doupdate();
}

static void psizetab_destroy(struct psizetab *table)
{
	del_panel(table->panel);
	delwin(table->win);

	del_panel(table->borderpanel);
	delwin(table->borderwin);

	update_panels();
	doupdate();
}

static int initialize_brackets(struct psizetab *table)
{
	int i;

	table->interval = table->mtu / 20;	/* There are 20 packet size brackets */

	for (i = 0; i <= 19; i++) {
		table->brackets[i].floor = table->interval * i + 1;
		table->brackets[i].ceil = table->interval * (i + 1);
		table->brackets[i].count = 0;
	}

	table->brackets[19].ceil = table->mtu;

	for (i = 0; i <= 9; i++) {
		wattrset(table->win, STDATTR);
		mvwprintw(table->win, i + 5, 2, "%4u to %4u:", table->brackets[i].floor,
			table->brackets[i].ceil);
		wattrset(table->win, HIGHATTR);
		mvwprintw(table->win, i + 5, 23, "%8lu", 0);
	}

	for (i = 10; i <= 19; i++) {
		wattrset(table->win, STDATTR);
		wmove(table->win, (i - 10) + 5, 36);

		if (i != 19)
			wprintw(table->win, "%4u to %4u:", table->brackets[i].floor,
				table->brackets[i].ceil);
		else
			wprintw(table->win, "%4u to %4u+:", table->brackets[i].floor,
				table->brackets[i].ceil);

		wattrset(table->win, HIGHATTR);
		mvwprintw(table->win, (i - 10) + 5, 57, "%8lu", 0);
	}

	wattrset(table->win, STDATTR);
	mvwprintw(table->win, 17, 1,
		  "Interface MTU is %d bytes, not counting the data-link header",
		  table->mtu);
	mvwprintw(table->win, 18, 1,
		  "Maximum packet size is the MTU plus the data-link header length");
	mvwprintw(table->win, 19, 1,
		  "Packet size computations include data-link headers, if any");

	return 0;
}

static void update_size_distrib(struct psizetab *table, unsigned int length)
{
	unsigned int i;

	i = (length - 1) / table->interval;	/* minus 1 to keep interval
						   boundary lengths within the
						   proper brackets */

	if (i > 19)		/* This is for extras for MTU's not */
		i = 19;		/* divisible by 20 */

	table->brackets[i].count++;
}

static void print_size_distrib(struct psizetab *table)
{
	for (unsigned int i = 0; i <= 19; i++) {
		if (i < 10)
			wmove(table->win, i + 5, 23);
		else
			wmove(table->win, (i - 10) + 5, 57);

		wprintw(table->win, "%8lu", table->brackets[i].count);
	}
}

void packet_size_breakdown(char *ifname, time_t facilitytime)
{
	int ch;

	int pkt_result;

	int logging = options.logging;
	FILE *logfile = NULL;

	struct psizetab table;

	int fd;

	struct pkt_hdr pkt;

	unsigned long dropped = 0UL;

	if (!dev_up(ifname)) {
		err_iface_down();
		return;
	}

	psizetab_init(&table, ifname);

	LIST_HEAD(promisc);
	if (options.promisc) {
		promisc_init(&promisc, ifname);
		promisc_set_list(&promisc);
	}

	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(fd == -1) {
		write_error("Unable to obtain monitoring socket");
		goto err;
	}
	if(dev_bind_ifname(fd, ifname) == -1) {
		write_error("Unable to bind interface on the socket");
		goto err_close;
	}

	table.mtu = dev_get_mtu(ifname);
	if (table.mtu < 0) {
		write_error("Unable to obtain interface MTU");
		goto err_close;
	}

	initialize_brackets(&table);

	if (logging) {
		if (strcmp(current_logfile, "") == 0) {
			snprintf(current_logfile, 80, "%s-%s.log", PKTSIZELOG,
				 ifname);

			if (!daemonized)
				input_logfile(current_logfile, &logging);
		}
	}

	if (logging) {
		opentlog(&logfile, current_logfile);

		if (logfile == NULL)
			logging = 0;
	}
	if (logging) {
		signal(SIGUSR1, rotate_size_log);

		rotate_flag = 0;
		writelog(logging, logfile,
			 "******** Packet size distribution facility started ********");
	}

	packet_init(&pkt);

	exitloop = 0;

	struct timeval now;
	gettimeofday(&now, NULL);
	struct timeval last_time = now;
	struct timeval last_update = now;

	time_t starttime = now.tv_sec;
	time_t endtime = INT_MAX;
	if (facilitytime != 0)
		endtime = now.tv_sec + facilitytime * 60;

	time_t log_next = INT_MAX;
	if (logging)
		log_next = now.tv_sec + options.logspan;

	do {
		gettimeofday(&now, NULL);

		if (now.tv_sec > last_time.tv_sec) {
			printelapsedtime(now.tv_sec - starttime, 1, table.borderwin);

			dropped += packet_get_dropped(fd);
			print_packet_drops(dropped, table.borderwin, 49);

			if (logging && (now.tv_sec > log_next)) {
				check_rotate_flag(&logfile);
				write_size_log(&table, now.tv_sec - starttime,
					       ifname, logfile);
				log_next = now.tv_sec + options.logspan;
			}

			if (now.tv_sec > endtime)
				exitloop = 1;

			last_time = now;
		}

		if (screen_update_needed(&now, &last_update)) {
			print_size_distrib(&table);

			update_panels();
			doupdate();

			last_update = now;
		}

		if (packet_get(fd, &pkt, &ch, table.win) == -1) {
			write_error("Packet receive failed");
			exitloop = 1;
			break;
		}

		if (ch != ERR) {
			switch (ch) {
			case 12:
			case 'l':
			case 'L':
				tx_refresh_screen();
				break;
			case 'x':
			case 'X':
			case 'q':
			case 'Q':
			case 27:
			case 24:
				exitloop = 1;
			}
		}

		if (pkt.pkt_len <= 0)
			continue;

		pkt_result = packet_process(&pkt, NULL, NULL, NULL,
					    MATCH_OPPOSITE_USECONFIG, 0);

		if (pkt_result != PACKET_OK)
			continue;

		update_size_distrib(&table, pkt.pkt_len);
	} while (!exitloop);

	packet_destroy(&pkt);

	if (logging) {
		signal(SIGUSR1, SIG_DFL);
		write_size_log(&table, time(NULL) - starttime, ifname, logfile);
		writelog(logging, logfile,
			 "******** Packet size distribution facility stopped ********");
		fclose(logfile);
	}
	strcpy(current_logfile, "");

err_close:
	close(fd);
err:
	if (options.promisc) {
		promisc_restore_list(&promisc);
		promisc_destroy(&promisc);
	}

	psizetab_destroy(&table);
}
