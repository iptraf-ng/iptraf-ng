/* For terms of usage/redistribution/modification see the LICENSE file */
/* For authors and contributors see the AUTHORS file */

/***

deskman.c - desktop management routines

***/

#include "iptraf-ng-compat.h"

#include "tui/labels.h"
#include "tui/msgboxes.h"
#include "tui/winops.h"

#include "deskman.h"
#include "options.h"
#include "timer.h"

/* Attribute variables */

int STDATTR;
int HIGHATTR;
int BOXATTR;
int ACTIVEATTR;
int BARSTDATTR;
int BARHIGHATTR;
int BARPTRATTR;
int DLGTEXTATTR;
int DLGBOXATTR;
int DLGHIGHATTR;
int STATUSBARATTR;
int KEYBARATTR;
int KEYHIGHATTR;
int IPSTATLABELATTR;
int IPSTATATTR;
int DESKTEXTATTR;
int PTRATTR;
int FIELDATTR;
int ERRBOXATTR;
int ERRTXTATTR;
int OSPFATTR;
int UDPATTR;
int IGPATTR;
int IGMPATTR;
int IGRPATTR;
int GREATTR;
int ARPATTR;
int UNKNIPATTR;
int UNKNATTR;
int IPV6ATTR;
int ICMPV6ATTR;

/*  draw the basic desktop common to my screen-oriented programs */

void draw_desktop(void)
{
	int row;		/* counter for desktop construction */

	scrollok(stdscr, 0);
	attrset(KEYBARATTR);
	move(0, 0);
	printw("%*c", COLS, ' ');	/* these two print the top n' bottom */
	move(LINES - 1, 0);
	printw("%*c", COLS, ' ');	/* lines */

	attrset(FIELDATTR);

	for (row = 1; row <= LINES - 2; row++) {	/* draw the background */
		move(row, 0);
		printw("%*c", COLS, ' ');
	}

	refresh();
}

void about(void)
{
	WINDOW *win;
	PANEL *panel;
	int ch;

	win = newwin(18, 62, (LINES - 17) / 2, (COLS - 62) / 2);

	panel = new_panel(win);

	tx_stdwinset(win);
	wtimeout(win, -1);
	wattrset(win, BOXATTR);
	tx_colorwin(win);
	tx_box(win, ACS_VLINE, ACS_HLINE);
	wattrset(win, STDATTR);
	mvwprintw(win, 1, 2, IPTRAF_NAME);
	mvwprintw(win, 2, 2, "An IP Network Statistics Utility");
	mvwprintw(win, 3, 2, "Version %s", IPTRAF_VERSION);
	mvwprintw(win, 5, 2, "Written by Gerard Paul Java");
	mvwprintw(win, 6, 2, "Copyright (c) Gerard Paul Java 1997-2004");
	mvwprintw(win, 8, 2, "This program is open-source software released");
	mvwprintw(win, 9, 2, "under the terms of the GNU General Public");
	mvwprintw(win, 10, 2, "License Version 2 or any later version.");
	mvwprintw(win, 11, 2, "See the included LICENSE file for details.");
	mvwprintw(win, 13, 2,
		  "IPv6 support by Markus Ullmann <mail@markus-ullmann.de>");
	mvwprintw(win, 14, 2,
		  "inspired by 2.7.0 diff by Guy Martin <gmsoft@tuxicoman.be>");

	wattrset(win, HIGHATTR);

	mvwprintw(win, 16, 2, ANYKEY_MSG);

	update_panels();
	doupdate();

	do {
		ch = wgetch(win);
		if (ch == 12)
			tx_refresh_screen();
	} while (ch == 12);

	del_panel(panel);
	delwin(win);
	update_panels();
	doupdate();
}

void show_sort_statwin(WINDOW ** statwin, PANEL ** panel)
{
	*statwin = newwin(5, 30, (LINES - 5) / 2, (COLS - 30) / 2);
	*panel = new_panel(*statwin);

	wattrset(*statwin, BOXATTR);
	tx_colorwin(*statwin);
	tx_box(*statwin, ACS_VLINE, ACS_HLINE);

	wattrset(*statwin, STDATTR);
	mvwprintw(*statwin, 2, 2, "Sorting, please wait...");
}

void printipcerr(void)
{
	attrset(ERRTXTATTR);
	mvprintw(0, 68, "  IPC Error ");
}

void stdkeyhelp(WINDOW * win)
{
	tx_printkeyhelp("Enter", "-accept  ", win, DLGHIGHATTR, DLGTEXTATTR);
	tx_printkeyhelp("Ctrl+X", "-cancel", win, DLGHIGHATTR, DLGTEXTATTR);
}

void sortkeyhelp(void)
{
	tx_printkeyhelp("S", "-sort  ", stdscr, KEYHIGHATTR, KEYBARATTR);
}

void stdexitkeyhelp(void)
{
	tx_printkeyhelp("X", "-exit", stdscr, KEYHIGHATTR, KEYBARATTR);
	tx_coloreol();
}

void scrollkeyhelp(void)
{
	tx_printkeyhelp("Up/Down/PgUp/PgDn", "-scroll window  ", stdscr,
			KEYHIGHATTR, KEYBARATTR);
}

void tabkeyhelp(WINDOW * win)
{
	tx_printkeyhelp("Tab", "-next field  ", win, DLGHIGHATTR, DLGTEXTATTR);
}

void indicate(char *message)
{
	attrset(KEYBARATTR);
	mvprintw(LINES - 1, 0, "%*c", COLS, ' ');
	mvprintw(LINES - 1, 1, "%s", message);
	refresh();
}

void printlargenum(unsigned long long i, WINDOW * win)
{
	if (i < 100000000)	/* less than 100 million */
		wprintw(win, "%9llu", i);
	else if (i < 1000000000)	/* less than 1 billion */
		wprintw(win, "%8lluk", i / 1000);
	else if (i < 1000000000000ULL)	/* less than 1 trillion */
		wprintw(win, "%8lluM", i / 1000000);
	else if (i < 1000000000000000ULL)	/* less than 1000 trillion */
		wprintw(win, "%8lluG", i / 1000000000ULL);
	else
		wprintw(win, "%8lluT", i / 1000000000000ULL);
}

void print_packet_drops(unsigned long count, WINDOW *win, int x)
{
	wattrset(win, BOXATTR);
	mvwprintw(win, getmaxy(win) - 1, x, " Drops: %9lu ", count);
}

static unsigned int get_screen_update_rate(void)
{
	if (options.updrate == 0)
		return DEFAULT_UPDATE_DELAY;
	else
		return options.updrate * 1000UL;
}

void set_next_screen_update(struct timespec *next_screen_update,
			    struct timespec *now)
{
	*next_screen_update = *now;
	time_add_msecs(next_screen_update, get_screen_update_rate());
}

void standardcolors(int color)
{
	if ((color) && (has_colors())) {
		init_pair(1, COLOR_BLUE, COLOR_WHITE);
		init_pair(2, COLOR_BLACK, COLOR_CYAN);
		init_pair(3, COLOR_CYAN, COLOR_BLUE);
		init_pair(4, COLOR_YELLOW, COLOR_RED);
		init_pair(5, COLOR_WHITE, COLOR_RED);
		init_pair(6, COLOR_BLUE, COLOR_CYAN);
		init_pair(7, COLOR_BLUE, COLOR_WHITE);
		init_pair(9, COLOR_RED, COLOR_WHITE);
		init_pair(10, COLOR_GREEN, COLOR_BLUE);
		init_pair(11, COLOR_CYAN, COLOR_BLACK);
		init_pair(12, COLOR_RED, COLOR_CYAN);
		init_pair(14, COLOR_YELLOW, COLOR_BLUE);
		init_pair(15, COLOR_YELLOW, COLOR_BLACK);
		init_pair(16, COLOR_WHITE, COLOR_CYAN);
		init_pair(17, COLOR_YELLOW, COLOR_CYAN);
		init_pair(18, COLOR_GREEN, COLOR_BLACK);
		init_pair(19, COLOR_WHITE, COLOR_BLUE);

		STDATTR = COLOR_PAIR(14) | A_BOLD;
		HIGHATTR = COLOR_PAIR(3) | A_BOLD;
		BOXATTR = COLOR_PAIR(3);
		ACTIVEATTR = COLOR_PAIR(10) | A_BOLD;
		BARSTDATTR = COLOR_PAIR(15) | A_BOLD;
		BARHIGHATTR = COLOR_PAIR(11) | A_BOLD;
		BARPTRATTR = COLOR_PAIR(18) | A_BOLD;
		STATUSBARATTR = COLOR_PAIR(2);
		DLGTEXTATTR = COLOR_PAIR(2);
		DLGBOXATTR = COLOR_PAIR(6);
		DLGHIGHATTR = COLOR_PAIR(12);
		KEYBARATTR = STDATTR;
		KEYHIGHATTR = HIGHATTR;
		IPSTATLABELATTR = COLOR_PAIR(2);
		IPSTATATTR = COLOR_PAIR(12);
		DESKTEXTATTR = COLOR_PAIR(7);
		PTRATTR = COLOR_PAIR(10) | A_BOLD;
		FIELDATTR = COLOR_PAIR(1);
		ERRBOXATTR = COLOR_PAIR(5) | A_BOLD;
		ERRTXTATTR = COLOR_PAIR(4) | A_BOLD;
		OSPFATTR = COLOR_PAIR(2);
		UDPATTR = COLOR_PAIR(9);
		IGPATTR = COLOR_PAIR(12);
		IGMPATTR = COLOR_PAIR(10) | A_BOLD;
		IGRPATTR = COLOR_PAIR(16) | A_BOLD;
		ARPATTR = COLOR_PAIR(5) | A_BOLD;
		GREATTR = COLOR_PAIR(1);
		UNKNIPATTR = COLOR_PAIR(19) | A_BOLD;
		ICMPV6ATTR = COLOR_PAIR(19) | A_BOLD;
		IPV6ATTR = COLOR_PAIR(19);
		UNKNATTR = COLOR_PAIR(4) | A_BOLD;
	} else {
		STDATTR = A_REVERSE;
		HIGHATTR = A_REVERSE;
		BOXATTR = A_REVERSE;
		ACTIVEATTR = A_BOLD;
		BARSTDATTR = A_NORMAL;
		BARHIGHATTR = A_BOLD;
		BARPTRATTR = A_NORMAL;
		STATUSBARATTR = A_BOLD;
		DLGBOXATTR = A_REVERSE;
		DLGTEXTATTR = A_REVERSE;
		DLGHIGHATTR = A_REVERSE | A_BOLD;
		KEYBARATTR = A_REVERSE;
		KEYHIGHATTR = A_REVERSE | A_BOLD;
		IPSTATLABELATTR = A_REVERSE;
		IPSTATATTR = A_STANDOUT;
		DESKTEXTATTR = A_NORMAL;
		PTRATTR = A_REVERSE;
		FIELDATTR = A_BOLD;
		ERRBOXATTR = A_BOLD;
		ERRTXTATTR = A_NORMAL;
		OSPFATTR = A_REVERSE;
		UDPATTR = A_BOLD;
		IGPATTR = A_REVERSE;
		IGMPATTR = A_REVERSE;
		IGRPATTR = A_REVERSE;
		ARPATTR = A_BOLD;
		GREATTR = A_BOLD;
		UNKNIPATTR = A_BOLD;
		ICMPV6ATTR = A_REVERSE;
		UNKNATTR = A_BOLD;
	}

	tx_init_error_attrs(ERRBOXATTR, ERRTXTATTR, ERRBOXATTR);
	tx_init_info_attrs(BOXATTR, STDATTR, HIGHATTR);
}
