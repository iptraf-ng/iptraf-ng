#ifndef IPTRAF_NG_TUI_LABELS_H
#define IPTRAF_NG_TUI_LABELS_H

#include <curses.h>

void tx_printkeyhelp(char *keytext, char *desc, WINDOW * win, int highattr,
		     int textattr);
void tx_menukeyhelp(int textattr, int highattr);
void tx_listkeyhelp(int textattr, int highattr);
char *tx_ltrim(char *str);

#endif	/* IPTRAF_NG_TUI_LABELS_H */
