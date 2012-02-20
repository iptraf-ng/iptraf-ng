#ifndef IPTRAF_NG_DESKMAN_H
#define IPTRAF_NG_DESKMAN_H

/*
   deskman.h - header file for deskman.c
   Written by Gerard Paul Java
   Copyright (c) Gerard Paul Java 1997, 1998

 */

void draw_desktop(void);
void printnomem(void);
void printipcerr(void);
void printkeyhelp(char *keytext, char *desc, WINDOW * win, int highattr,
		  int textattr);
void stdkeyhelp(WINDOW * win);
void sortkeyhelp(void);
void tabkeyhelp(WINDOW * win);
void scrollkeyhelp(void);
void stdexitkeyhelp(void);
void indicate(char *message);
void printlargenum(unsigned long long i, WINDOW * win);
void infobox(char *text, char *prompt);
void standardcolors(int color);
void show_sort_statwin(WINDOW **, PANEL **);

#endif	/* IPTRAF_NG_DESKMAN_H */
