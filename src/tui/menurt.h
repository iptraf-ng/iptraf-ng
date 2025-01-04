#ifndef IPTRAF_NG_TUI_MENURT_H
#define IPTRAF_NG_TUI_MENURT_H

/***
   menu.h - declaration file for my menu library
***/

#define SELECTED 1
#define NOTSELECTED 0

#define SEPARATOR 0
#define REGULARITEM 1

#define OPTIONSTRLEN_MAX 50
#define DESCSTRLEN_MAX 81
#define SHORTCUTSTRLEN_MAX 25

struct ITEM {
	char option[OPTIONSTRLEN_MAX];
	char desc[DESCSTRLEN_MAX];
	unsigned int itemtype;
	struct ITEM *prev;
	struct ITEM *next;
};

struct MENU {
	struct ITEM *itemlist;
	struct ITEM *selecteditem;
	struct ITEM *lastitem;
	int itemcount;
	int postn;
	int x1, y1;
	int x2, y2;
	unsigned int menu_maxx;
	WINDOW *menuwin;
	PANEL *menupanel;
	WINDOW *descwin;
	PANEL *descpanel;
	int borderattr;
	int normalattr;
	int highattr;
	int barnormalattr;
	int barhighattr;
	int statusattr;
	char shortcuts[SHORTCUTSTRLEN_MAX];
};

void tx_initmenu(struct MENU *menu, int y1, int x1, int y2, int x2,
		 int borderattr, int normalattr, int highattr,
		 int barnormalattr, int barhighattr, int statusattr);
void tx_additem(struct MENU *menu, char *item, char *desc);
void tx_showitem(struct MENU *menu, struct ITEM *itemptr, int selected);
void tx_showmenu(struct MENU *menu);
void tx_operatemenu(struct MENU *menu, int *row, int *aborted);
void tx_destroymenu(struct MENU *menu);

#endif	/* IPTRAF_NG_TUI_MENURT_H */
