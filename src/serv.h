#ifndef IPTRAF_NG_SERV_H
#define IPTRAF_NG_SERV_H

/***

serv.h  - TCP/UDP port statistics header file
Written by Gerard Paul Java
Copyright (c) Gerard Paul Java 1997

***/

struct serv_spans {
	int spanbr_in;
	int spanbr_out;
	int spanbr;
};

struct portlistent {
	unsigned int port;
	unsigned int protocol;
	char servname[11];
	unsigned int idx;
	unsigned long long count;
	unsigned long long bcount;
	unsigned long long icount;
	unsigned long long ibcount;
	unsigned long long ocount;
	unsigned long long obcount;
	time_t starttime;
	time_t proto_starttime;
	struct serv_spans spans;
	struct portlistent *prev_entry;
	struct portlistent *next_entry;
};

struct portlist {
	struct portlistent *head;
	struct portlistent *tail;
	struct portlistent *firstvisible;
	struct portlistent *lastvisible;
	struct portlistent *barptr;
	int imaxy;
	unsigned int baridx;
	unsigned int count;
	unsigned long bcount;
	WINDOW *win;
	PANEL *panel;
	WINDOW *borderwin;
	PANEL *borderpanel;
};

struct porttab {
	unsigned int port_min;
	unsigned int port_max;
	struct porttab *prev_entry;
	struct porttab *next_entry;
};

void addmoreports(struct porttab **table);
void loadaddports(struct porttab **table);
void destroyporttab(struct porttab *table);
void removeaport(struct porttab **table);

#endif	/* IPTRAF_NG_SERV_H */
