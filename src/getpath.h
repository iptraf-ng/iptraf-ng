#ifndef IPTRAF_NG_GETPATH_H
#define IPTRAF_NG_GETPATH_H

#define T_WORKDIR	1
#define T_LOGDIR	2
#define T_EXECDIR	3
#define T_LOCKDIR	4
#define T_SHAREDIR	5

char *get_path(int dirtype, char *file);

#endif	/* IPTRAF_NG_GETPATH_H */
