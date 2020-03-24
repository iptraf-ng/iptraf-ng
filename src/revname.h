#ifndef IPTRAF_NG_REVNAME_H
#define IPTRAF_NG_REVNAME_H

/***

revname.h - public declarations related to reverse name resolution

***/

bool rvnamedactive(int fd);
void killrvnamed(int fd);
void close_rvn_socket(int fd);

int revname(int *lookup, struct sockaddr_storage *addr,
	    char *target, size_t target_size, int rvnfd);

#endif	/* IPTRAF_NG_REVNAME_H */
