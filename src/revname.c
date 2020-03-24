/* For terms of usage/redistribution/modification see the LICENSE file */
/* For authors and contributors see the AUTHORS file */

/***

revname.c - reverse DNS resolution module for IPTraf.  As of IPTraf 1.1,
this module now communicates with the rvnamed process to resolve in the
background while allowing the foreground process to continue with the
interim IP addresses in the meantime.

***/

#include "iptraf-ng-compat.h"

#include "deskman.h"
#include "getpath.h"
#include "revname.h"
#include "rvnamed.h"
#include "sockaddr.h"

bool rvnamedactive(int fd)
{
	fd_set sockset;
	struct rvn rpkt;
	int sstat;
	struct timeval tv;
	int br;

	rpkt.type = RVN_HELLO;

	send(fd, &rpkt, sizeof(struct rvn), 0);

	tv.tv_sec = 3;
	tv.tv_usec = 0;

	FD_ZERO(&sockset);
	FD_SET(fd, &sockset);

	do {
		sstat = select(fd + 1, &sockset, NULL, NULL, &tv);
	} while ((sstat < 0) && (errno != ENOMEM) && (errno == EINTR));

	if (sstat == 1) {
		do {
			br = recv(fd, &rpkt, sizeof(struct rvn), 0);
		} while ((br < 0) && (errno == EINTR));

		if (br < 0)
			printipcerr();
	}

	if (sstat == 0)
		return false;
	else
		return true;
}

/*
 * Terminate rvnamed process
 */

void killrvnamed(int fd)
{
	struct rvn rvnpkt;

	rvnpkt.type = RVN_QUIT;
	send(fd, &rvnpkt, sizeof(struct rvn), 0);
}

void close_rvn_socket(int fd)
{
	if (fd > 0)
		close(fd);
}

int revname(int *lookup, struct sockaddr_storage *addr,
	    char *target, size_t target_size, int rvnfd)
{
	struct rvn rpkt;
	int br;
	fd_set sockset;
	struct timeval tv;
	int sstat = 0;

	memset(target, 0, target_size);
	if (*lookup) {
		if (rvnfd > 0) {
			rpkt.type = RVN_REQUEST;
			sockaddr_copy(&rpkt.addr, addr);

			send(rvnfd, &rpkt, sizeof(struct rvn), 0);
			do {
				tv.tv_sec = 10;
				tv.tv_usec = 0;

				FD_ZERO(&sockset);
				FD_SET(rvnfd, &sockset);

				do {
					sstat =
					    select(rvnfd + 1, &sockset, NULL,
						   NULL, &tv);
				} while ((sstat < 0) && (errno == EINTR));

				if (FD_ISSET(rvnfd, &sockset))
					br = recv(rvnfd, &rpkt, sizeof(struct rvn), 0);
				else
					br = -1;
			} while ((br < 0) && (errno == EINTR));

			if (br < 0) {
				sockaddr_ntop(addr, target, target_size);
				printipcerr();
				*lookup = 0;
				return RESOLVED;
			}
			strncpy(target, rpkt.fqdn, target_size - 1);
			return (rpkt.ready);
		} else {
			sockaddr_gethostbyaddr(addr, target, target_size);
			return RESOLVED;
		}
	} else {
		sockaddr_ntop(addr, target, target_size);
		return RESOLVED;
	}
	return NOTRESOLVED;
}
