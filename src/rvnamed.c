/* For terms of usage/redistribution/modification see the LICENSE file */
/* For authors and contributors see the AUTHORS file */

/***

rvnamed		- reverse DNS lookup daemon for the IPTraf network
		  statistics utility.

Version 2.6.1                      Parallel with IPTraf 2.6

Written by Gerard Paul Java
Copyright (c) Gerard Paul Java 1998-2001

rvnamed is a daemon designed to do reverse DNS lookups, but return the
IP address immediately while the lookup goes on in the background.
A process requesting the lookup issues a request, and will immediately
get a reply with the IP address.  Meanwhile, rvnamed will fork and do
the lookup.  The requesting process simply needs to reissue the request
until a full domain name is returned.

This program is designed to be used by the IPTraf program to minimize
blocking and allow smoother keyboard control and packet counting when
reverse DNS lookups are enabled.

rvnamed and IPTraf communicate with each other using the BSD UNIX domain
socket protocol.

***/

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/un.h>
#include <time.h>
#include <netdb.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include "rvnamed.h"
#include "dirs.h"
#include "sockaddr.h"

#define NUM_CACHE_ENTRIES 2048
#define TIME_TARGET_MAX 30

#define __unused __attribute__((unused))

struct hosts {
	struct sockaddr_storage addr;
	char fqdn[45];
	int ready;
};

static int fork_count = 0;
static int max_fork_count = 0;

/*
 * This is the classic zombie-preventer
 */

static void childreap(int s __unused)
{
	signal(SIGCHLD, childreap);

	while (waitpid(-1, NULL, WNOHANG) > 0)
		fork_count--;
}

static void auto_terminate(int s __unused)
{
	exit(2);
}

/*
 * Process reverse DNS request from the client
 */

static void process_rvn_packet(struct rvn *rvnpacket)
{
	int ccfd;
	struct sockaddr_un ccsa;

	struct hostent *he;

	ccfd = socket(PF_UNIX, SOCK_DGRAM, 0);

	he = sockaddr_gethostbyaddr(&rvnpacket->addr);
	if (he == NULL) {
		sockaddr_ntop(&rvnpacket->addr, rvnpacket->fqdn,
			      sizeof(rvnpacket->fqdn));
	} else {
		memset(rvnpacket->fqdn, 0, sizeof(rvnpacket->fqdn));
		strncpy(rvnpacket->fqdn, he->h_name,
			sizeof(rvnpacket->fqdn) - 1);
	}

	ccsa.sun_family = AF_UNIX;
	strcpy(ccsa.sun_path, CHILDSOCKNAME);

	sendto(ccfd, rvnpacket, sizeof(struct rvn), 0,
	       (struct sockaddr *) &ccsa,
	       sizeof(ccsa.sun_family) + strlen(ccsa.sun_path));
	close(ccfd);
}

/*
 * Check if name is already resolved and in the cache.
 */

static int name_resolved(struct rvn *rvnpacket, struct hosts *hostlist,
			 unsigned int lastfree)
{
	for (unsigned int i = 0; i != lastfree; i++)
		if ((hostlist[i].ready == RESOLVED)
		    && sockaddr_is_equal(&rvnpacket->addr, &hostlist[i].addr))
			return i;

	return -1;
}

/*
 * Return the resolution status (NOTRESOLVED, RESOLVING, RESOLVED) of
 * the given IP address
 */

static int addrstat(struct rvn *rvnpacket, struct hosts *hostlist,
		    unsigned int lastfree)
{
	for (unsigned int i = 0; i != lastfree; i++)
		if (sockaddr_is_equal(&rvnpacket->addr, &hostlist[i].addr))
			return hostlist[i].ready;

	return NOTRESOLVED;
}

static void writervnlog(FILE * fd, char *msg)
{
	time_t now;
	char atime[TIME_TARGET_MAX] = "";

	now = time(NULL);

	strcpy(atime, ctime(&now));
	atime[strlen(atime) - 1] = '\0';

	fprintf(fd, "%s: %s\n", atime, msg);
}

int main(void)
{
	int cfd;
	int ifd;

	struct hosts hostlist[NUM_CACHE_ENTRIES];
	char logmsg[160];

	unsigned int hostindex = 0;
	unsigned int lastfree = 0;
	unsigned int hi = 0;
	int readyidx = 0;
	int fr = 0;
	int maxlogged = 0;

	struct rvn rvnpacket;

	int br;

	int ss = 0;

	fd_set sockset;

	struct sockaddr_un csa, isa;	/* child and iptraf comm sockets */
	struct sockaddr_un fromaddr;
	socklen_t fromlen;

	FILE *logfile;

	/* Daemonization Sequence */

	switch (fork()) {
	case -1:
		exit(1);
	case 0:
		break;
	default:
		exit(0);
	}

	setsid();
	int i = chdir("/");

	(void) i;

	signal(SIGCHLD, childreap);

	logfile = fopen(RVNDLOGFILE, "a");

	if (logfile == NULL)
		logfile = fopen("/dev/null", "a");

	writervnlog(logfile, "******** rvnamed started ********");
	writervnlog(logfile, "Clearing socket names");

	/*
	 * Get rid of any residue socket names in case of a previous
	 * abormal termination of rvnamed.
	 */

	unlink(CHILDSOCKNAME);
	unlink(IPTSOCKNAME);

	writervnlog(logfile, "Opening sockets");
	csa.sun_family = AF_UNIX;
	strcpy(csa.sun_path, CHILDSOCKNAME);

	isa.sun_family = AF_UNIX;
	strcpy(isa.sun_path, IPTSOCKNAME);

	cfd = socket(PF_UNIX, SOCK_DGRAM, 0);

	if (cfd < 0) {
		writervnlog(logfile,
			    "Unable to open child communication socket, aborting");
		exit(1);
	}
	if (bind
	    (cfd, (struct sockaddr *) &csa,
	     sizeof(csa.sun_family) + strlen(csa.sun_path)) < 0) {
		writervnlog(logfile,
			    "Error binding child communication socket, aborting");
		exit(1);
	}
	ifd = socket(PF_UNIX, SOCK_DGRAM, 0);

	if (ifd < 0) {
		writervnlog(logfile,
			    "Unable to open client communication socket, aborting");
		exit(1);
	}
	if (bind
	    (ifd, (struct sockaddr *) &isa,
	     sizeof(isa.sun_family) + strlen(isa.sun_path)) < 0) {
		writervnlog(logfile,
			    "Error binding client communication socket, aborting");
		exit(1);
	}
	while (1) {
		FD_ZERO(&sockset);
		FD_SET(cfd, &sockset);
		FD_SET(ifd, &sockset);

		do {
			ss = select(ifd + 1, &sockset, NULL, NULL, NULL);
		} while ((ss < 0) && (errno != ENOMEM));

		if (errno == ENOMEM) {
			writervnlog(logfile,
				    "Fatal error: no memory for descriptor monitoring");
			close(ifd);
			close(cfd);
			fclose(logfile);
			exit(1);
		}
		/*
		 * Code to process packets coming from the forked child.
		 */

		if (FD_ISSET(cfd, &sockset)) {
			fromlen =
			    sizeof(fromaddr.sun_family) +
			    strlen(fromaddr.sun_path);
			br = recvfrom(cfd, &rvnpacket, sizeof(struct rvn), 0,
				      (struct sockaddr *) &fromaddr, &fromlen);

			if (br > 0) {
				hi = 0;

				while (hi <= lastfree) {
					if (sockaddr_is_equal(&hostlist[hi].addr, &rvnpacket.addr))
						break;
					hi++;
				}

				if (hi == lastfree) {	/* Address not in cache */
					memset(&(hostlist[hi]), 0,
					       sizeof(struct hosts));
					hi = hostindex;
					hostindex++;
					if (hostindex == NUM_CACHE_ENTRIES)
						hostindex = 0;

					sockaddr_copy(&hostlist[hi].addr, &rvnpacket.addr);
				}
				memcpy(hostlist[hi].fqdn, rvnpacket.fqdn, sizeof(hostlist[hi].fqdn));

				hostlist[hi].ready = RESOLVED;
			}
		}
		/*
		 * This code section processes packets received from the IPTraf
		 * program.
		 */

		if (FD_ISSET(ifd, &sockset)) {
			fromlen = sizeof(struct sockaddr_un);
			br = recvfrom(ifd, &rvnpacket, sizeof(struct rvn), 0,
				      (struct sockaddr *) &fromaddr, &fromlen);
			if (br > 0) {
				switch (rvnpacket.type) {
				case RVN_HELLO:
					sendto(ifd, &rvnpacket,
					       sizeof(struct rvn), 0,
					       (struct sockaddr *)
					       &fromaddr,
					       sizeof(fromaddr.sun_family) +
					       strlen(fromaddr.sun_path));
					break;
				case RVN_QUIT:
					writervnlog(logfile,
						    "Received quit instruction");
					writervnlog(logfile, "Closing sockets");
					close(ifd);
					close(cfd);
					writervnlog(logfile,
						    "Clearing socket names");
					unlink(IPTSOCKNAME);
					unlink(CHILDSOCKNAME);
					sprintf(logmsg,
						"rvnamed terminating: max processes spawned: %d",
						max_fork_count);
					writervnlog(logfile, logmsg);
					writervnlog(logfile,
						    "******** rvnamed terminated ********");
					fclose(logfile);
					exit(0);
				case RVN_REQUEST:
					readyidx =
					    name_resolved(&rvnpacket, hostlist,
							  lastfree);
					if (readyidx >= 0) {
						rvnpacket.type = RVN_REPLY;
						memset(rvnpacket.fqdn, 0, sizeof(rvnpacket.fqdn));
						strncpy(rvnpacket.fqdn,
							hostlist[readyidx].fqdn,
							sizeof(rvnpacket.fqdn)-1);
						rvnpacket.ready = RESOLVED;

						br = sendto(ifd, &rvnpacket,
							    sizeof(struct rvn),
							    0,
							    (struct sockaddr *)
							    &fromaddr,
							    sizeof(fromaddr.
								   sun_family)
							    +
							    strlen(fromaddr.
								   sun_path));
					} else {

						/*
						 * Add this IP address to the cache if this is a
						 * new one.
						 */

						if (addrstat
						    (&rvnpacket, hostlist,
						     lastfree) == NOTRESOLVED) {
							fflush(logfile);	/* flush all data prior */
							/* to fork() */

							if (fork_count <=
							    MAX_RVNAMED_CHILDREN)
							{
								/*
								 * If we can still fork(), we add the data
								 * to the cache array, but we don't update
								 * the indexes until after the fork()
								 * succeeds.  If the fork() fails, we'll
								 * just reuse this slot for the next query.
								 *
								 * This is so that if the fork() fails due
								 * to a temporary condition, rvnamed won't
								 * think it's RESOLVING while there isn't
								 * any actual child doing the resolution
								 * before the entry expires.
								 *
								 * However, we'll still tell IPTraf that the
								 * address is RESOLVING.
								 *
								 */
								sockaddr_copy(&hostlist[hostindex].addr, &rvnpacket.addr);
								hostlist[hostindex].ready = RESOLVING;

								maxlogged = 0;
								fr = fork();
							} else {
								fr = -1;
								if (!maxlogged)
									writervnlog
									    (logfile,
									     "Maximum child process limit reached");
								maxlogged = 1;
							}

							switch (fr) {
							case 0:	/* spawned child */
								fclose(logfile);	/* no logging in child */
								close(ifd);	/* no comm with client */

								/*
								 * Set auto-terminate timeout
								 */
								signal(SIGALRM,
								       auto_terminate);
								alarm(300);
								process_rvn_packet
								    (&rvnpacket);
								exit(0);
							case -1:
								if (!maxlogged)
									writervnlog
									    (logfile,
									     "Error on fork, returning IP address");
								break;
							default:	/* parent */
								if (fork_count >
								    max_fork_count)
									max_fork_count
									    =
									    fork_count;

								/*
								 * Increase cache indexes only if fork()
								 * succeeded, otherwise the previously
								 * allocated slots will be used for the
								 * next query.
								 */

								hostindex++;

								if (hostindex ==
								    NUM_CACHE_ENTRIES)
									hostindex
									    = 0;

								if (lastfree <
								    NUM_CACHE_ENTRIES)
									lastfree++;

								fork_count++;
								break;
							}
						}
						rvnpacket.type = RVN_REPLY;
						sockaddr_ntop(&rvnpacket.addr, rvnpacket.fqdn, sizeof(rvnpacket.fqdn));
						rvnpacket.ready = RESOLVING;

						br = sendto(ifd, &rvnpacket,
							    sizeof(struct rvn),
							    0,
							    (struct sockaddr *)
							    &fromaddr,
							    sizeof(fromaddr.
								   sun_family)
							    +
							    strlen(fromaddr.
								   sun_path));

					}
				}
			}
		}		/* end block for packets from IPTraf */
	}
}
