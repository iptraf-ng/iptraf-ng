/* For terms of usage/redistribution/modification see the LICENSE file */
/* For authors and contributors see the AUTHORS file */

#include "iptraf-ng-compat.h"

#include "options.h"
#include "promisc.h"
#include "error.h"
#include "ifaces.h"
#include "packet.h"
#include "capt.h"
#include "capt-recvmsg.h"
#include "capt-recvmmsg.h"
#include "capt-mmap-v2.h"
#include "capt-mmap-v3.h"

static int capt_set_recv_timeout(int fd, unsigned int msec)
{
	struct timeval timeout;
	socklen_t len = sizeof(timeout);

	timeout.tv_sec = msec / 1000;
	timeout.tv_usec = (msec % 1000) * 1000;
	if(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, len) != 0)
		return -1;
	else
		return 0;
}

static int capt_setup_receive_function(struct capt *capt)
{
	/* try packet mmap() TPACKET_V3 */
	if (capt_setup_mmap_v3(capt) == 0)
		return 0;

	/* try packet mmap() TPACKET_V2 */
	if (capt_setup_mmap_v2(capt) == 0)
		return 0;

	/* try packet recvmmsg() */
	if (capt_setup_recvmmsg(capt) == 0)
		return 0;

	/* try packet recvmsg() */
	if (capt_setup_recvmsg(capt) == 0)
		return 0;

	return -1;
}

int capt_init(struct capt *capt, char *ifname)
{
	capt->have_packet = NULL;
	capt->get_packet = NULL;
	capt->put_packet = NULL;
	capt->cleanup = NULL;

	capt->dropped = 0UL;

	INIT_LIST_HEAD(&capt->promisc);

	/* initialize socket first with some default protocol;
	 * the right protocol is then set with bind();
	 * this overcomes the problem with getting packets
	 * from other interfaces, because the socket was not
	 * properly initialized yet */
	int fd = socket(PF_PACKET, SOCK_RAW, 0);
	if (fd == -1)
		return fd;
	capt->fd = fd;

	/* set socket receive timeout */
	if (capt_set_recv_timeout(capt->fd, 250) == -1)
		goto out;

	/* try all available receive functions */
	if (capt_setup_receive_function(capt) == -1)
		goto out;

	if (options.promisc) {
		promisc_init(&capt->promisc, ifname);
		promisc_set_list(capt->fd, &capt->promisc);
	}

	/* bind interface (and protocol) to socket
	 * (interface can be NULL -> any interface) */
	if (dev_bind_ifname(capt->fd, ifname) == -1)
		goto out;

	return 0;	/* all O.K. */

out:
	close(capt->fd);
	capt->fd = -1;

	return -1;
}

void capt_destroy(struct capt *capt)
{
	promisc_disable(capt->fd, &capt->promisc);

	if (capt->cleanup)
		capt->cleanup(capt);

	close(capt->fd);
	capt->fd = -1;
}

unsigned long capt_get_dropped(struct capt *capt)
{
	struct tpacket_stats stats;
	socklen_t len = sizeof(stats);

	memset(&stats, 0, len);
	int err = getsockopt(capt->fd, SOL_PACKET, PACKET_STATISTICS, &stats, &len);
	if (err < 0)
		die_errno("%s(): getsockopt(PACKET_STATISTICS)", __func__);

	capt->dropped += stats.tp_drops;

	return capt->dropped;
}

static bool time_after(struct timeval const *a, struct timeval const *b)
{
	if (a->tv_sec > b->tv_sec)
		return true;
	if (a->tv_sec < b->tv_sec)
		return false;
	if(a->tv_usec > b->tv_usec)
		return true;
	else
		return false;
}

static void time_add_msecs(struct timeval *time, unsigned int msecs)
{
	if (time != NULL) {
		while (msecs >= 1000) {
			time->tv_sec++;
			msecs -= 1000;
		}
		time->tv_usec += msecs * 1000;
		while (time->tv_usec >= 1000000) {
			time->tv_sec++;
			time->tv_usec -= 1000000;
		}
	}
}

int capt_get_packet(struct capt *capt, struct pkt_hdr *pkt, int *ch, WINDOW *win)
{
	struct pollfd pfds[2];
	nfds_t nfds = 0;
	int pfd_packet = -1;
	int pfd_key = -1;
	int ss = 0;
	int have_packet = capt->have_packet(capt);
	int timeout = DEFAULT_UPDATE_DELAY;
	static struct timeval next_kbd_check = { 0 };

	/* no packet ready, so poll() for it */
	if (!have_packet) {
		pfds[nfds].fd = capt->fd;
		pfds[nfds].events = POLLIN;
		pfd_packet = nfds;
		nfds++;
	}

	/* check for key press */
	/* Monitor stdin only if in interactive, not daemon mode. */
	if (ch && !daemonized) {
		struct timeval now;

		gettimeofday(&now, NULL);
		if (time_after(&now, &next_kbd_check)) {
			pfds[nfds].fd = 0;
			pfds[nfds].events = POLLIN;
			pfd_key = nfds;
			nfds++;
			if (have_packet)
				timeout = 0;

			next_kbd_check = now;
			time_add_msecs(&next_kbd_check, 20);
		}
	}

	if (nfds > 0)
		do {
			ss = poll(pfds, nfds, timeout);
		} while ((ss == -1) && (errno == EINTR));

	/* no packet ready yet */
	pkt->pkt_len = 0;

	if ((pfd_packet != -1) && (ss > 0)) {
		if (pfds[pfd_packet].revents & POLLERR) {
			/* some error occured, don't try to get packet */
			have_packet = false;
			/* ... and return error */
			ss = -1;
		} else if (pfds[pfd_packet].revents & POLLIN) {
			/* packet ready */
			have_packet = true;
		}
	}
	if (have_packet) {
		int ret = capt->get_packet(capt, pkt);
		if (ret <= 0)
			ss = ret;
	}

	if (ch) {
		*ch = ERR;	/* signalize we have no key ready */
		if (!daemonized && (((pfd_key != -1) && ((ss > 0) && ((pfds[pfd_key].revents & POLLIN) != 0)))))
			*ch = wgetch(win);
	}

	return ss;
}

int capt_put_packet(struct capt *capt, struct pkt_hdr *pkt)
{
	if (capt->put_packet)
		capt->put_packet(capt, pkt);

	return 0;
}
