/* For terms of usage/redistribution/modification see the LICENSE file */
/* For authors and contributors see the AUTHORS file */

/***

promisc.c	- handles the promiscuous mode flag for the Ethernet/FDDI/
              Token Ring interfaces

***/

#include "iptraf-ng-compat.h"

#include "ifaces.h"
#include "error.h"
#include "promisc.h"

struct promisc_list {
	struct list_head list;
	int ifindex;
	char ifname[IFNAMSIZ];
};

static void promisc_add_dev(struct list_head *promisc, const char *dev_name)
{
	struct promisc_list *p = xmallocz(sizeof(*p));
	int ifindex = dev_get_ifindex(dev_name);
	if (ifindex < 0)
		return;

	p->ifindex = ifindex;
	strcpy(p->ifname, dev_name);

	list_add_tail(&p->list, promisc);
}

static bool promisc_dev_suitable(const char *dev_name)
{
	int flags = dev_get_flags(dev_name);
	if (flags < 0)
		return false;

	if ((flags & (IFF_UP | IFF_PROMISC)) == IFF_UP)
		return true;
	else
		return false;
}

void promisc_init(struct list_head *promisc, const char *device_name)
{
	if (device_name && promisc_dev_suitable(device_name)) {
		promisc_add_dev(promisc, device_name);
		return;
	}

	FILE *fp = open_procnetdev();
	if (!fp)
		die_errno("%s: open_procnetdev", __func__);

	char dev_name[IFNAMSIZ];
	while (get_next_iface(fp, dev_name, sizeof(dev_name))) {
		if (!strcmp(dev_name, ""))
			continue;

		if (promisc_dev_suitable(dev_name))
			promisc_add_dev(promisc, dev_name);
	}

	fclose(fp);
}

static int sock_change_promisc(int sock, int action, int ifindex)
{
	struct packet_mreq mreq;

	mreq.mr_ifindex = ifindex;
	mreq.mr_type = PACKET_MR_PROMISC;

	return setsockopt(sock, SOL_PACKET, action, &mreq, sizeof(mreq));
}

static int sock_enable_promisc(int sock, int ifindex)
{
	return sock_change_promisc(sock, PACKET_ADD_MEMBERSHIP, ifindex);
}

static int sock_disable_promisc(int sock, int ifindex)
{
	return sock_change_promisc(sock, PACKET_DROP_MEMBERSHIP, ifindex);
}

void promisc_set_list(int sock, struct list_head *promisc)
{
	struct promisc_list *entry = NULL;
	list_for_each_entry(entry, promisc, list) {
		int r = sock_enable_promisc(sock, entry->ifindex);
		if (r < 0)
			write_error("Failed to set promiscuous mode on %s", entry->ifname);
	}
}

void promisc_restore_list(int sock, struct list_head *promisc)
{
	struct promisc_list *entry = NULL;
	list_for_each_entry(entry, promisc, list) {
		int r = sock_disable_promisc(sock, entry->ifindex);
		if (r < 0)
			write_error("Failed to clear promiscuous mode on %s", entry->ifname);
	}
}

void promisc_destroy(struct list_head *promisc)
{
	struct promisc_list *entry, *tmp;
	list_for_each_entry_safe(entry, tmp, promisc, list) {
		list_del(&entry->list);
		free(entry);
	}
}
