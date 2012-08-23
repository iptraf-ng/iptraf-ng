#ifndef IPTRAF_NG_PKTSIZE_H
#define IPTRAF_NG_PKTSIZE_H

#include "fltselect.h"

void packet_size_breakdown(char *iface, time_t facilitytime,
			   struct filterstate *ofilter);

#endif	/* IPTRAF_NG_PKTSIZE_H */
