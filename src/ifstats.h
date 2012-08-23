#ifndef IPTRAF_NG_IFSTATS_H
#define IPTRAF_NG_IFSTATS_H

#include "fltselect.h"

void selectiface(char *ifname, int withall, int *aborted);
void ifstats(struct filterstate *ofilter, time_t facilitytime);

#endif /* IPTRAF_NG_IFSTATS_H */
