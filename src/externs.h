#ifndef IPTRAF_NG_EXTERNS_H
#define IPTRAF_NG_EXTERNS_H

/***

externs.h - external routines used by the the iptraf module and some
others

***/

void servmon(char *iface, struct porttab *ports, const struct OPTIONS *options,
	     int facilitytime, struct filterstate *ofilter);
void hostmon(const struct OPTIONS *options, int facilitytime, char *ifptr,
	     struct filterstate *ofilter);

#endif	/* IPTRAF_NG_EXTERNS_H */
