#ifndef IPTRAF_NG_EXTERNS_H
#define IPTRAF_NG_EXTERNS_H

/***

externs.h - external routines used by the the iptraf module and some
others

***/

void hostmon(const struct OPTIONS *options, int facilitytime, char *ifptr,
	     struct filterstate *ofilter);

#endif	/* IPTRAF_NG_EXTERNS_H */
