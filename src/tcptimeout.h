#ifndef IPTRAF_NG_TCPTIMEOUT_H
#define IPTRAF_NG_TCPTIMEOUT_H

void write_timeout_log(int logging, FILE * logfile, struct tcptableent *tcpnode,
		       struct OPTIONS *opts);

#endif	/* IPTRAF_NG_TCPTIMEOUT_H */
