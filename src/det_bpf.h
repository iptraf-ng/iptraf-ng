#ifndef DET_BPF_H
#define DET_BPF_H

enum protocols {
	/* all */
	TOTAL,
	BROADCAST,

	/* L3 */
	IPV4,
	IPV6,
	NON_IP,

	/* L4 */
	ICMP,
	TCP,
	UDP,
	OTHER_IP,

	_MAX_PROTO,
};

struct trafdata {
	uint64_t packets;
	uint64_t bytes;
};

#endif
