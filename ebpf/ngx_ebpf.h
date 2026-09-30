
/*
 * Types and limits shared by the nginx eBPF loader (ngx_ebpf_module.c) and
 * its BPF programs (bpf/ngx_ebpf.bpf.c).  The map layouts are a private
 * contract: both sides must be built from the same revision.
 */


#ifndef _NGX_EBPF_H_INCLUDED_
#define _NGX_EBPF_H_INCLUDED_


#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif


#define SYNACK_VERSION          1
#define SYNACK_MAX_HEADERS      256
#define SYNACK_MAX_ALIASES      2       /* wire and socket tuples */
#define SYNACK_CONNECTIONS      65536
#define SYNACK_EXPECTATIONS     (SYNACK_MAX_ALIASES * SYNACK_CONNECTIONS)

#define SYNACK_NSEC_PER_SEC     1000000000ULL
#define SYNACK_PENDING_NS       (120 * SYNACK_NSEC_PER_SEC)
#define SYNACK_CAPTURE_NS       (10 * SYNACK_NSEC_PER_SEC)


/*
 * The family is native-endian; addresses, ports and the ACK are in network
 * order.  IPv4 uses the first four address bytes.  All remaining bytes,
 * including pad, are zero, so keys compare as plain memory.
 */

struct synack_key {
    __u16                   family;
    __u8                    protocol;
    __u8                    pad;
    __u8                    src[16];
    __u8                    dst[16];
    __be16                  sport;
    __be16                  dport;
    __be32                  ack;
};


enum synack_phase {
    SYNACK_PENDING = 0,
    SYNACK_CLAIMED,
    SYNACK_COMPLETE
};


struct synack_connection {
    __u64                   deadline;
    __u32                   phase;
    __u32                   count;
    struct synack_key       keys[SYNACK_MAX_ALIASES];
};


struct synack_expectation {
    __u64                   cookie;
    __u64                   deadline;
    __u32                   ambiguous;
    __u32                   pad;
};


struct synack_record {
    __u32                   version;
    __u32                   length;
    __u64                   timestamp;
    __u8                    headers[SYNACK_MAX_HEADERS];
};


/*
 * Indexes into the synack_stats array; the tests read them by number, so new
 * counters are appended.  The maps are LRU: an insert evicts instead of
 * failing, so the *_FULL counters only count lost insert races.
 */

enum synack_stat {
    SYNACK_STAT_EXPECT_FULL = 0,
    SYNACK_STAT_ALIAS_FULL,
    SYNACK_STAT_COLLISION,
    SYNACK_STAT_CAPTURE_FULL,
    SYNACK_STAT_CAPTURED,
    SYNACK_STAT_EXPIRED,
    SYNACK_STAT_REGISTER_FAILED,
    SYNACK_STAT_ALLOC_FAILED,
    SYNACK_STAT_HANDOFF_ERROR,
    SYNACK_STAT_INVALID_RECORD,
    SYNACK_STAT_EVICTED,                /* registration or capture evicted */
    SYNACK_STAT_MISSED,                 /* registered, but nothing captured */
    SYNACK_STAT_COUNT
};


#endif /* _NGX_EBPF_H_INCLUDED_ */
