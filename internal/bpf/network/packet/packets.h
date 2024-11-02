//go:build ignore

#ifndef __PACKETS_H
#define __PACKETS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

enum map_keys {
    RECEIVED_PACKETS = 0,
    RECEIVED_PACKETS_SIZE = 1,
    SEND_PACKETS = 2,
    SEND_PACKETS_SIZE = 3,
    DROPPED_PACKETS = 4,
};


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 5);
} pkt_maps SEC(".maps");


static __always_inline void update_pkt_map(__u32 key, __u64 val) {
    __u64 *value = bpf_map_lookup_elem(&pkt_maps, &key);
    if (value) {
        __sync_fetch_and_add(value, val);
    }
}
#endif