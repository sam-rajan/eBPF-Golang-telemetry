//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pkt_count_map SEC(".maps");

SEC("xdp")
int xdp_prog() {
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&pkt_count_map, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";