//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} drop_count SEC(".maps");

SEC("tracepoint/skb/kfree_skb")
int count_packet_drops(struct trace_event_raw_kfree_skb *ctx)
{
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&drop_count, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";