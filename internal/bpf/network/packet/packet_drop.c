//go:build ignore


#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_count SEC(".maps");

SEC("tracepoint/skb/kfree_skb")
int count_packet_drops(void *ctx)
{
    // Read the entire 4-byte value
    unsigned int raw_reason;
    bpf_probe_read(&raw_reason, sizeof(raw_reason), (void *)ctx + 28);

    // Extract the correct reason value, handling both byte orders
    unsigned short reason;
    if (raw_reason > 0xFFFF) {
        // Case where bytes are 00 00 XX 00
        reason = (raw_reason >> 16) & 0xFF;
    } else {
        // Case where bytes are XX 00 00 00
        reason = raw_reason & 0xFF;
    }

    
    if (reason == 2) {
        // Not a packet drop, ignore
        return 0;
    }

    // Increment the drop count
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&drop_count, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";