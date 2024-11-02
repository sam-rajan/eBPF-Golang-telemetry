//go:build ignore
#include "packets.h"

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

    update_pkt_map(DROPPED_PACKETS, 1);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";