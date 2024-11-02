// go:build ignore
#include "packets.h"

SEC("tc")
int tc_sent_packet(struct __sk_buff *skb)
{
    // update the packet count
    update_pkt_map(SEND_PACKETS, 1);
    //update the packet size
    update_pkt_map(SEND_PACKETS_SIZE, skb->len);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";