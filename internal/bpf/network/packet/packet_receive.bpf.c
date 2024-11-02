// go:build ignore
#include "packets.h"

SEC("xdp")
int xdp_recieved_packet(struct xdp_md* ctx)
{
    // update the packet count
    update_pkt_map(RECEIVED_PACKETS, 1);
    //calculate the packet size
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    int size = data_end - data;
    update_pkt_map(RECEIVED_PACKETS_SIZE, size);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";