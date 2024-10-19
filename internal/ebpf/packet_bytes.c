
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pkt_bytes_map SEC(".maps");

SEC("xdp")
int xdp_packet_bytes(struct xdp_md* ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    int size = data_end - data;
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&pkt_bytes_map, &key);
    if (value) {
        __sync_fetch_and_add(value, size);
    }
    return XDP_PASS;
}