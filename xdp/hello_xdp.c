// D3 Step 0 스파이크: 패킷 카운트만 하는 hello-XDP (drop 없음, XDP_PASS)
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} pkt_count SEC(".maps");

SEC("xdp")
int hello_xdp(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&pkt_count, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
