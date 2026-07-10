// D3 Step 1: per-source-IP 패킷/SYN 카운트 관측 (drop 없음, 항상 XDP_PASS)
//
// 관측 지점: ztg-gateway 컨테이너 netns 안 eth0 (Step 0 실험 결론 — host-side veth는 egress만 보임).
// TLS라 L7은 안 보이므로 XDP가 셀 수 있는 것만 센다: IPv4 소스 IP별 전체 패킷 수 + TCP SYN(신규 연결 시도) 수.
// SYN 레이트는 Step 2에서 PIP 레이트 신호(rate.l4)의 원료가 된다.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct ip_stats {
    __u64 pkts;
    __u64 syns;
};

// LRU: 소스 IP가 max_entries를 넘으면 오래된 항목부터 밀려남 — 관측용이라 유실 허용(fail-open이 아니라 카운트 손실일 뿐).
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);              // IPv4 saddr (network byte order)
    __type(value, struct ip_stats);
} src_ip_stats SEC(".maps");

SEC("xdp")
int rate_observe(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;                     // IPv4만 관측(도커 브리지에 VLAN 없음)

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u64 is_syn = 0;
    if (ip->protocol == IPPROTO_TCP && ip->ihl >= 5) {
        struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
        // syn && !ack = 신규 연결 시도(3-way 1단계). SYN-ACK 응답은 세지 않는다.
        if ((void *)(tcp + 1) <= data_end && tcp->syn && !tcp->ack)
            is_syn = 1;
    }

    __u32 saddr = ip->saddr;
    struct ip_stats *st = bpf_map_lookup_elem(&src_ip_stats, &saddr);
    if (st) {
        __sync_fetch_and_add(&st->pkts, 1);
        if (is_syn)
            __sync_fetch_and_add(&st->syns, 1);
    } else {
        struct ip_stats init = { .pkts = 1, .syns = is_syn };
        bpf_map_update_elem(&src_ip_stats, &saddr, &init, BPF_ANY);
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
