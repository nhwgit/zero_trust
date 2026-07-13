// D3 Step 3: 관측(rate_observe와 동일) + enforcement — deny map에 오른 소스 IP를 스택 진입 전 드랍.
//
// 판단→제어 체인: PIP가 신호 ack에 enforcement 지시(deny+TTL)를 실어 주면 에이전트가 이 map에
// {만료시각, 0}을 기록한다. 커널은 스스로 판단하지 않는다 — map에 적힌 결정을 집행만 한다.
//
// 가역성(fail-safe): 만료 판정을 커널이 직접 한다(bpf_ktime_get_ns 단조시계 비교).
// 에이전트가 죽어 엔트리를 못 지워도 TTL이 지나면 트래픽은 저절로 통과한다 —
// 오탐이 영구 차단이 되지 않게, 차단의 지속은 "살아 있는 판단 주체의 갱신"에만 의존시킨다.
// (만료 엔트리 삭제는 에이전트 몫 — 커널은 deny map에 drops 카운트 외엔 쓰지 않는다.)
//
// 관측은 차단 중에도 계속된다(stats 먼저, deny 판정 나중): 폭주가 지속되면 에이전트가 계속
// 신호를 쏘고 PIP hold/deny TTL이 연장된다 — 차단이 관측을 가리면 해제 판단 근거가 사라진다.
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

// 관측 map — rate_observe.c와 이름·배치 동일(에이전트 폴러 재사용).
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);              // IPv4 saddr (network byte order)
    __type(value, struct ip_stats);
} src_ip_stats SEC(".maps");

struct deny_entry {
    __u64 expires_at_ns;             // bpf_ktime_get_ns() 기준(CLOCK_MONOTONIC) 만료 시각
    __u64 drops;                     // 이 차단 구간에서 드랍한 패킷 수(집행 증거)
};

// 차단 목록 — 판단 주체(PIP→에이전트)가 명시적으로 넣은 IP만 담는다.
// LRU가 아닌 일반 HASH: 차단 결정이 조용히 밀려나면(evict) 집행이 구멍난다. 꽉 차면 새 등록이
// 실패할 뿐 기존 차단은 유지 — 집행 무결성이 수용량보다 우선(fail-close 방향).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);              // IPv4 saddr (network byte order)
    __type(value, struct deny_entry);
} deny_ips SEC(".maps");

SEC("xdp")
int rate_enforce(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u64 is_syn = 0;
    if (ip->protocol == IPPROTO_TCP && ip->ihl >= 5) {
        struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
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

    struct deny_entry *deny = bpf_map_lookup_elem(&deny_ips, &saddr);
    if (deny && bpf_ktime_get_ns() < deny->expires_at_ns) {
        __sync_fetch_and_add(&deny->drops, 1);
        return XDP_DROP;             // 커널 스택 진입 전 폐기 — L7은 이 패킷을 아예 못 본다
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
