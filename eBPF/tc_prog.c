#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>

struct ip_range
{
    __u32 ip;
    __u32 mask;
};

struct bpf_map_def SEC("maps") blocked_ips_outgoing = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct ip_range),
    .value_size = sizeof(__u32),
    .max_entries = 128,
};

struct event
{
    __u32 dst_ip;
};

struct bpf_map_def SEC("maps") events_outgoing = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 4096,
};

static __always_inline int ip_in_range(__u32 ip, struct ip_range *range)
{
    return (ip & range->mask) == (range->ip & range->mask);
}

SEC("tc_prog")
int tc_prog(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct ip_range range;
    __u32 *blocked;

    if ((void *)eth + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return TC_ACT_OK;

    for (int i = 0; i < 128; i++)
    {
        if (bpf_map_lookup_elem(&blocked_ips_outgoing, &range) && ip_in_range(ip->daddr, &range))
        {
            struct event *e;
            e = bpf_ringbuf_reserve(&events_outgoing, sizeof(*e), 0);
            if (e)
            {
                e->dst_ip = ip->daddr;
                bpf_ringbuf_submit(e, 0);
            }
            return TC_ACT_SHOT;
        }
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";