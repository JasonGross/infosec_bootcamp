#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/types.h>
#include <linux/if_ether.h>

struct ip_range
{
    __u32 ip;
    __u32 mask;
};

SEC("maps")
BPF_HASH(blocked_ips, struct ip_range, __u32, 128);
// struct bpf_map_def blocked_ips = {
//     .type = BPF_MAP_TYPE_HASH,
//     .key_size = sizeof(struct ip_range),
//     .value_size = sizeof(__u32),
//     .max_entries = 128,
// };

struct event
{
    __u32 src_ip;
};

SEC("maps")
BPF_RINGBUF_OUTPUT(events, 4096);
// struct bpf_map_def events = {
//     .type = BPF_MAP_TYPE_RINGBUF,
//     .max_entries = 4096,
// };

static __always_inline int ip_in_range(__u32 ip, struct ip_range *range)
{
    return (ip & range->mask) == (range->ip & range->mask);
}

SEC("xdp_prog")
int xdp_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct ip_range range;
    __u32 *blocked;

    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    for (int i = 0; i < 128; i++)
    {
        if (bpf_map_lookup_elem(&blocked_ips, &range) && ip_in_range(ip->saddr, &range))
        {
            struct event *e;
            e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
            if (e)
            {
                e->src_ip = ip->saddr;
                bpf_ringbuf_submit(e, 0);
            }
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";