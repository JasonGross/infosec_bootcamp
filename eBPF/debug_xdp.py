from bcc import BPF

# Load the C program
b = BPF(text=r"""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

BPF_HASH(blocked_ips, __u32, __u32, 1); // Simplified to just store a single IP

int xdp_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)eth + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u32 *blocked = bpf_map_lookup_elem(&blocked_ips, &src_ip);

    if (blocked)
        return XDP_DROP;

    return XDP_PASS;
}""", debug=4)

try:
    fn = b.load_func("xdp_prog", BPF.XDP)
except Exception as e:
    print(f"Error loading BPF program: {e}")
    print(b.get_kprobe_functions(b"xdp"))
    print(b.get_uprobe_functions(b"xdp"))

# Rest of your code...