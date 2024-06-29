#!/usr/bin/env python3
from bcc import BPF
import pyroute2

# Define the BPF program
bpf = BPF(text=r"""#include <linux/bpf.h>
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

# Attach XDP program to the network interface
device = "eth0"  # Change this to your network interface
fn = bpf.load_func("xdp_prog", BPF.XDP)
bpf.attach_xdp(device, fn, 0)

# Get reference to the ring buffer map
events = bpf["events"]

# Callback function to print filtered packets
def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    ip = event.src_ip
    print(f"Dropped incoming packet from IP: {ip >> 24 & 0xFF}.{ip >> 16 & 0xFF}.{ip >> 8 & 0xFF}.{ip & 0xFF}")

# Open the ring buffer
events.open_ring_buffer(print_event)

print("Loaded eBPF program on interface {}".format(device))

try:
    # Poll the ring buffer
    while True:
        events.ring_buffer_poll()
except KeyboardInterrupt:
    pass
finally:
    # Clean up and remove XDP program from interface
    bpf.remove_xdp(device, 0)
    print("Removed eBPF program from interface {}".format(device))