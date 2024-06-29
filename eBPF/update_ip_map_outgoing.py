#!/usr/bin/env python3
from bcc import BPF

# Function to convert an IP and mask to a struct
def ip_mask_to_struct(ip, mask):
    parts_ip = ip.split('.')
    parts_mask = mask.split('.')
    ip_int = (int(parts_ip[0]) << 24) + (int(parts_ip[1]) << 16) + (int(parts_ip[2]) << 8) + int(parts_ip[3])
    mask_int = (int(parts_mask[0]) << 24) + (int(parts_mask[1]) << 16) + (int(parts_mask[2]) << 8) + int(parts_mask[3])
    return (ip_int, mask_int)

# Update outgoing IP map
bpf = BPF(src_file="tc_prog.c")
blocked_ips_outgoing = bpf.get_table("blocked_ips_outgoing")

# Example: block 192.168.2.0/24
ip, mask = ip_mask_to_struct("192.168.2.0", "255.255.255.0")
blocked_ips_outgoing[blocked_ips_outgoing.Key(ip, mask)] = blocked_ips_outgoing.Leaf(1)

print("Updated eBPF map for outgoing IP addresses")
