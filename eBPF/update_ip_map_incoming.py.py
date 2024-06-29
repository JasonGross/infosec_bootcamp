#!/usr/bin/env python3
from bcc import BPF

# Function to convert an IP and mask to a struct
def ip_mask_to_struct(ip, mask):
    parts_ip = ip.split('.')
    parts_mask = mask.split('.')
    ip_int = (int(parts_ip[0]) << 24) + (int(parts_ip[1]) << 16) + (int(parts_ip[2]) << 8) + int(parts_ip[3])
    mask_int = (int(parts_mask[0]) << 24) + (int(parts_mask[1]) << 16) + (int(parts_mask[2]) << 8) + int(parts_mask[3])
    return (ip_int, mask_int)

# Update incoming IP map
bpf = BPF(src_file="xdp_prog.c")
blocked_ips = bpf.get_table("blocked_ips")

# Example: block 192.168.1.0/24
ip, mask = ip_mask_to_struct("192.168.1.0", "255.255.255.0")
blocked_ips[blocked_ips.Key(ip, mask)] = blocked_ips.Leaf(1)

print("Updated eBPF map for incoming IP addresses")
