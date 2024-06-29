#!/usr/bin/env python3
from bcc import BPF
import pyroute2

# Define the BPF program
bpf = BPF(src_file="xdp_prog.c")

# Attach XDP program to the network interface
device = "eth0"  # Change this to your network interface
fn = bpf.load_func("xdp_prog", BPF.XDP, debug=4)
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