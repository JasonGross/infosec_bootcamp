#!/usr/bin/env python3
from bcc import BPF
import pyroute2

# Define the BPF program
bpf = BPF(src_file="tc_prog.c")

# Attach TC program to the network interface
device = "eth0"  # Change this to your network interface
fn = bpf.load_func("tc_prog", BPF.SCHED_CLS)

# Attach the TC eBPF program
ipr = pyroute2.IPRoute()
ipr.tc("add", "clsact", device)
ipr.tc("add-filter", "bpf", device, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff2", action="drop", classid=1)

# Get reference to the ring buffer map
events_outgoing = bpf["events_outgoing"]

# Callback function to print filtered packets
def print_event_outgoing(cpu, data, size):
    event = bpf["events_outgoing"].event(data)
    ip = event.dst_ip
    print(f"Dropped outgoing packet to IP: {ip >> 24 & 0xFF}.{ip >> 16 & 0xFF}.{ip >> 8 & 0xFF}.{ip & 0xFF}")

# Open the ring buffer
events_outgoing.open_ring_buffer(print_event_outgoing)

print("Loaded TC eBPF program on interface {}".format(device))

try:
    # Poll the ring buffer
    while True:
        events_outgoing.ring_buffer_poll()
except KeyboardInterrupt:
    pass