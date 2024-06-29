from scapy.all import Ether, IP, UDP, Raw, sendp, get_if_hwaddr
import sys

def send_test_packet(src_if, dst_if, src_ip, dst_ip, src_port, dst_port):
    # Create a test packet
    packet = (Ether(src=get_if_hwaddr(src_if), dst="ff:ff:ff:ff:ff:ff") /
              IP(src=src_ip, dst=dst_ip) /
              UDP(sport=src_port, dport=dst_port) /
              Raw(load="Test packet from virtual switch to internet bridge"))

    # Send the packet
    sendp(packet, iface=src_if, verbose=False)
    print(f"Sent test packet from {src_ip}:{src_port} ({src_if}) to {dst_ip}:{dst_port} ({dst_if})")

if __name__ == "__main__":
    src_if = "bridge0"
    dst_if = "bridge1"
    src_ip = "192.168.100.1"
    dst_ip = "192.168.200.1"
    src_port = 12345  # Example source port
    dst_port = 80     # Example destination port (HTTP)
    
    send_test_packet(src_if, dst_if, src_ip, dst_ip, src_port, dst_port)