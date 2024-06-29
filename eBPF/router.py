import socket
import struct
import os
import sys
import select

# Define virtual network interfaces and routing table
INTERFACES = ["dummy0", "dummy1", "dummy2"]
ROUTING_TABLE = {
	"192.168.1.3": "dummy1",
	"192.168.1.4": "dummy2"
}

# Create raw socket to send and receive packets
def create_socket(interface):
	try:
    	s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    	s.bind((interface, 0))
    	return s
	except socket.error as e:
    	print(f"Error creating socket on interface {interface}: {e}")
    	sys.exit(1)

# Function to parse incoming IP packets
def parse_packet(packet):
	eth_header = packet[:14]
	ip_header = packet[14:34]
	data = packet[34:]

	# Unpack the IP header
	iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

	version_ihl = iph[0]
	version = version_ihl >> 4
	ihl = version_ihl & 0xF

	iph_length = ihl * 4

	src_ip = socket.inet_ntoa(iph[8])
	dst_ip = socket.inet_ntoa(iph[9])

	return src_ip, dst_ip, packet

# Function to modify the IP packet (decrement TTL and recalculate checksum)
def modify_packet(packet):
	eth_header = packet[:14]
	ip_header = packet[14:34]
	data = packet[34:]

	iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
	ttl = iph[5] - 1

	if ttl <= 0:
    	return None  # Packet should be dropped

	checksum = 0
	iph = iph[:5] + (ttl,) + iph[6:7] + (checksum,) + iph[8:]

	ip_header = struct.pack('!BBHHHBBH4s4s', *iph)
	packet = eth_header + ip_header + data

	return packet

# Function to forward IP packets between interfaces
def forward_packet(src_socket, sockets):
	while True:
    	rlist, _, _ = select.select([src_socket], [], [], 1)  # 1-second timeout
    	if rlist:
        	packet = src_socket.recv(4096)
        	src_ip, dst_ip, packet = parse_packet(packet)
        	modified_packet = modify_packet(packet)
        	if modified_packet:
            	dst_interface = ROUTING_TABLE.get(dst_ip)
            	if dst_interface:
                	dst_socket = sockets[dst_interface]
                	dst_socket.send(modified_packet)

# Create sockets for all interfaces
sockets = {interface: create_socket(interface) for interface in INTERFACES}

# Main packet forwarding loop
try:
	while True:
    	for src_socket in sockets.values():
        	forward_packet(src_socket, sockets)
except KeyboardInterrupt:
	print("\nTerminating...")
finally:
	for s in sockets.values():
    	s.close()