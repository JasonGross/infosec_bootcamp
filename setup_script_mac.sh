#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# Create a new network service
INTERFACE_NAME="VirtualNet"
networksetup -createnetworkservice $INTERFACE_NAME $(networksetup -listallhardwareports | awk '/Device: bridge0/{print $2}')

if [ $? -ne 0 ]; then
    echo "Failed to create virtual interface"
    exit 1
fi

echo "Created virtual interface: $INTERFACE_NAME"

# Assign an IP address to the virtual interface
networksetup -setmanual $INTERFACE_NAME 192.168.100.1 255.255.255.0

# Enable IP forwarding
sysctl -w net.inet.ip.forwarding=1

echo "Virtual network setup complete."
echo "Virtual interface: $INTERFACE_NAME"
echo "IP address: 192.168.100.1"