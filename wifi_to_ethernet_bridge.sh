# Check if running as root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# Create a new bridge interface
BRIDGE_NAME="bridge1"
ifconfig $BRIDGE_NAME create

# Add the Wi-Fi interface to the bridge
ifconfig $BRIDGE_NAME addm en0

# Bring the bridge interface up
ifconfig $BRIDGE_NAME up

# Assign an IP address to the bridge interface
sudo ifconfig bridge1 192.168.200.1 netmask 255.255.255.0

echo "Bridge interface $BRIDGE_NAME created and configured"
echo "Wi-Fi interface en0 is now bridged to $BRIDGE_NAME"
echo "Bridge IP address: 192.168.200.1"