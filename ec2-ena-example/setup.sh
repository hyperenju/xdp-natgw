#!/bin/bash -e

if [ $# -eq 0 ]; then
    echo "Usage: $0 <network_interface>"
    echo "Example: $0 ens5"
    exit 1
fi

NIC=$1

if ! ip link show "$NIC" &> /dev/null; then
    echo "Error: Network interface '$NIC' not found"
    exit 1
fi

# Set MTU to prevent XDP attachment failure
if ! ip link set dev "$NIC" mtu 3498; then
    echo "Error: Failed to set MTU"
    exit 1
fi

# Set combined queue number to half of maximum for performance optimization
QUEUE_NUM=$(ethtool -l "$NIC" | grep Combined | head -1 | awk '{print $2}')
NEW_QUEUE_NUM=$((QUEUE_NUM/2))

# Ensure at least 1 queue
if [ "$NEW_QUEUE_NUM" -lt 1 ]; then
    NEW_QUEUE_NUM=1
fi

if ! ethtool -L "$NIC" combined "$NEW_QUEUE_NUM"; then
    echo "Warning: Failed to set queue number, continuing..."
fi

echo "Successfully configured."
