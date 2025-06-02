#!/bin/bash
set -e

ACTION="$1"
CONFIG_FILE="${2:-config.yaml}"

case "$ACTION" in
    "show-config")
        PUBLIC_IP=$(yq '.public_ip' "$CONFIG_FILE" 2>/dev/null)
        PUBLIC_IP_HEX=$(python3 -c "import socket, struct; ip = '$PUBLIC_IP'; print('0x%08X' % struct.unpack('<I', socket.inet_aton(ip))[0]) if ip else print('0x00000000')")

        echo "=== XDP NAT Configuration ==="
        echo "Config File: $CONFIG_FILE"
        echo "Public IP: $PUBLIC_IP -> $PUBLIC_IP_HEX"
        echo "Interfaces:"

        count=$(yq '.interfaces | length' "$CONFIG_FILE" 2>/dev/null || echo 0)

        if [ "$count" -eq 0 ]; then
            echo "  No interfaces found in $CONFIG_FILE"
        else
            for ((i=0; i<count; i++)); do
                NIC=$(yq ".interfaces[$i].interface" "$CONFIG_FILE")
                SUBNET=$(yq ".interfaces[$i].internal.subnet // \"0.0.0.0\"" "$CONFIG_FILE")
                MASK=$(yq ".interfaces[$i].internal.mask // \"0.0.0.0\"" "$CONFIG_FILE")

                SUBNET_HEX=$(python3 -c "import socket, struct; print('0x%08X' % struct.unpack('<I', socket.inet_aton('$SUBNET'))[0])")
                MASK_HEX=$(python3 -c "import socket, struct; print('0x%08X' % struct.unpack('<I', socket.inet_aton('$MASK'))[0])")

                echo "  $i: $NIC - $SUBNET/$MASK ($SUBNET_HEX/$MASK_HEX)"
            done
        fi

        echo "============================="
        ;;

    "deploy")
        count=$(yq '.interfaces | length' "$CONFIG_FILE" 2>/dev/null || echo 0)

        if [ "$count" -eq 0 ]; then
            echo "Error: No interfaces found in $CONFIG_FILE"
            exit 1
        fi

        for ((i=0; i<count; i++)); do
            echo "Building and attaching interface $i..."
            make build-for-index INDEX=$i CONFIG_FILE="$CONFIG_FILE"
            make attach-for-index INDEX=$i CONFIG_FILE="$CONFIG_FILE"
        done

        echo "Deployment completed for $count interfaces"
        ;;

    "build")
        count=$(yq '.interfaces | length' "$CONFIG_FILE" 2>/dev/null || echo 0)

        if [ "$count" -eq 0 ]; then
            echo "Error: No interfaces found in $CONFIG_FILE"
            exit 1
        fi

        for ((i=0; i<count; i++)); do
            echo "Building for interface $i..."
            make build-for-index INDEX=$i CONFIG_FILE="$CONFIG_FILE"
        done

        echo "Build completed for $count interfaces"
        ;;

    "detach")
        echo "Detaching XDP programs from all interfaces..."

        count=$(yq '.interfaces | length' "$CONFIG_FILE" 2>/dev/null || echo 0)

        for ((i=0; i<count; i++)); do
            NIC=$(yq ".interfaces[$i].interface" "$CONFIG_FILE" 2>/dev/null || echo "")
            if [ -n "$NIC" ]; then
                echo "Detaching from $NIC"
                ip link set dev "$NIC" xdp off 2>/dev/null || true
            fi
        done

        echo "Detach completed"
        ;;

    "clean")
        echo "Detaching XDP programs from all interfaces..."

        count=$(yq '.interfaces | length' "$CONFIG_FILE" 2>/dev/null || echo 0)

        for ((i=0; i<count; i++)); do
            NIC=$(yq ".interfaces[$i].interface" "$CONFIG_FILE" 2>/dev/null || echo "")
            if [ -n "$NIC" ]; then
                echo "Detaching from $NIC"
                ip link set dev "$NIC" xdp off 2>/dev/null || true
            fi
        done

        echo "Cleaning build artifacts..."
        rm -f xdp-nat.bpf.o

        echo "Clean completed"
        ;;

    *)
        echo "Usage: $0 {show-config|deploy|build|detach|clean} CONFIG_FILE(config.yaml by default)"
        echo ""
        echo "Actions:"
        echo "  show-config  - Display current configuration"
        echo "  deploy       - Build and attach to all interfaces"
        echo "  build        - Build only (no attachment)"
        echo "  detach       - Detach from all interfaces"
        echo "  clean        - Detach and clean build artifacts"
        exit 1
        ;;
esac
