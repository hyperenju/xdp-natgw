# xdp-natgw

Simple XDP-based NAT Gateway.

A lightweight symmetric NAT implementation using eBPF/XDP for packet processing in the Linux kernel.

## Features

- TCP, UDP and ICMP NAT translation
- YAML-based configuration
- LRU hash maps for session management
- Build-time configuration compilation

## Requirements

- Linux kernel with XDP support
- clang
- yq
- Root privileges

## Quick Start

1. Copy the example configuration for unified NIC for WAN/LAN:
   ```bash
   cp config-single.yaml config.yaml
   ```

   For separate NIC for WAN/LAN, use another:
   ```bash
   cp config-bridge.yaml config.yaml
   ```

2. Edit the configuration:
   ```bash
   vim config.yaml
   ```

3. Build and attach:
   ```bash
   make
   ```

### Get started in EC2 instance
See [ec2-ena-example/readme.md](ec2-ena-example/readme.md) for detailed instructions.

## Configuration

Edit `config.yaml` to match your network setup.

For unified NIC for WAN/LAN (e.g. in EC2 environemnt where final NAT is done by VPC):
```yaml
# Single - for unified NIC for WAN/LAN
public_ip: "100.100.100.162"  # WAN Address

interfaces:
  # WAN/LAN interface - handles inbound/outbound packets from clients
  - interface: "ens5"
    internal:
      subnet: "100.100.100.0"      # Internal network subnet
      mask: "255.255.255.0"
```

For separate NIC for WAN/LAN:
```yaml
# Bridge - for separate NIC for WAN/LAN
public_ip: "100.100.100.162"  # WAN Address

interfaces:
  # WAN interface - handles return packets from internet
  - interface: "ens5"

  # LAN interface - handles outbound packets from clients
  - interface: "ens6"
    internal:
      subnet: "10.0.0.0"      # Internal network subnet
      mask: "255.255.255.0"
```

## Usage

Build and attach to interface:
```bash
make
```

Build only:
```bash
make build
```

Show current configuration:
```bash
make show-config
```

Detach from interface:
```bash
make detach
```

Clean build artifacts:
```bash
make clean
```

View BPF trace output:
```bash
make trace
```
