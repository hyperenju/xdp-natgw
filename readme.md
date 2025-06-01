# xdp-natgw

Simple XDP-based NAT Gateway.

A lightweight symmetric NAT implementation using eBPF/XDP for packet processing in the Linux kernel.

## Features

- TCP, UDP and ICMP NAT translation
- JSON-based configuration
- LRU hash maps for session management
- Build-time configuration compilation

## Requirements

- Linux kernel with XDP support
- clang
- jq
- Root privileges

## Quick Start

1. Copy the example configuration:
   ```bash
   cp config.json.example config.json
   ```

2. Edit the configuration:
   ```bash
   vim config.json
   ```

3. Build and attach:
   ```bash
   make
   ```

### Get started in EC2 instance
See [ec2-ena-example/readme.md](ec2-ena-example/readme.md) for detailed instructions.

## Configuration

Edit `config.json` to match your network setup:

```json
{
  "interface": "ens5",
  "internal": {
    "subnet": "100.100.100.176",
    "mask": "255.255.255.252"
  },
  "public_ip": "100.100.100.150"
}
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
