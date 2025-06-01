# XDP NAT Gateway for EC2
## Overview
This directory provides configurations and scripts to run XDP-based NAT gateway software in Amazon EC2 environments.

## Tested Environment
### EC2 Instance
- **Instance Type**: t4g.nano (Should work on any Nitro System instances with ENA support)
- **OS**: Amazon Linux 2023.7.20250512
- **Network Configuration**: VPC, Security Group, Network ACL, source/destination settings follow a [document](https://docs.aws.amazon.com/vpc/latest/userguide/work-with-nat-instances.html).
  - Note: iptables and `net.ipv4.ip_forward` configurations instructed in the document above are not required.

### Installed Software
- clang 20.1.0 [Releases - llvm/llvm-project](https://github.com/llvm/llvm-project/releases)
- `dnf install python3 jq bpftool git make`

## Installation (needs to be done as root)
### 1. Apply ENA-specific configurations
```bash
./ec2-ena-example/setup.sh <network_interface>
# Example: ./ec2-ena-example/setup.sh ens5
```
### 2. modify config.json
```
cp config.json.example config.json
vim config.json
```

### 3. Build and run
```bash
make # build and run
make clean # cleanup
```

### 4. Check XDP statistics (Optional)

You can monitor XDP statistics provided by the ENA driver:
```bash
ethtool -S <network_interface> | grep xdp
```

Expected output example:
```
     queue_0_rx_xdp_aborted: 0
     queue_0_rx_xdp_drop: 0
     queue_0_rx_xdp_pass: 7167
     queue_0_rx_xdp_tx: 643
     queue_0_rx_xdp_invalid: 0
     queue_0_rx_xdp_redirect: 0
     queue_1_xdp_tx_cnt: 643
     queue_1_xdp_tx_bytes: 125399
     queue_1_xdp_tx_queue_stop: 0
     queue_1_xdp_tx_queue_wakeup: 0
     queue_1_xdp_tx_dma_mapping_err: 0
     queue_1_xdp_tx_linearize: 0
     queue_1_xdp_tx_linearize_failed: 0
     queue_1_xdp_tx_napi_comp: 548
     queue_1_xdp_tx_tx_poll: 548
     queue_1_xdp_tx_doorbells: 538
     queue_1_xdp_tx_prepare_ctx_err: 0
     queue_1_xdp_tx_bad_req_id: 0
     queue_1_xdp_tx_llq_buffer_copy: 0
     queue_1_xdp_tx_missed_tx: 0
     queue_1_xdp_tx_unmask_interrupt: 547
     queue_1_xdp_tx_xsk_cnt: 0
     queue_1_xdp_tx_xsk_bytes: 0
     queue_1_xdp_tx_xsk_need_wakeup_: 0
     queue_1_xdp_tx_xsk_wakeup_reque: 0
```

