TARGET = xdp-nat.bpf
SOURCE = $(TARGET).c
OBJECT = $(TARGET).o

CONFIG_FILE ?= config.json

DEFAULT_NIC = eth0
DEFAULT_INTERNAL_SUBNET = 192.168.1.0
DEFAULT_INTERNAL_MASK = 255.255.255.0
DEFAULT_PUBLIC_IP = 192.168.1.1

get_interface = $(shell jq -r '.interface // "$(DEFAULT_NIC)"' $(CONFIG_FILE) 2>/dev/null || echo $(DEFAULT_NIC))
get_internal_subnet = $(shell jq -r '.internal.subnet // "$(DEFAULT_INTERNAL_SUBNET)"' $(CONFIG_FILE) 2>/dev/null || echo $(DEFAULT_INTERNAL_SUBNET))
get_internal_mask = $(shell jq -r '.internal.mask // "$(DEFAULT_INTERNAL_MASK)"' $(CONFIG_FILE) 2>/dev/null || echo $(DEFAULT_INTERNAL_MASK))
get_public_ip = $(shell jq -r '.public_ip // "$(DEFAULT_PUBLIC_IP)"' $(CONFIG_FILE) 2>/dev/null || echo $(DEFAULT_PUBLIC_IP))

NIC := $(get_interface)
INTERNAL_SUBNET := $(get_internal_subnet)
INTERNAL_MASK := $(get_internal_mask)
PUBLIC_IP := $(get_public_ip)

define ip_to_hex
$(shell python3 -c "import socket, struct; ip = '$(1)'; print('0x%08X' % struct.unpack('<I', socket.inet_aton(ip))[0]) if ip else print('0x00000000')")
endef

INTERNAL_SUBNET_HEX := $(if $(INTERNAL_SUBNET),$(call ip_to_hex,$(INTERNAL_SUBNET)),0x00000000)
INTERNAL_MASK_HEX := $(if $(INTERNAL_MASK),$(call ip_to_hex,$(INTERNAL_MASK)),0x00000000)
PUBLIC_IP_HEX := $(if $(PUBLIC_IP),$(call ip_to_hex,$(PUBLIC_IP)),0x00000000)

CFLAGS = -g -O2 -target bpf
DEFINES = -DINTERNAL_SUBNET=$(INTERNAL_SUBNET_HEX) \
          -DINTERNAL_MASK=$(INTERNAL_MASK_HEX) \
          -DPUBLIC_IP=$(PUBLIC_IP_HEX)

all: $(OBJECT) attach

build: $(OBJECT)

show-config:
	@echo "=== XDP NAT Configuration ==="
	@echo "Config File: $(CONFIG_FILE)"
	@echo "Interface: $(NIC)"
	@echo "Internal Subnet: $(INTERNAL_SUBNET) -> $(INTERNAL_SUBNET_HEX)"
	@echo "Internal Mask: $(INTERNAL_MASK) -> $(INTERNAL_MASK_HEX)"
	@echo "Public IP: $(PUBLIC_IP) -> $(PUBLIC_IP_HEX)"
	@echo "============================="

$(OBJECT): $(SOURCE) $(CONFIG_FILE)
	@echo "Building with configuration:"
	@echo "  Interface: $(NIC)"
	@echo "  Internal: $(INTERNAL_SUBNET)/$(INTERNAL_MASK) ($(INTERNAL_SUBNET_HEX)/$(INTERNAL_MASK_HEX))"
	@echo "  Public IP: $(PUBLIC_IP) ($(PUBLIC_IP_HEX))"
	clang $(CFLAGS) $(DEFINES) -c $(SOURCE) -o $(OBJECT)

attach: $(OBJECT)
	sysctl -w net.ipv4.conf.all.forwarding=1
	ip link set dev $(NIC) xdp obj $(OBJECT) sec xdp
	@echo "XDP NAT attached to $(NIC)"

clean: detach
	- rm -f $(OBJECT)

detach:
	- ip link set dev $(NIC) xdp off

rebuild: clean all

trace:
	cat /sys/kernel/debug/tracing/trace_pipe

help:
	@echo "XDP NAT Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make [target] [CONFIG_FILE=config.json]"
	@echo ""
	@echo "Targets:"
	@echo "  all             - Build and attach (default)"
	@echo "  build           - Build only"
	@echo "  attach          - Attach to interface"
	@echo "  detach          - Detach from interface"
	@echo "  clean           - Clean and detach"
	@echo "  rebuild         - Clean and rebuild"
	@echo "  show-config     - Show current configuration"
	@echo "  trace           - Show BPF trace output"
	@echo ""
	@echo "Examples:"
	@echo "  make CONFIG_FILE=production.json"
	@echo "  make show-config"

.PHONY: all build attach clean detach rebuild show-config trace help
