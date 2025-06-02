TARGET = xdp-nat.bpf
SOURCE = $(TARGET).c
OBJECT = $(TARGET).o

CONFIG_FILE ?= config.yaml

get_public_ip = $(shell yq '.public_ip' $(CONFIG_FILE) 2>/dev/null)

define ip_to_hex
$(shell python3 -c "import socket, struct; ip = '$(1)'; print('0x%08X' % struct.unpack('<I', socket.inet_aton(ip))[0]) if ip else print('0x00000000')")
endef

PUBLIC_IP_HEX := $(call ip_to_hex,$(get_public_ip))

CFLAGS = -g -O2 -target bpf

all: deploy

deploy:
	@./scripts/xdp-nat.sh deploy $(CONFIG_FILE)

build-for-index:
	@NIC=$$(yq ".interfaces[$(INDEX)].interface" $(CONFIG_FILE)); \
	SUBNET=$$(yq ".interfaces[$(INDEX)].internal.subnet // \"0.0.0.0\"" $(CONFIG_FILE)); \
	MASK=$$(yq ".interfaces[$(INDEX)].internal.mask // \"0.0.0.0\"" $(CONFIG_FILE)); \
	SUBNET_HEX=$$(python3 -c "import socket, struct; print('0x%08X' % struct.unpack('<I', socket.inet_aton('$$SUBNET'))[0])"); \
	MASK_HEX=$$(python3 -c "import socket, struct; print('0x%08X' % struct.unpack('<I', socket.inet_aton('$$MASK'))[0])"); \
	echo "Building for $$NIC with subnet $$SUBNET/$$MASK ($$SUBNET_HEX/$$MASK_HEX)"; \
	clang $(CFLAGS) \
		-DINTERNAL_SUBNET=$$SUBNET_HEX \
		-DINTERNAL_MASK=$$MASK_HEX \
		-DPUBLIC_IP=$(PUBLIC_IP_HEX) \
		-c $(SOURCE) -o $(OBJECT)

attach-for-index:
	@NIC=$$(yq ".interfaces[$(INDEX)].interface" $(CONFIG_FILE)); \
	echo "Attaching XDP program to $$NIC"; \
	sysctl -w net.ipv4.conf.all.forwarding=1; \
	ip link set dev $$NIC xdp obj $(OBJECT) sec xdp; \
	echo "XDP NAT attached to $$NIC"

build:
	@./scripts/xdp-nat.sh build $(CONFIG_FILE)

show-config:
	@./scripts/xdp-nat.sh show-config $(CONFIG_FILE)

clean:
	@./scripts/xdp-nat.sh clean $(CONFIG_FILE)

detach:
	@./scripts/xdp-nat.sh detach $(CONFIG_FILE)

rebuild: clean deploy

trace:
	cat /sys/kernel/debug/tracing/trace_pipe

help:
	@echo "XDP NAT Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make [target] [CONFIG_FILE=config.yaml]"
	@echo ""
	@echo "Targets:"
	@echo "  deploy       	 - Build and attach to all interfaces (default)"
	@echo "  build      	 - Build only (no attachment)"
	@echo "  show-config     - Show current configuration"
	@echo "  detach          - Detach from all interfaces"
	@echo "  clean           - Clean and detach"
	@echo "  rebuild         - Clean and rebuild"
	@echo "  trace           - Show BPF trace output"
	@echo ""
	@echo "Examples:"
	@echo "  make CONFIG_FILE=config-bridge.yaml"
	@echo "  make CONFIG_FILE=config-single.yaml"
	@echo "  make show-config"

.PHONY: all deploy build show-config clean detach rebuild trace help
