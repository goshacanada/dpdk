# CXI PMD Driver

This directory contains the DPDK Poll Mode Driver (PMD) for HPE Cassini (CXI) Network Interface Cards.

## Overview

The CXI PMD provides high-performance packet processing capabilities for Cassini NICs, leveraging the hardware's unique dual-path architecture and advanced multi-queue RSS capabilities:

- **IDC (Immediate Data Commands)**: For small packets (≤256 bytes) embedded directly in commands
- **DMA Commands**: For large packets using scatter-gather DMA with up to 5 segments
- **RSS (Receive Side Scaling)**: Hardware-accelerated packet distribution across multiple queues

## Features

- **High Performance**: Optimized for low latency and high throughput
- **Hardware Offloads**: Checksum calculation and validation (TCP, UDP, IP)
- **Multi-Queue RSS Support**: Up to 64 RX/TX queues with hardware RSS
- **Advanced RSS**: 2048-entry indirection table with configurable 44-byte hash key
- **Memory Efficiency**: Efficient buffer management using DPDK mempools
- **Event-Driven**: Hardware event queues for completion processing
- **Zero-Copy Design**: Direct hardware access via memory mapping

## Hardware Architecture

The Cassini NIC consists of several key hardware blocks:

- **CQ (Command Queue)**: Handles command submission with per-queue isolation
- **EQ (Event Queue)**: Processes completions with per-queue event handling
- **HNI (Host Network Interface)**: Ethernet packet processing 
- **RMU (Resource Management Unit)**: RSS and resource management
- **IXE (Initiator eXecution Engine)**: Inbound packet processing
- **OXE (Outbound eXecution Engine)**: Outbound packet processing
- **ATU (Address Translation Unit)**: Memory mapping
- **EE (Event Engine)**: Event/completion handling

## Multi-Queue RSS Architecture

### Cassini Hardware RSS Capabilities

The Cassini NIC provides sophisticated RSS hardware support based on the kernel CXI ethernet driver:

- **Maximum RSS Queues**: 64 (must be power of 2)
- **Maximum TX Queues**: 64 (aligned with RX queues)
- **Indirection Table**: Up to 2048 entries for fine-grained load balancing
- **Hash Key Size**: 44 bytes (351 bits rounded up)
- **Hash Types Supported**:
  - IPv4/IPv6 with TCP, UDP protocols
  - IPv4/IPv6 with protocol-specific hashing
  - IPv6 flow label hashing
  - RoCE-optimized UDP hashing

### RSS Queue Distribution

When RSS is enabled, incoming packets are distributed across multiple RX queues based on hardware-computed hash values:

```
Incoming Packet → Hardware RSS Hash → Indirection Table → RX Queue
     ↓                    ↓                   ↓              ↓
[Eth|IP|TCP]    →    Hash(src_ip,dst_ip,  →  RETA[hash %  → Queue 0-63
                          src_port,dst_port)    table_size]
```

### Multi-Queue Configuration Example

```c
// Configure 8 RX/TX queues with RSS
struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode = RTE_ETH_MQ_RX_RSS,
        .max_rx_pkt_len = 9216,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,  // Use default Cassini hash key
            .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
        },
    },
};

// Setup device with 8 queues
rte_eth_dev_configure(port_id, 8, 8, &port_conf);

// Each queue gets independent CQ/EQ pair
for (int q = 0; q < 8; q++) {
    rte_eth_rx_queue_setup(port_id, q, 1024, socket, NULL, mbuf_pool);
    rte_eth_tx_queue_setup(port_id, q, 1024, socket, NULL);
}
```

### Performance Benefits

Multi-queue RSS provides significant performance improvements:

- **Parallel Processing**: Each CPU core handles dedicated queue(s)
- **Cache Efficiency**: Queue data structures stay in core's cache
- **Lock-Free Operation**: No synchronization between queues
- **NUMA Awareness**: Queues allocated on appropriate NUMA nodes
- **Load Balancing**: Hardware distributes traffic evenly across queues

## Multi-TX Queue Support

The CXI PMD provides comprehensive multi-TX queue support for maximum transmission performance:

### TX Queue Architecture

- **64 Independent TX Queues**: Each queue has dedicated Command Queue (CQ) and Event Queue (EQ)
- **Per-Queue Credit Management**: Atomic credit tracking prevents queue overflow
- **Hardware Isolation**: No locking required between TX queues for lock-free operation
- **Dual-Path Transmission**: Each queue supports both IDC and DMA paths
- **NUMA-Aware Allocation**: TX queues allocated on appropriate NUMA nodes

### TX Queue Features

```c
// Each TX queue provides:
struct cxi_tx_queue {
    uint16_t queue_id;              // Queue identifier (0-63)
    struct cxi_cq cq;               // Dedicated command queue
    struct cxi_eq eq;               // Dedicated event queue
    rte_atomic32_t tx_credits;      // Per-queue credit management
    uint32_t force_dma_interval;    // IDC/DMA balancing
    // Per-queue statistics
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t tx_errors;
};
```

### Application Usage

```c
// Configure multiple TX queues
struct rte_eth_conf port_conf = {
    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,  // Simple multi-queue mode
        .offloads = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM |
                   RTE_ETH_TX_OFFLOAD_TCP_CKSUM,
    },
};

// Setup 8 TX queues
rte_eth_dev_configure(port_id, nb_rx_queues, 8, &port_conf);
for (int q = 0; q < 8; q++) {
    rte_eth_tx_queue_setup(port_id, q, 1024, socket_id, NULL);
}

// Each worker core uses dedicated TX queue (lock-free)
static int worker_thread(void *arg) {
    uint16_t queue_id = *(uint16_t *)arg;
    struct rte_mbuf *pkts[32];

    while (running) {
        // Process packets...

        // Transmit on dedicated queue - no locking needed
        uint16_t sent = rte_eth_tx_burst(port_id, queue_id, pkts, nb_pkts);
    }
    return 0;
}
```

### CXI-Specific Optimizations

- **Automatic IDC/DMA Selection**: Small packets (≤256 bytes) use IDC, large packets use DMA
- **Credit-Based Flow Control**: Prevents queue overflow with atomic operations
- **Queue-Specific Flow Hash**: Each queue uses its ID as flow hash for hardware distribution
- **Scatter-Gather Support**: DMA path supports up to 5 segments per packet

## Architecture Documentation

Architecture documentation is available in this directory:

- **`CXI_PMD_Architecture.md`** - Detailed architecture documentation

The documentation includes:
1. **Complete Call Flow** - Function calls from DPDK app through PMD, libcxi, kernel driver, to hardware
2. **Component Architecture** - Modular design and component relationships
3. **Data Flow** - Packet processing flow and zero-copy design
4. **Multi-Queue RSS Implementation** - Queue allocation and RSS configuration details

### Key Architectural Features

- **Zero-Copy Design**: Direct hardware access via memory mapping, no data copying
- **Dual Transmission Paths**: IDC for small packets, DMA for large packets
- **Credit-Based Flow Control**: Prevents queue overflow with atomic credit management
- **Event-Driven Completions**: Asynchronous completion processing via hardware events
- **libcxi Integration**: Uses libcxi library for resource management and hardware abstraction

## libcxi Integration

The CXI PMD is built on top of the libcxi library, which provides a comprehensive user-space interface to the Cassini hardware. This integration enables high-performance, zero-copy packet processing while maintaining proper resource management and hardware abstraction.

### libcxi Architecture Overview

libcxi serves as the critical abstraction layer between the CXI PMD and the Cassini hardware:

```
┌─────────────────────────────────────────────────────────────┐
│                    DPDK Application                         │
└─────────────────────┬───────────────────────────────────────┘
                      │ rte_eth_* API calls
┌─────────────────────▼───────────────────────────────────────┐
│                    CXI PMD                                  │
│  ┌─────────────────┬─────────────────┬─────────────────┐    │
│  │   Device Ops    │   Queue Mgmt    │   Packet I/O    │    │
│  └─────────────────┴─────────────────┴─────────────────┘    │
└─────────────────────┬───────────────────────────────────────┘
                      │ libcxi API calls
┌─────────────────────▼───────────────────────────────────────┐
│                   libcxi Library                            │
│  ┌─────────────────┬─────────────────┬─────────────────┐    │
│  │ Device Mgmt     │ Resource Alloc  │ Memory Mapping  │    │
│  │ Command I/F     │ Event Handling  │ Hardware Access │    │
│  └─────────────────┴─────────────────┴─────────────────┘    │
└─────────────────────┬───────────────────────────────────────┘
                      │ ioctl() + mmap()
┌─────────────────────▼───────────────────────────────────────┐
│                 CXI Kernel Driver                           │
└─────────────────────┬───────────────────────────────────────┘
                      │ Hardware registers
┌─────────────────────▼───────────────────────────────────────┐
│                 Cassini Hardware                            │
└─────────────────────────────────────────────────────────────┘
```

### Core libcxi Components Used by CXI PMD

#### 1. Device Management
The CXI PMD uses libcxi for complete device lifecycle management:

**Device Discovery and Initialization:**
```c
// Device enumeration and opening
cxil_open_device(pci_dev->addr.devid, &adapter->cxil_dev);

// Ethernet-specific initialization
cxil_init_eth_device(adapter->cxil_dev);

// Capability discovery
cxil_get_eth_capabilities(adapter->cxil_dev, &eth_caps);
```

**Resource Allocation Pattern:**
```c
// Logical Network Interface (LNI) - Core communication context
cxil_alloc_lni(adapter->cxil_dev, &adapter->lni, CXI_DEFAULT_SVC_ID);

// Communication Profile (CP) - Ethernet traffic class configuration
cxil_alloc_cp(adapter->lni, 0, CXI_TC_ETH, CXI_TC_TYPE_DEFAULT, &adapter->cp);
```

#### 2. Memory Management and Zero-Copy Architecture
libcxi provides sophisticated memory management that enables zero-copy packet processing:

**Memory Mapping for Hardware Access:**
```c
// Map packet buffers for DMA access
cxil_map(adapter->lni, buffer_va, buffer_len,
         CXI_MAP_PIN | CXI_MAP_READ | CXI_MAP_WRITE,
         NULL, &memory_descriptor);

// Direct hardware access via mapped memory
// - Command Queues: Direct write access for packet commands
// - Event Queues: Direct read access for completion events
// - CSRs: Direct access for configuration and status
```

**Benefits of libcxi Memory Management:**
- **Zero-Copy Design**: Packets are never copied between user and kernel space
- **Hardware DMA**: Direct memory access by Cassini hardware
- **IOMMU Integration**: Proper address translation for virtualized environments
- **Memory Pinning**: Prevents page swapping for consistent performance

#### 3. Command and Event Queue Management
libcxi manages the hardware command/event queue infrastructure that enables high-performance packet processing:

**Command Queue (CQ) Allocation:**
```c
// Allocate command queue for packet transmission
cxil_alloc_cmdq(adapter->lni, event_queue, &cq_options, &command_queue);

// Configure queue for ethernet traffic
struct cxi_cq_alloc_opts cq_opts = {
    .count = CXI_DEFAULT_CQ_SIZE,
    .flags = CXI_CQ_IS_TX,
    .policy = CXI_CQ_UPDATE_HIGH_FREQ,
};
```

**Event Queue (EQ) Management:**
```c
// Allocate event queue for completion processing
cxil_alloc_evtq(adapter->lni, eq_memory_descriptor, &eq_attrs,
                NULL, NULL, &event_queue);

// Event queue provides asynchronous completion notifications
// - TX completions for credit management
// - RX notifications for packet arrival
// - Error events for exception handling
```

#### 4. Packet Transmission via libcxi
The CXI PMD leverages libcxi's dual-path transmission architecture:

**IDC (Immediate Data Commands) for Small Packets:**
```c
// Small packets (≤256 bytes) embedded directly in commands
ret = cxi_cq_emit_idc_eth(txq->cq.cq, &idc_cmd,
                         packet_data, packet_length);
```

**DMA Commands for Large Packets:**
```c
// Large packets use scatter-gather DMA
ret = cxi_cq_emit_dma_eth(txq->cq.cq, &dma_cmd);
```

**Hardware Doorbell Mechanism:**
```c
// Ring doorbell to notify hardware of new commands
cxi_cq_ring(command_queue);
// This triggers MMIO write to hardware doorbell register
```

#### 5. Network Configuration via libcxi
libcxi provides comprehensive network configuration capabilities:

**MAC Address Management:**
```c
// Get hardware MAC address
cxil_get_mac_address(adapter->cxil_dev, mac_addr_bytes);

// Set new MAC address
cxil_set_mac_address(adapter->cxil_dev, new_mac_addr);
```

**Link and MTU Configuration:**
```c
// Query link status and capabilities
cxil_get_link_info(adapter->cxil_dev, &link_info);

// Configure Maximum Transmission Unit
cxil_set_mtu(adapter->cxil_dev, new_mtu_size);
```

**Traffic Filtering:**
```c
// Configure promiscuous mode
cxil_set_promiscuous(adapter->cxil_dev, enable);

// Configure multicast filtering
cxil_set_allmulticast(adapter->cxil_dev, enable);
```

### Performance Benefits of libcxi Integration

#### 1. Zero-Copy Data Path
- **No Memory Copies**: Packets flow directly from application buffers to hardware
- **Reduced CPU Overhead**: Eliminates expensive memory copy operations
- **Cache Efficiency**: Minimizes cache pollution from unnecessary data movement

#### 2. Direct Hardware Access
- **Memory Mapped I/O**: Command and event queues accessed via mmap()
- **User-Space Operations**: No system calls in fast path
- **Hardware Doorbells**: Direct MMIO writes for command submission

#### 3. Efficient Resource Management
- **Hardware Resource Pooling**: libcxi manages hardware resource allocation
- **Multi-Queue Isolation**: Independent command/event queues per TX/RX queue
- **Credit-Based Flow Control**: Prevents hardware queue overflow

#### 4. Advanced Hardware Features
- **RSS (Receive Side Scaling)**: Hardware-accelerated packet distribution
- **Checksum Offload**: Hardware calculation of TCP/UDP/IP checksums
- **Scatter-Gather DMA**: Efficient handling of fragmented packets

### libcxi API Categories Used by CXI PMD

| Category | Functions | Purpose |
|----------|-----------|---------|
| **Device Management** | `cxil_open_device()`, `cxil_close_device()`, `cxil_init_eth_device()` | Device lifecycle and initialization |
| **Resource Allocation** | `cxil_alloc_lni()`, `cxil_alloc_cp()`, `cxil_destroy_*()` | Communication context setup |
| **Queue Management** | `cxil_alloc_cmdq()`, `cxil_alloc_evtq()`, `cxi_cq_emit_*()` | Command/event queue operations |
| **Memory Management** | `cxil_map()`, `cxil_unmap()` | Zero-copy memory mapping |
| **Network Configuration** | `cxil_get_mac_address()`, `cxil_set_mtu()`, `cxil_get_link_info()` | Network interface configuration |
| **Hardware Capabilities** | `cxil_get_eth_capabilities()` | Feature discovery and validation |

### Error Handling and Resource Cleanup

The CXI PMD implements robust error handling following libcxi best practices:

```c
// Proper resource cleanup order (reverse of allocation)
if (adapter->cp) {
    cxil_destroy_cp(adapter->cp);
    adapter->cp = NULL;
}
if (adapter->lni) {
    cxil_destroy_lni(adapter->lni);
    adapter->lni = NULL;
}
if (adapter->cxil_dev) {
    cxil_close_device(adapter->cxil_dev);
    adapter->cxil_dev = NULL;
}
```

## Dependencies

### Required Libraries

The driver requires libcxi library and CXI hardware definition headers:
- `libcxi` - CXI user-space library for resource management and hardware abstraction
- `cassini_user_defs.h` - Core hardware definitions and command structures
- `cxi_prov_hw.h` - Hardware provider interface for command/event operations
- `libcassini.h` - Hardware control interface definitions

### Build Configuration and libcxi Integration

The CXI PMD build system is designed to work with both development and production environments:

#### Development Build (Headers Only)
For development and testing, the PMD includes essential libcxi headers locally:

```bash
# The build system automatically detects local headers
meson setup build
ninja -C build

# Local headers are included from drivers/net/cxi/include/:
# - libcxi.h (main API definitions)
# - cxi_prov_hw.h (hardware provider interface)
# - cassini_user_defs.h (hardware constants and structures)
```

#### Production Build (Full libcxi Library)
For production deployment, install the complete libcxi library:

```bash
# Install libcxi development package (example for RPM-based systems)
sudo dnf install libcxi-devel

# Or build from source
git clone https://github.com/HewlettPackard/shs-libcxi.git
cd shs-libcxi
./autogen.sh
./configure --prefix=/usr/local
make && sudo make install

# Configure DPDK build with libcxi
meson setup build
ninja -C build
```

#### Build System libcxi Detection
The meson build system automatically handles libcxi integration:

```meson
# From drivers/net/cxi/meson.build
libcxi_dep = dependency('libcxi', required: false)
if not libcxi_dep.found()
    # Try to find libcxi in standard locations
    libcxi_dep = cc.find_library('cxi', required: false)
    if not libcxi_dep.found()
        # Build with headers only (development mode)
        message('Warning: libcxi library not found, building with headers only')
        message('Note: Runtime will require libcxi to be installed separately')
    endif
endif
```

#### Runtime Requirements
- **Development/Testing**: Only headers needed for compilation
- **Production**: Full libcxi library must be installed on target system
- **Hardware**: Cassini NIC with appropriate kernel drivers

## Building

### Quick Start
```bash
# Clone DPDK (if not already available)
git clone https://github.com/DPDK/dpdk.git
cd dpdk

# Configure and build with CXI PMD
meson setup build
ninja -C build
```

### Detailed Build Process

1. **Verify Prerequisites**
   ```bash
   # Check for required tools
   which meson ninja pkg-config

   # Verify Python version (3.6+ required)
   python3 --version
   ```

2. **Configure Build Environment**
   ```bash
   # Set up build directory
   meson setup build

   # Optional: Enable debug for CXI PMD development
   meson setup build -Dbuildtype=debug

   # Optional: Build only CXI PMD and dependencies
   meson setup build -Ddisable_drivers=* -Denable_drivers=net/cxi
   ```

3. **Build DPDK with CXI PMD**
   ```bash
   # Build all components
   ninja -C build

   # Or build only CXI PMD
   ninja -C build drivers/librte_net_cxi.so
   ```

4. **Verify Build Success**
   ```bash
   # Check if CXI PMD was built
   ls -la build/drivers/librte_net_cxi.*

   # Verify PMD registration
   build/app/dpdk-testpmd --help | grep -i cxi
   ```

### Build Troubleshooting

**Missing libcxi Headers:**
```bash
# Error: Required CXI headers not found
# Solution: Ensure headers are present in drivers/net/cxi/include/
ls drivers/net/cxi/include/libcxi.h
```

**libcxi Library Not Found (Runtime):**
```bash
# Error: libcxi.so not found when running applications
# Solution: Install libcxi or set LD_LIBRARY_PATH
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
```

**Compilation Errors:**
```bash
# Enable verbose build for debugging
ninja -C build -v

# Check meson configuration
meson configure build | grep cxi
```

## Usage

### Device Binding

Bind CXI devices to DPDK-compatible driver:

```bash
# Bind to vfio-pci (recommended)
dpdk-devbind.py --bind=vfio-pci 0000:xx:xx.x

# Or bind to uio_pci_generic
dpdk-devbind.py --bind=uio_pci_generic 0000:xx:xx.x
```

### Application Integration

```c
#include <rte_ethdev.h>

/* Initialize DPDK EAL */
rte_eal_init(argc, argv);

/* Configure CXI port with RSS for multi-queue */
struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode = RTE_ETH_MQ_RX_RSS,  // Enable RSS
        .max_rx_pkt_len = 9216,
    },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,  // Use Cassini default hash key
            .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
        },
    },
};

// Configure with multiple queues for RSS
rte_eth_dev_configure(port_id, 8, 8, &port_conf);

// Setup each queue
for (int q = 0; q < 8; q++) {
    rte_eth_rx_queue_setup(port_id, q, 1024, socket, NULL, mbuf_pool);
    rte_eth_tx_queue_setup(port_id, q, 1024, socket, NULL);
}
```

## Performance Tuning

### Multi-Queue Configuration

#### RX Queue (RSS) Optimization
- **Queue Count**: Use power-of-2 queues (2, 4, 8, 16, 32, 64) for optimal RSS
- **CPU Mapping**: Assign one RX queue per CPU core for maximum parallelism
- **NUMA Awareness**: Allocate queues on same NUMA node as processing cores
- **Hash Types**: Enable appropriate hash types for your traffic patterns

#### TX Queue Optimization
- **Queue Count**: Match TX queues to RX queues (1:1 ratio recommended)
- **Per-Core Assignment**: Each worker core gets dedicated TX queue (lock-free)
- **Credit Management**: Monitor per-queue credits to avoid blocking
- **IDC/DMA Balance**: Let driver automatically select optimal path

```c
// Optimal multi-queue configuration for 8-core system
struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode = RTE_ETH_MQ_RX_RSS,
    },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,  // Simple multi-queue
        .offloads = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM |
                   RTE_ETH_TX_OFFLOAD_TCP_CKSUM,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_hf = RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_IPV6 |
                      RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
        },
    },
};

// Configure 8 RX + 8 TX queues
rte_eth_dev_configure(port_id, 8, 8, &port_conf);
```

### Packet Size Optimization

- Small packets (≤256 bytes) automatically use IDC path
- Large packets use DMA path with scatter-gather (up to 5 segments)
- Driver automatically balances IDC/DMA usage for optimal performance

### Memory Configuration

- Use hugepages for better performance
- Configure appropriate mempool sizes (recommend 8192+ mbufs per queue)
- Consider NUMA-aware memory allocation for multi-socket systems

## Debugging

Enable debug logging:

```bash
# Set log level for CXI PMD
--log-level=pmd.net.cxi:debug

# Or set specific component logging
--log-level=pmd.net.cxi.init:debug
--log-level=pmd.net.cxi.driver:debug
```

## Limitations

Current implementation limitations:

- TSO (TCP Segmentation Offload) not implemented
- VLAN support not implemented
- SR-IOV support not implemented
- Interrupt mode support not implemented

## Development Status

This implementation provides comprehensive multi-queue packet processing functionality:

**✅ Completed:**
- Device probe and initialization via libcxi
- **Multi-TX Queue Support (up to 64 independent TX queues)**
- **Multi-RX Queue Support with RSS (up to 64 queues)**
- RSS (Receive Side Scaling) with hardware hash support
- RSS indirection table (RETA) configuration
- **Per-queue credit management with atomic operations**
- Packet transmission with IDC/DMA path selection
- **Lock-free multi-queue operation**
- Event-driven completion processing
- Hardware checksum offload support
- Memory mapping and zero-copy architecture
- **Per-queue statistics and error tracking**
- **NUMA-aware queue allocation**

## Contributing

When contributing to the CXI PMD:

1. Follow DPDK coding standards
2. Add appropriate logging and error handling
3. Update documentation for new features
4. Test thoroughly on actual hardware

## Support

For issues and questions:

- Check DPDK documentation
- Review CXI hardware documentation
- Submit issues to the DPDK mailing list

## License

SPDX-License-Identifier: BSD-3-Clause
Copyright(c) 2024 Hewlett Packard Enterprise Development LP
