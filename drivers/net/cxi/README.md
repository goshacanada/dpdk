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
- **HNI (Host Network Interface)**: Ethernet packet processing with RSS support
- **RMU (Resource Management Unit)**: Memory and resource management
- **IXE (Initiator eXecution Engine)**: Command execution
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

Comprehensive architecture documentation is available in this directory:

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

## Dependencies

### Required Libraries

The driver requires libcxi library and CXI hardware definition headers:
- `libcxi` - CXI user-space library for resource management
- `cassini_user_defs.h` - Core hardware definitions
- `cxi_prov_hw.h` - User-level control interface
- `libcassini.h` - Hardware control interface

### Build Configuration

Configure the build with CXI headers path:

```bash
meson setup build -Dcxi_headers_path=/path/to/cxi/headers
```

Or set the path in your environment:

```bash
export CXI_HEADERS_PATH=/path/to/cxi/headers
```

## Building

1. Ensure DPDK is properly configured
2. Set the CXI headers path (see above)
3. Build DPDK with CXI PMD enabled:

```bash
meson setup build
ninja -C build
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

- TSO (TCP Segmentation Offload) not yet implemented
- VLAN support not yet implemented
- SR-IOV support not yet implemented
- Interrupt mode support not yet implemented

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

**🚧 In Progress:**
- Packet reception implementation refinements
- RSS hash key configuration via libcxi
- Statistics collection improvements
- Error handling enhancements

**📋 Planned:**
- VLAN filtering capabilities
- TSO (TCP Segmentation Offload)
- Interrupt mode support
- Advanced flow steering
- SR-IOV support

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
