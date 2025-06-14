# CXI PMD Driver

This directory contains the DPDK Poll Mode Driver (PMD) for HPE Cassini (CXI) Network Interface Cards.

## Overview

The CXI PMD provides high-performance packet processing capabilities for Cassini NICs, leveraging the hardware's unique dual-path architecture:

- **IDC (Immediate Data Commands)**: For small packets embedded directly in commands
- **DMA Commands**: For large packets using scatter-gather DMA

## Features

- **High Performance**: Optimized for low latency and high throughput
- **Hardware Offloads**: Checksum calculation and validation
- **Multi-Queue Support**: Multiple TX/RX queues for parallel processing
- **Memory Efficiency**: Efficient buffer management using DPDK mempools
- **Event-Driven**: Hardware event queues for completion processing

## Hardware Architecture

The Cassini NIC consists of several key hardware blocks:

- **CQ (Command Queue)**: Handles command submission
- **HNI (Host Network Interface)**: Ethernet packet processing
- **RMU (Resource Management Unit)**: Memory and resource management
- **IXE (Initiator eXecution Engine)**: Command execution
- **ATU (Address Translation Unit)**: Memory mapping
- **EE (Event Engine)**: Event/completion handling

## Architecture Documentation

Comprehensive architecture documentation is available in this directory:

- **`CXI_PMD_Architecture.md`** - Detailed architecture documentation with PlantUML diagrams
- **`cxi_pmd_architecture.puml`** - Raw PlantUML source files for architecture diagrams

The documentation includes:
1. **Complete Call Flow Sequence Diagram** - Function calls from DPDK app through PMD, libcxi, kernel driver, to hardware
2. **Component Architecture Diagram** - Modular design and component relationships
3. **Data Flow Diagram** - Packet processing flow and zero-copy design

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

/* Configure CXI port */
struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode = RTE_ETH_MQ_RX_NONE,
    },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,
    },
};

rte_eth_dev_configure(port_id, nb_rx_queues, nb_tx_queues, &port_conf);
```

## Performance Tuning

### Queue Configuration

- Use multiple queues for parallel processing
- Size queues appropriately for your workload
- Consider NUMA topology when assigning queues

### Packet Size Optimization

- Small packets (≤256 bytes) automatically use IDC path
- Large packets use DMA path with scatter-gather
- Driver automatically balances IDC/DMA usage

### Memory Configuration

- Use hugepages for better performance
- Configure appropriate mempool sizes
- Consider NUMA-aware memory allocation

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
- RSS (Receive Side Scaling) not yet implemented
- VLAN support not yet implemented
- SR-IOV support not yet implemented

## Development Status

This implementation provides comprehensive packet transmission functionality:

**✅ Completed:**
- Device probe and initialization via libcxi
- Queue setup and management (command/event queues)
- Packet transmission with IDC/DMA path selection
- Credit-based flow control and backpressure
- Event-driven completion processing
- Hardware checksum offload support
- Memory mapping and zero-copy architecture
- Comprehensive architecture documentation

**🚧 In Progress:**
- Packet reception implementation
- Statistics collection improvements
- Error handling enhancements
- Performance optimizations

**📋 Planned:**
- RSS (Receive Side Scaling) support
- VLAN filtering capabilities
- TSO (TCP Segmentation Offload)
- Interrupt mode support
- Multi-queue optimizations

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
