# CXI PMD Include Directory

This directory contains the essential header files required for building the CXI PMD.

## Header Files

### libcxi.h
Main libcxi interface header containing:
- Device and resource management structures
- API function declarations
- Core libcxi types and constants

### cxi_prov_hw.h  
Hardware provider interface header containing:
- Hardware command structures (cxi_cq, cxi_eq, cxi_md)
- Function declarations for hardware operations
- CXI hardware interface definitions

### cassini_user_defs.h
Cassini hardware definitions header containing:
- Hardware constants (C_MAX_ETH_FRAGS, etc.)
- Command structures (c_dma_eth_cmd, c_idc_eth_cmd)
- Hardware enumerations and return codes

## Source

These headers are derived from the official HPE repositories:
- **shs-libcxi**: https://github.com/HewlettPackard/shs-libcxi
- **shs-cassini-headers**: https://github.com/HewlettPackard/shs-cassini-headers

Only the essential headers needed for CXI PMD compilation are included here.

## Usage

The CXI PMD build system automatically includes this directory:
```meson
includes += include_directories('include')
```

## Runtime Dependencies

While these headers allow compilation, the runtime requires:
- libcxi library installed on the system
- Appropriate CXI hardware drivers
- Proper system configuration for CXI devices

## Maintenance

To update headers:
1. Check the upstream repositories for changes
2. Copy only the required definitions to maintain minimal footprint
3. Ensure compatibility with existing CXI PMD code
4. Test compilation and basic functionality
