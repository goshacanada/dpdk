# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Hewlett Packard Enterprise Development LP

if not is_linux
    build = false
    reason = 'only supported on Linux'
    subdir_done()
endif

sources = files(
    'cxi_ethdev.c',
    'cxi_hw.c',
    'cxi_rxtx.c',
)

headers = files(
    'cxi_ethdev.h',
    'cxi_hw.h',
)

# Add DPDK build directory to include path to find rte_build_config.h
includes += include_directories('../../..')

# Use local CXI headers from include directory
local_include_dir = meson.current_source_dir() / 'include'

# Add local include directory
includes += include_directories('include')

# Check if required headers exist
required_headers = [
    local_include_dir / 'libcxi.h',
    local_include_dir / 'cxi_prov_hw.h',
    local_include_dir / 'cassini_user_defs.h',
]

headers_found = true
foreach header_file : required_headers
    if not fs.exists(header_file)
        headers_found = false
        message('Missing required header: ' + header_file)
    endif
endforeach

if not headers_found
    build = false
    reason = 'Required CXI headers not found in include directory'
    subdir_done()
endif

message('Using local CXI headers from: ' + local_include_dir)

# External dependencies - libcxi library
libcxi_dep = dependency('libcxi', required: false)
if not libcxi_dep.found()
    # Try to find libcxi in standard locations
    libcxi_dep = cc.find_library('cxi', required: false)
    if not libcxi_dep.found()
        # Build without libcxi library but with headers for compilation
        message('Warning: libcxi library not found, building with headers only')
        message('Note: Runtime will require libcxi to be installed separately')
        # Create a dummy dependency for compilation
        libcxi_dep = declare_dependency()
    endif
endif

if libcxi_dep.found()
    ext_deps += libcxi_dep
endif

# Additional dependencies for CXI hardware interface
deps += ['pci', 'mempool']

# Note: libcxi library should be installed separately on the system
# The CXI PMD only needs the headers for compilation
