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
includes += include_directories('../../..', global_inc_dir)

# Check for system CXI headers
cxi_headers_found = false
cassini_headers_found = false

# Try pkg-config first
cxi_headers_dep = dependency('cxi-headers', required: false)
cassini_headers_dep = dependency('cray-cassini-headers', required: false)

if cxi_headers_dep.found() and cassini_headers_dep.found()
    cxi_headers_found = true
    cassini_headers_found = true
    deps += [cxi_headers_dep, cassini_headers_dep]
else
    # Try user-specified path
    cxi_inc_dir = get_option('cxi_headers_path')
    if cxi_inc_dir != ''
        if fs.is_dir(cxi_inc_dir)
            includes += include_directories(cxi_inc_dir)
            cxi_headers_found = true
            cassini_headers_found = true
        endif
    else
        # Try standard locations
        cxi_inc_dirs = [
            '/usr/include/cxi',
            '/usr/local/include/cxi',
            '/usr/include',
            '/usr/local/include',
        ]
        
        foreach inc_dir : cxi_inc_dirs
            if fs.is_dir(inc_dir)
                includes += include_directories(inc_dir)
                cxi_headers_found = true
                cassini_headers_found = true
                break
            endif
        endforeach
    endif
endif

if not cxi_headers_found or not cassini_headers_found
    build = false
    reason = 'missing CXI or Cassini headers'
    subdir_done()
endif

# External dependencies
libcxi_dep = dependency('libcxi', required: false)
if not libcxi_dep.found()
    # Try to find libcxi in standard locations
    libcxi_dep = cc.find_library('cxi', required: false)
    if not libcxi_dep.found()
        build = false
        reason = 'missing dependency, libcxi'
        subdir_done()
    endif
endif

ext_deps += libcxi_dep

# Additional dependencies for CXI hardware interface
deps += ['pci', 'mempool']
