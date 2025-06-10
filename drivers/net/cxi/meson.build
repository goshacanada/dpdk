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

# Include CXI hardware headers from the system
cxi_headers_dep = dependency('cxi-headers', required: false)
if not cxi_headers_dep.found()
    # Fallback to local headers if available
    cxi_inc_dir = get_option('cxi_headers_path')
    if cxi_inc_dir != ''
        cxi_headers_dep = declare_dependency(include_directories: include_directories(cxi_inc_dir))
    else
        build = false
        reason = 'missing cxi headers dependency'
        subdir_done()
    endif
endif

deps += [cxi_headers_dep]

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

# Add meson option for cxi headers path
if get_option('cxi_headers_path') == ''
    # Try to find headers in standard locations
    cxi_inc_dirs = [
        '/usr/include/cxi',
        '/usr/local/include/cxi',
        '../../../include',  # Relative to this directory
    ]
    
    foreach inc_dir : cxi_inc_dirs
        if fs.is_dir(inc_dir)
            cxi_headers_dep = declare_dependency(include_directories: include_directories(inc_dir))
            break
        endif
    endforeach
endif
