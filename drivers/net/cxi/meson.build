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

# Download and setup CXI headers from GitHub
git = find_program('git', required: true)
wget = find_program('wget', required: false)
curl = find_program('curl', required: false)

# Define header repositories
shs_libcxi_repo = 'https://github.com/HewlettPackard/shs-libcxi.git'
shs_cassini_repo = 'https://github.com/HewlettPackard/shs-cassini-headers.git'

# Create headers directory in build
headers_dir = meson.current_build_dir() / 'external_headers'
libcxi_headers_dir = headers_dir / 'shs-libcxi'
cassini_headers_dir = headers_dir / 'shs-cassini-headers'

# Clone or update shs-libcxi headers
if not fs.exists(libcxi_headers_dir)
    message('Cloning shs-libcxi headers from GitHub...')
    run_command(git, 'clone', '--depth=1', shs_libcxi_repo, libcxi_headers_dir, check: true)
else
    message('Updating shs-libcxi headers...')
    run_command(git, '-C', libcxi_headers_dir, 'pull', check: false)
endif

# Clone or update shs-cassini-headers
if not fs.exists(cassini_headers_dir)
    message('Cloning shs-cassini-headers from GitHub...')
    run_command(git, 'clone', '--depth=1', shs_cassini_repo, cassini_headers_dir, check: true)
else
    message('Updating shs-cassini-headers...')
    run_command(git, '-C', cassini_headers_dir, 'pull', check: false)
endif

# Add include directories for the downloaded headers
libcxi_inc_dirs = [
    libcxi_headers_dir / 'include',
    libcxi_headers_dir / 'include' / 'uapi',
    libcxi_headers_dir,
]

cassini_inc_dirs = [
    cassini_headers_dir / 'include',
    cassini_headers_dir / 'include' / 'uapi',
    cassini_headers_dir,
]

# Check if include directories exist and add them
cxi_headers_found = false
cassini_headers_found = false

foreach inc_dir : libcxi_inc_dirs
    if fs.is_dir(inc_dir)
        includes += include_directories(inc_dir)
        cxi_headers_found = true
        message('Added libcxi include directory: ' + inc_dir)
    endif
endforeach

foreach inc_dir : cassini_inc_dirs
    if fs.is_dir(inc_dir)
        includes += include_directories(inc_dir)
        cassini_headers_found = true
        message('Added Cassini include directory: ' + inc_dir)
    endif
endforeach

# Fallback: try to find specific header files
if not cxi_headers_found
    # Look for key libcxi headers
    libcxi_header_files = [
        libcxi_headers_dir / 'libcxi.h',
        libcxi_headers_dir / 'include' / 'libcxi.h',
        libcxi_headers_dir / 'include' / 'cxi_prov_hw.h',
    ]

    foreach header_file : libcxi_header_files
        if fs.exists(header_file)
            includes += include_directories(fs.parent(header_file))
            cxi_headers_found = true
            message('Found libcxi header: ' + header_file)
            break
        endif
    endforeach
endif

if not cassini_headers_found
    # Look for key Cassini headers
    cassini_header_files = [
        cassini_headers_dir / 'cassini_user_defs.h',
        cassini_headers_dir / 'include' / 'cassini_user_defs.h',
        cassini_headers_dir / 'include' / 'uapi' / 'misc' / 'cxi.h',
    ]

    foreach header_file : cassini_header_files
        if fs.exists(header_file)
            includes += include_directories(fs.parent(header_file))
            cassini_headers_found = true
            message('Found Cassini header: ' + header_file)
            break
        endif
    endforeach
endif

if not cxi_headers_found
    build = false
    reason = 'shs-libcxi headers not found after GitHub clone'
    subdir_done()
endif

if not cassini_headers_found
    build = false
    reason = 'shs-cassini-headers not found after GitHub clone'
    subdir_done()
endif

# External dependencies - libcxi library
libcxi_dep = dependency('libcxi', required: false)
if not libcxi_dep.found()
    # Try to find libcxi in standard locations
    libcxi_dep = cc.find_library('cxi', required: false)
    if not libcxi_dep.found()
        # Try to find libcxi in the downloaded shs-libcxi directory
        libcxi_lib_paths = [
            libcxi_headers_dir / 'lib',
            libcxi_headers_dir / 'build' / 'lib',
            libcxi_headers_dir / '.libs',
        ]

        libcxi_found_in_download = false
        foreach lib_path : libcxi_lib_paths
            if fs.is_dir(lib_path)
                libcxi_dep = cc.find_library('cxi', dirs: lib_path, required: false)
                if libcxi_dep.found()
                    libcxi_found_in_download = true
                    message('Found libcxi in downloaded directory: ' + lib_path)
                    break
                endif
            endif
        endforeach

        if not libcxi_found_in_download
            # Build without libcxi library but with headers for compilation
            message('Warning: libcxi library not found, building with headers only')
            message('Note: Runtime will require libcxi to be installed separately')
            # Create a dummy dependency for compilation
            libcxi_dep = declare_dependency()
        endif
    endif
endif

if libcxi_dep.found()
    ext_deps += libcxi_dep
endif

# Additional dependencies for CXI hardware interface
deps += ['pci', 'mempool']

# Optional: Build libcxi if Makefile exists
libcxi_makefile = libcxi_headers_dir / 'Makefile'
libcxi_meson_build = libcxi_headers_dir / 'meson.build'

if fs.exists(libcxi_makefile) or fs.exists(libcxi_meson_build)
    message('Found build system in shs-libcxi, attempting to build...')

    # Try to build libcxi
    if fs.exists(libcxi_meson_build)
        # Use meson build
        libcxi_build_result = run_command(
            'sh', '-c',
            'cd ' + libcxi_headers_dir + ' && meson setup build --prefix=' + libcxi_headers_dir + '/install && ninja -C build && ninja -C build install',
            check: false
        )
    elif fs.exists(libcxi_makefile)
        # Use make build
        libcxi_build_result = run_command(
            'sh', '-c',
            'cd ' + libcxi_headers_dir + ' && make && make install PREFIX=' + libcxi_headers_dir + '/install',
            check: false
        )
    endif

    if libcxi_build_result.returncode() == 0
        message('Successfully built libcxi from source')
        # Add the built library to dependencies
        libcxi_built_lib = libcxi_headers_dir / 'install' / 'lib'
        if fs.is_dir(libcxi_built_lib)
            libcxi_dep = cc.find_library('cxi', dirs: libcxi_built_lib, required: false)
            if libcxi_dep.found()
                ext_deps += libcxi_dep
                message('Using built libcxi from: ' + libcxi_built_lib)
            endif
        endif
    else
        message('Failed to build libcxi, continuing with headers only')
    endif
endif
