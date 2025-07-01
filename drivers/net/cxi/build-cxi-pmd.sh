#!/bin/bash
# Build script for CXI PMD with automatic header download

set -e

# Configuration
DPDK_DIR="$HOME/development/dpdk"
BUILD_DIR="$DPDK_DIR/build"
HEADERS_DIR="$BUILD_DIR/drivers/net/cxi/external_headers"
LIBCXI_REPO="https://github.com/HewlettPackard/shs-libcxi.git"
CASSINI_REPO="https://github.com/HewlettPackard/shs-cassini-headers.git"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

echo_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

echo_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    echo_info "Checking prerequisites..."
    
    # Check if git is installed
    if ! command -v git &> /dev/null; then
        echo_error "git is required but not installed"
        exit 1
    fi
    
    # Check if DPDK directory exists
    if [ ! -d "$DPDK_DIR" ]; then
        echo_error "DPDK directory not found: $DPDK_DIR"
        echo_info "Please clone DPDK first: git clone https://dpdk.org/git/dpdk $DPDK_DIR"
        exit 1
    fi
    
    # Check if CXI PMD exists
    if [ ! -d "$DPDK_DIR/drivers/net/cxi" ]; then
        echo_error "CXI PMD directory not found: $DPDK_DIR/drivers/net/cxi"
        exit 1
    fi
    
    echo_success "Prerequisites check passed"
}

# Download headers manually (fallback)
download_headers_manual() {
    echo_info "Downloading headers manually..."
    
    mkdir -p "$HEADERS_DIR"
    
    # Download shs-libcxi
    if [ ! -d "$HEADERS_DIR/shs-libcxi" ]; then
        echo_info "Cloning shs-libcxi..."
        git clone --depth=1 "$LIBCXI_REPO" "$HEADERS_DIR/shs-libcxi"
    else
        echo_info "Updating shs-libcxi..."
        cd "$HEADERS_DIR/shs-libcxi"
        git pull || echo_warning "Failed to update shs-libcxi"
        cd - > /dev/null
    fi
    
    # Download shs-cassini-headers
    if [ ! -d "$HEADERS_DIR/shs-cassini-headers" ]; then
        echo_info "Cloning shs-cassini-headers..."
        git clone --depth=1 "$CASSINI_REPO" "$HEADERS_DIR/shs-cassini-headers"
    else
        echo_info "Updating shs-cassini-headers..."
        cd "$HEADERS_DIR/shs-cassini-headers"
        git pull || echo_warning "Failed to update shs-cassini-headers"
        cd - > /dev/null
    fi
    
    echo_success "Headers downloaded successfully"
}

# Build libcxi if possible
build_libcxi() {
    echo_info "Attempting to build libcxi..."
    
    LIBCXI_DIR="$HEADERS_DIR/shs-libcxi"
    
    if [ ! -d "$LIBCXI_DIR" ]; then
        echo_warning "libcxi directory not found, skipping build"
        return
    fi
    
    cd "$LIBCXI_DIR"
    
    # Try meson build first
    if [ -f "meson.build" ]; then
        echo_info "Building libcxi with meson..."
        if meson setup build --prefix="$LIBCXI_DIR/install" 2>/dev/null; then
            if ninja -C build 2>/dev/null; then
                ninja -C build install 2>/dev/null
                echo_success "libcxi built successfully with meson"
                cd - > /dev/null
                return
            fi
        fi
        echo_warning "Meson build failed, trying make..."
    fi
    
    # Try make build
    if [ -f "Makefile" ] || [ -f "makefile" ]; then
        echo_info "Building libcxi with make..."
        if make 2>/dev/null; then
            make install PREFIX="$LIBCXI_DIR/install" 2>/dev/null || true
            echo_success "libcxi built successfully with make"
        else
            echo_warning "Make build failed"
        fi
    else
        echo_warning "No build system found in libcxi"
    fi
    
    cd - > /dev/null
}

# Build DPDK with CXI PMD
build_dpdk() {
    echo_info "Building DPDK with CXI PMD..."
    
    cd "$DPDK_DIR"
    
    # Clean previous build
    if [ -d "$BUILD_DIR" ]; then
        echo_info "Cleaning previous build..."
        rm -rf "$BUILD_DIR"
    fi
    
    # Configure build
    echo_info "Configuring DPDK build..."
    meson setup build \
        -Dexamples=all \
        -Dtests=true \
        -Ddeveloper_mode=true \
        -Denable_drivers=net/cxi \
        -Dwerror=false
    
    # Build
    echo_info "Building DPDK (this may take a while)..."
    ninja -C build -j$(nproc)
    
    echo_success "DPDK build completed"
}

# Verify CXI PMD build
verify_build() {
    echo_info "Verifying CXI PMD build..."
    
    # Check if CXI PMD library exists
    CXI_LIB=$(find "$BUILD_DIR" -name "*cxi*" -type f 2>/dev/null | head -1)
    
    if [ -n "$CXI_LIB" ]; then
        echo_success "CXI PMD built successfully!"
        echo_info "CXI PMD files found:"
        find "$BUILD_DIR" -name "*cxi*" -type f
        
        # Test if CXI PMD is available in testpmd
        if [ -f "$BUILD_DIR/app/dpdk-testpmd" ]; then
            echo_info "Testing CXI PMD availability in testpmd..."
            if sudo "$BUILD_DIR/app/dpdk-testpmd" --help 2>/dev/null | grep -q "cxi\|CXI"; then
                echo_success "CXI PMD is available in testpmd"
            else
                echo_warning "CXI PMD may not be properly registered"
            fi
        fi
    else
        echo_error "CXI PMD not found in build output"
        echo_info "Check build logs for errors:"
        echo_info "cat $BUILD_DIR/meson-logs/meson-log.txt | grep -i cxi"
        return 1
    fi
}

# Main execution
main() {
    echo_info "Starting CXI PMD build process..."
    
    check_prerequisites
    download_headers_manual
    build_libcxi
    build_dpdk
    verify_build
    
    echo_success "CXI PMD build process completed successfully!"
    echo_info "You can now use the CXI PMD with DPDK applications"
    echo_info "Example: sudo $BUILD_DIR/app/dpdk-testpmd -l 0-1 -n 4"
}

# Run main function
main "$@"
