
cmake_minimum_required(VERSION 3.20)

set(VCPKG_OVERLAY_TRIPLETS "${CMAKE_INSTALL_PREFIX}/share/caffeine/vcpkg")
set(VCPKG_TARGET_TRIPLET    x64-linux-gllvm)

project(fuzz-tests C CXX)

include("${CMAKE_CURRENT_LIST_DIR}/cmake/bundle.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/cmake/extract-bitcode.cmake")

find_package(libpng REQUIRED)
find_package(caffeine REQUIRED)

add_subdirectory(caffeine)
add_subdirectory(libpng)

