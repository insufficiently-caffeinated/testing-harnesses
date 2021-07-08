#!/bin/bash

# Environment variables that need to point towards the respective types.
VCPKG_ROOT=${VCPKG_ROOT:-~/projects/vcpkg}
CMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX:-~/fydp/install}

rm -rf build/*
CC=gclang CXX=gclang++ cmake -S. -Bbuild \
  -DCMAKE_INSTALL_PREFIX=$CMAKE_INSTALL_PREFIX \
  -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake 