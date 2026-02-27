# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.25)

# When invoked as a subdirectory, just collect source files and return.
if(NOT CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(cppvrf_TESTS_FILES ${cppvrf_TESTS_FILES}
        "${CMAKE_CURRENT_LIST_DIR}/common_tests.cpp"
        "${CMAKE_CURRENT_LIST_DIR}/log_tests.cpp"
        "${CMAKE_CURRENT_LIST_DIR}/test_runner.cpp"
        "${CMAKE_CURRENT_LIST_DIR}/utils.cpp"
        "${CMAKE_CURRENT_LIST_DIR}/vrf_tests.cpp"
    )

    set(cppvrf_TESTS_FILES ${cppvrf_TESTS_FILES} PARENT_SCOPE)
    return()
endif()

# Standalone mode: build tests against an installed or build-tree cppvrf.
#
# Usage:
#   cmake -S tests -B build_tests \
#         -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT_DIR/scripts/buildsystems/vcpkg.cmake \
#         -Dcppvrf_ROOT=/path/to/cppvrf/install/dir \
#         -DCMAKE_BUILD_TYPE=<Debug|Release>
#   cmake --build build_tests --target vrf_tests
project(cppvrf_tests LANGUAGES CXX)

# Accept CPPVRF_ROOT as a case-insensitive alias for cppvrf_ROOT.
if(DEFINED CPPVRF_ROOT AND NOT DEFINED cppvrf_ROOT)
    set(cppvrf_ROOT "${CPPVRF_ROOT}")
endif()

find_package(cppvrf REQUIRED)
find_package(GTest CONFIG REQUIRED)

add_executable(vrf_tests
    common_tests.cpp
    log_tests.cpp
    test_runner.cpp
    utils.cpp
    vrf_tests.cpp
)

target_link_libraries(vrf_tests PRIVATE
    cppvrf::cppvrf
    GTest::gtest
)

# Add the parent directory to the include path so that test-local headers
# (included via paths like "vrf/../tests/utils.h") resolve correctly.
target_include_directories(vrf_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/..")
