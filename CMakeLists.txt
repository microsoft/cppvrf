# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.25)

option(CPPVRF_BUILD_TESTS      "Build the tests."      OFF)
option(CPPVRF_BUILD_BENCHMARKS "Build the benchmarks." OFF)
option(CPPVRF_ENABLE_HARDENING "Enable security hardening compile and link flags." YES)

# Currently we do not support shared builds. Warn the user.
if(BUILD_SHARED_LIBS)
    message(WARNING "BUILD_SHARED_LIBS is set but cppvrf only supports static"
                    "builds. Ignoring BUILD_SHARED_LIBS.")
endif()

# Conditionally enable VCPKG manifest features for tests and benchmarks.
if(CPPVRF_BUILD_TESTS)
    list(APPEND VCPKG_MANIFEST_FEATURES "tests")
endif()
if(CPPVRF_BUILD_BENCHMARKS)
    list(APPEND VCPKG_MANIFEST_FEATURES "benchmarks")
endif()

# Where to look for our helper modules.
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

project(cppvrf VERSION 1.6.2 LANGUAGES CXX)

# Security hardening flags. Applied as directory-scope options; do NOT
# propagate to downstream consumers via the install/export interface.
if(CPPVRF_ENABLE_HARDENING)
    if(MSVC)
        # Control Flow Guard.
        add_compile_options(/guard:cf)
        add_link_options(/guard:cf)
    else()
        # Stack canaries.
        add_compile_options(-fstack-protector-strong)

        # Stack-clash protection (no-op on Apple Clang; gated for older
        # GCC/Clang versions that don't support the flag).
        if(NOT APPLE)
            include(CheckCXXCompilerFlag)
            check_cxx_compiler_flag(-fstack-clash-protection CPPVRF_HAS_STACK_CLASH_PROTECTION)
            if(CPPVRF_HAS_STACK_CLASH_PROTECTION)
                add_compile_options(-fstack-clash-protection)
            endif()
        endif()

        # Position-independent code (static archives may be linked into
        # shared/executable consumers).
        set(CMAKE_POSITION_INDEPENDENT_CODE ON)

        # Standard library hardening (bounds-checked containers, etc.).
        add_compile_definitions(
            $<$<NOT:$<CONFIG:Debug>>:_GLIBCXX_ASSERTIONS>
            $<$<NOT:$<CONFIG:Debug>>:_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST>
        )

        # Full RELRO, immediate binding, non-executable stack (ELF only).
        if(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_SYSTEM_NAME STREQUAL "Android")
            add_link_options(-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
        endif()

        # Fortified libc functions (requires -O1+, skip on Apple).
        if(NOT APPLE)
            add_compile_options($<$<NOT:$<CONFIG:Debug>>:-U_FORTIFY_SOURCE>)
            add_compile_definitions($<$<NOT:$<CONFIG:Debug>>:_FORTIFY_SOURCE=2>)
        endif()
    endif()
endif()

# Define additional directory path variables.
include(GNUInstallDirs)

# Setup runtime path.
# set(CMAKE_INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
# set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# Define source tree variables.
set(cppvrf_INCLUDES_DIR "${CMAKE_CURRENT_LIST_DIR}")
set(cppvrf_CONFIG_IN_FILENAME "${CMAKE_CURRENT_LIST_DIR}/cmake/cppvrfConfig.cmake.in")

# Define build tree variables.
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY
    "${CMAKE_CURRENT_BINARY_DIR}/lib")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY
    "${CMAKE_CURRENT_BINARY_DIR}/lib")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY
    "${CMAKE_CURRENT_BINARY_DIR}/bin")
set(cppvrf_CONFIG_FILENAME
    "${CMAKE_CURRENT_BINARY_DIR}/cmake/cppvrfConfig.cmake")
set(cppvrf_TARGETS_FILENAME
    "${CMAKE_CURRENT_BINARY_DIR}/cmake/cppvrfTargets.cmake")
set(cppvrf_CONFIG_VERSION_FILENAME
    "${CMAKE_CURRENT_BINARY_DIR}/cmake/cppvrfConfigVersion.cmake")

# Define the install directories.
set(cppvrf_VERSION_MM "${cppvrf_VERSION_MAJOR}.${cppvrf_VERSION_MINOR}")
set(cppvrf_CONFIG_INSTALL_DIR
    "${CMAKE_INSTALL_LIBDIR}/cmake/cppvrf-${cppvrf_VERSION_MM}")
set(cppvrf_INCLUDES_INSTALL_DIR
    "${CMAKE_INSTALL_INCLUDEDIR}/cppvrf-${cppvrf_VERSION_MM}")

# Find all source files.
set(cppvrf_SOURCE_FILES "")
add_subdirectory(vrf)

# cppvrf can only be built as a static library for now.
add_library(cppvrf STATIC ${cppvrf_SOURCE_FILES})

# Require C++20 for cppvrf and downstream.
target_compile_features(cppvrf PUBLIC cxx_std_20)

find_package(OpenSSL 3.2 REQUIRED)
target_link_libraries(cppvrf PUBLIC OpenSSL::Crypto)

# For debug builds, append "_debug" to the library name.
set_target_properties(cppvrf PROPERTIES DEBUG_POSTFIX "_debug")

# Set the VERSION and SOVERSION properties for semantic versioning.
# set_target_properties(cppvrf PROPERTIES
#     VERSION ${cppvrf_VERSION}
#     SOVERSION ${cppvrf_VERSION_MAJOR}
# )

# Set our include directories.
target_include_directories(cppvrf PUBLIC
    $<BUILD_INTERFACE:${cppvrf_INCLUDES_DIR}>
    $<INSTALL_INTERFACE:${cppvrf_INCLUDES_INSTALL_DIR}>
)

# Create an export set for cppvrf.
install(TARGETS cppvrf
    EXPORT cppvrfTargets
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}/cppvrf-${cppvrf_VERSION_MM}"
)

# Create the CMake config file.
include(CMakePackageConfigHelpers)
configure_package_config_file(
    "${cppvrf_CONFIG_IN_FILENAME}" "${cppvrf_CONFIG_FILENAME}"
    INSTALL_DESTINATION "${cppvrf_CONFIG_INSTALL_DIR}"
    PATH_VARS cppvrf_INCLUDES_INSTALL_DIR
)

install(
    EXPORT cppvrfTargets
    NAMESPACE cppvrf::
    DESTINATION "${cppvrf_CONFIG_INSTALL_DIR}"
)

# Create a version file.
write_basic_package_version_file(
    "${cppvrf_CONFIG_VERSION_FILENAME}"
    VERSION ${cppvrf_VERSION}
    COMPATIBILITY SameMajorVersion
)

# Install the CMake config file.
install(
    FILES "${cppvrf_CONFIG_FILENAME}" "${cppvrf_CONFIG_VERSION_FILENAME}"
    DESTINATION "${cppvrf_CONFIG_INSTALL_DIR}"
)

# Export cppvrfTargets from the build tree so it can be used without installing.
export(
    EXPORT cppvrfTargets
    NAMESPACE cppvrf::
    FILE "${cppvrf_TARGETS_FILENAME}"
)

# Test suite.
if(CPPVRF_BUILD_TESTS)
    find_package(GTest CONFIG REQUIRED)

    set(cppvrf_TESTS_FILES "")
    add_subdirectory(tests)

    add_executable(vrf_tests ${cppvrf_TESTS_FILES})
    target_link_libraries(vrf_tests PRIVATE
        cppvrf
        GTest::gtest
    )
endif()

# Benchmark suite.
if(CPPVRF_BUILD_BENCHMARKS)
    find_package(benchmark REQUIRED)

    set(cppvrf_BENCHMARKS_FILES "")
    add_subdirectory(benchmarks)

    add_executable(vrf_benchmarks ${cppvrf_BENCHMARKS_FILES})
    target_link_libraries(vrf_benchmarks PRIVATE
        cppvrf
        benchmark::benchmark
    )
endif()
