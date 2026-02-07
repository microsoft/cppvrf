# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Check that this CMake file is not invoked directly.
if("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_CURRENT_SOURCE_DIR}")
    message(FATAL_ERROR "${CMAKE_CURRENT_LIST_FILE} must not be invoked directly.")
endif()

set(cppvrf_BENCHMARKS_FILES ${cppvrf_BENCHMARKS_FILES}
    "${CMAKE_CURRENT_LIST_DIR}/vrf_benchmarks.cpp"
)

# Update cppvrf_BENCHMARKS_FILES variable in the parent scope.
set(cppvrf_BENCHMARKS_FILES ${cppvrf_BENCHMARKS_FILES} PARENT_SCOPE)
