# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Check that this CMake file is not invoked directly.
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
    message(FATAL_ERROR "${CMAKE_CURRENT_LIST_FILE} must not be invoked directly.")
endif()

set(cppvrf_TESTS_FILES ${cppvrf_TESTS_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/common_tests.cpp
    ${CMAKE_CURRENT_LIST_DIR}/log_tests.cpp
    ${CMAKE_CURRENT_LIST_DIR}/test_runner.cpp
    ${CMAKE_CURRENT_LIST_DIR}/utils.cpp
    ${CMAKE_CURRENT_LIST_DIR}/vrf_tests.cpp
)

# Update cppvrf_TESTS_FILES variable in the parent scope.
set(cppvrf_TESTS_FILES ${cppvrf_TESTS_FILES} PARENT_SCOPE)