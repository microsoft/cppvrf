# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Check that this CMake file is not invoked directly.
if("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_CURRENT_SOURCE_DIR}")
    message(FATAL_ERROR "${CMAKE_CURRENT_LIST_FILE} must not be invoked directly.")
endif()

# Add the source files from this directory.
set(cppvrf_SOURCE_FILES ${cppvrf_SOURCE_FILES}
    "${CMAKE_CURRENT_LIST_DIR}/keys.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/params.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/rsavrf.cpp"
)

install(
    FILES
        "${CMAKE_CURRENT_LIST_DIR}/keys.h"
        "${CMAKE_CURRENT_LIST_DIR}/params.h"
        "${CMAKE_CURRENT_LIST_DIR}/rsavrf.h"
    DESTINATION
        "${cppvrf_INCLUDES_INSTALL_DIR}/vrf/rsa"
)

# Update cppvrf_SOURCE_FILES variable in the parent scope.
set(cppvrf_SOURCE_FILES ${cppvrf_SOURCE_FILES} PARENT_SCOPE)