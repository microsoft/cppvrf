# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Check that this CMake file is not invoked directly.
if("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_CURRENT_SOURCE_DIR}")
    message(FATAL_ERROR "${CMAKE_CURRENT_LIST_FILE} must not be invoked directly.")
endif()

# Add the source files from this directory.
set(cppvrf_SOURCE_FILES ${cppvrf_SOURCE_FILES}
    "${CMAKE_CURRENT_LIST_DIR}/ecpoint.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/ecvrf.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/params.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/utils.cpp"
)

install(
    FILES
        "${CMAKE_CURRENT_LIST_DIR}/ecpoint.h"
        "${CMAKE_CURRENT_LIST_DIR}/ecvrf.h"
        "${CMAKE_CURRENT_LIST_DIR}/params.h"
        "${CMAKE_CURRENT_LIST_DIR}/utils.h"
    DESTINATION
        "${cppvrf_INCLUDES_INSTALL_DIR}/vrf/ec"
)

# Update cppvrf_SOURCE_FILES variable in the parent scope.
set(cppvrf_SOURCE_FILES ${cppvrf_SOURCE_FILES} PARENT_SCOPE)