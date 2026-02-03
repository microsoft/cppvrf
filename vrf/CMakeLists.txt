# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Check that this CMake file is not invoked directly.
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
    message(FATAL_ERROR "${CMAKE_CURRENT_LIST_FILE} must not be invoked directly.")
endif()

# Add the source files from this directory.
set(cppvrf_SOURCE_FILES ${cppvrf_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/bnconv.cpp
    ${CMAKE_CURRENT_LIST_DIR}/common.cpp
    ${CMAKE_CURRENT_LIST_DIR}/guards.cpp
    ${CMAKE_CURRENT_LIST_DIR}/hash.cpp
    ${CMAKE_CURRENT_LIST_DIR}/log.cpp
    ${CMAKE_CURRENT_LIST_DIR}/secure_buf.cpp
    ${CMAKE_CURRENT_LIST_DIR}/stdout_log.cpp
    ${CMAKE_CURRENT_LIST_DIR}/vrf.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/common.h
        ${CMAKE_CURRENT_LIST_DIR}/guards.h
        ${CMAKE_CURRENT_LIST_DIR}/log.h
        ${CMAKE_CURRENT_LIST_DIR}/secure_buf.h
        ${CMAKE_CURRENT_LIST_DIR}/type.h
        ${CMAKE_CURRENT_LIST_DIR}/vrf.h
        ${CMAKE_CURRENT_LIST_DIR}/vrf_base.h
    DESTINATION
        ${cppvrf_INCLUDES_INSTALL_DIR}/vrf
)

add_subdirectory(ec)
add_subdirectory(rsa)

# Update cppvrf_SOURCE_FILES variable in the parent scope.
set(cppvrf_SOURCE_FILES ${cppvrf_SOURCE_FILES} PARENT_SCOPE)
