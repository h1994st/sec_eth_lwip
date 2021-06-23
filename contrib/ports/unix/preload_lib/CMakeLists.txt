cmake_minimum_required(VERSION 3.10)

project(lwip_preload C)

set (BUILD_SHARED_LIBS ON)

if (NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_SYSTEM_NAME STREQUAL "GNU")
    message(FATAL_ERROR "Lwip shared library is only working on Linux or the Hurd")
endif()

set(LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../..)
include(${LWIP_DIR}/contrib/ports/CMakeCommon.cmake)

set (LWIP_DEFINITIONS -DLWIP_DEBUG)
set (LWIP_INCLUDE_DIRS
    "${LWIP_DIR}/src/include"
    "${LWIP_CONTRIB_DIR}/"
    "${LWIP_CONTRIB_DIR}/ports/unix/port/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/"
    "/usr/local/include"
)

include(${LWIP_CONTRIB_DIR}/ports/unix/Filelists.cmake)
include(${LWIP_DIR}/src/Filelists.cmake)

add_library(lwip_preload lwip_preload.c socket_overrides.c ${lwipnoapps_SRCS} ${lwipcontribportunix_SRCS} ${lwipcontribportunixnetifs_SRCS})
target_compile_options(lwip_preload PRIVATE ${LWIP_COMPILER_FLAGS})
target_compile_definitions(lwip_preload PRIVATE ${LWIP_DEFINITIONS} ${LWIP_MBEDTLS_DEFINITIONS})
target_include_directories(lwip_preload PRIVATE ${LWIP_INCLUDE_DIRS} ${LWIP_MBEDTLS_INCLUDE_DIRS})
target_link_libraries(lwip_preload ${LWIP_SANITIZER_LIBS} -ldl -lwolfssl)

find_library(LIBPTHREAD pthread)
target_link_libraries(lwip_preload ${LIBPTHREAD})

# Gatekeeper - sender
add_library(lwip_gk_sender lwip_preload.c socket_overrides.c ${lwipnoapps_SRCS} ${lwipcontribportunix_SRCS} ${lwipcontribportunixnetifs_SRCS})
target_compile_options(lwip_gk_sender PRIVATE ${LWIP_COMPILER_FLAGS})
target_compile_definitions(lwip_gk_sender PRIVATE -DLWIP_GATEKEEPER=1 -DLWIP_GK_ROLE=0 ${LWIP_DEFINITIONS} ${LWIP_MBEDTLS_DEFINITIONS})
target_include_directories(lwip_gk_sender PRIVATE ${LWIP_INCLUDE_DIRS} ${LWIP_MBEDTLS_INCLUDE_DIRS})
target_link_libraries(lwip_gk_sender ${LWIP_SANITIZER_LIBS} -ldl -lwolfssl ${LIBPTHREAD})

# Gatekeeper - receiver
add_library(lwip_gk_receiver lwip_preload.c socket_overrides.c ${lwipnoapps_SRCS} ${lwipcontribportunix_SRCS} ${lwipcontribportunixnetifs_SRCS})
target_compile_options(lwip_gk_receiver PRIVATE ${LWIP_COMPILER_FLAGS})
target_compile_definitions(lwip_gk_receiver PRIVATE -DLWIP_GATEKEEPER=1 -DLWIP_GK_ROLE=1 ${LWIP_DEFINITIONS} ${LWIP_MBEDTLS_DEFINITIONS})
target_include_directories(lwip_gk_receiver PRIVATE ${LWIP_INCLUDE_DIRS} ${LWIP_MBEDTLS_INCLUDE_DIRS})
target_link_libraries(lwip_gk_receiver ${LWIP_SANITIZER_LIBS} -ldl -lwolfssl ${LIBPTHREAD})

# IPsec
add_library(lwip_ipsec lwip_preload.c socket_overrides.c ${lwipnoapps_SRCS} ${lwipcontribportunix_SRCS} ${lwipcontribportunixnetifs_SRCS})
target_compile_options(lwip_ipsec PRIVATE ${LWIP_COMPILER_FLAGS})
target_compile_definitions(lwip_ipsec PRIVATE -DEIPS=1 ${LWIP_DEFINITIONS} ${LWIP_MBEDTLS_DEFINITIONS})
target_include_directories(lwip_ipsec PRIVATE ${LWIP_INCLUDE_DIRS} ${LWIP_MBEDTLS_INCLUDE_DIRS})
target_link_libraries(lwip_ipsec ${LWIP_SANITIZER_LIBS} -ldl -lwolfssl ${LIBPTHREAD})

# MACsec
add_library(lwip_macsec lwip_preload.c socket_overrides.c ${lwipnoapps_SRCS} ${lwipcontribportunix_SRCS} ${lwipcontribportunixnetifs_SRCS})
target_compile_options(lwip_macsec PRIVATE ${LWIP_COMPILER_FLAGS})
target_compile_definitions(lwip_macsec PRIVATE -DMACSEC=1 ${LWIP_DEFINITIONS} ${LWIP_MBEDTLS_DEFINITIONS})
target_include_directories(lwip_macsec PRIVATE ${LWIP_INCLUDE_DIRS} ${LWIP_MBEDTLS_INCLUDE_DIRS})
target_link_libraries(lwip_macsec ${LWIP_SANITIZER_LIBS} -ldl -lwolfssl ${LIBPTHREAD})
