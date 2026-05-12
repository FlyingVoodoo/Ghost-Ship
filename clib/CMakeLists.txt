cmake_minimum_required(VERSION 3.16)
project(GhostShip_Streamer CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -Wall -Wextra")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Find dependencies
find_package(OpenSSL 1.1.1 REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LZ4 REQUIRED liblz4)

# Streamer library
add_library(streamer STATIC
    streamer.cpp
)

target_include_directories(streamer PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${LZ4_INCLUDE_DIRS}
)

target_link_libraries(streamer PUBLIC
    OpenSSL::Crypto
    ${LZ4_LIBRARIES}
)

# Test executable
add_executable(streamer_test
    test.cpp
    streamer.cpp
)

target_include_directories(streamer_test PRIVATE
    ${OPENSSL_INCLUDE_DIR}
    ${LZ4_INCLUDE_DIRS}
)

target_link_libraries(streamer_test
    OpenSSL::Crypto
    ${LZ4_LIBRARIES}
)

# Benchmark executable
add_executable(streamer_bench
    benchmark.cpp
    streamer.cpp
)

target_include_directories(streamer_bench PRIVATE
    ${OPENSSL_INCLUDE_DIR}
    ${LZ4_INCLUDE_DIRS}
)

target_link_libraries(streamer_bench
    OpenSSL::Crypto
    ${LZ4_LIBRARIES}
)

# Install
install(TARGETS streamer DESTINATION lib)
install(FILES streamer.hpp DESTINATION include)

