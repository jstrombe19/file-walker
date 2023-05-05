cmake_minimum_required(VERSION 3.1)
project(file_maker VERSION 1.0)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

add_executable(file_maker
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/utils.c
)

target_include_directories(file_maker PUBLIC ${OPENSSL_INCLUDE_DIR} ${ZLIB_LIBRARIES})
target_link_libraries(file_maker PUBLIC OpenSSL::SSL OpenSSL::Crypto)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -pedantic")

set_target_properties(file_maker PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib
)
