cmake_minimum_required(VERSION 3.10)
project(tron_gpu)

find_package(CUDA REQUIRED)

include_directories(${CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES})
include_directories(${CMAKE_SOURCE_DIR})

set(CMAKE_CUDA_STANDARD 11)

add_executable(tron_gpu main.cu tron.cpp keccak.c base58.c)

target_link_libraries(tron_gpu ${CUDA_LIBRARIES} crypto ssl)
