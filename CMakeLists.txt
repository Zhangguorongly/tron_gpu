cmake_minimum_required(VERSION 3.20)
project(tron_gpu LANGUAGES C CXX CUDA)

# CUDA
enable_language(CUDA)
set(CMAKE_CUDA_STANDARD 14)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)
# 允许在 .cu 里使用 C 头
set(CMAKE_CUDA_SEPARABLE_COMPILATION ON)

# OpenSSL（通过 vcpkg 提供）
find_package(OpenSSL REQUIRED)

# 源文件
add_executable(tron_gpu
    main.cu
    tron.cpp
    tron.h
    keccak.c
    keccak.h
    base58.c
    base58.h
)

# 如果用到 C 运行库函数，在 Windows 上需要这个定义避免不必要警告
target_compile_definitions(tron_gpu PRIVATE _CRT_SECURE_NO_WARNINGS)

# 链接 CUDA 运行时 + OpenSSL
find_package(CUDAToolkit REQUIRED)
target_link_libraries(tron_gpu PRIVATE CUDA::cudart OpenSSL::Crypto OpenSSL::SSL)

# Windows 上把可执行文件放到 build/Release 目录
set_target_properties(tron_gpu PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release"
)
