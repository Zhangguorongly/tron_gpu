#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <cuda_runtime.h>
#include "tron.h"

// GPU 内核 - 每个线程生成一个私钥并检查地址
__global__ void search_tron_vanity(uint64_t start_nonce, int target_len, int *found, char *found_priv, char *found_addr) {
    uint64_t idx = blockIdx.x * blockDim.x + threadIdx.x + start_nonce;
    if (*found) return;

    uint8_t priv[32];
    gen_private_key(idx, priv);

    char addr[40];
    tron_address_from_priv(priv, addr);

    // 检查尾部是否全相等
    int len = strlen(addr);
    bool match = true;
    char last = addr[len - 1];
    for (int i = len - target_len; i < len; i++) {
        if (addr[i] != last) { match = false; break; }
    }

    if (match) {
        if (atomicCAS(found, 0, 1) == 0) {
            priv_to_hex(priv, found_priv);
            strcpy(found_addr, addr);
        }
    }
}

int main() {
    int N;
    std::cout << "输入尾部连续位数 N: ";
    std::cin >> N;

    int threads_per_block = 256;
    int blocks = 1024; // 每批生成 256 * 1024 ≈ 26 万个私钥

    int *d_found;
    char *d_priv, *d_addr;
    cudaMallocManaged(&d_found, sizeof(int));
    cudaMallocManaged(&d_priv, 65);
    cudaMallocManaged(&d_addr, 50);
    *d_found = 0;

    uint64_t nonce = 0;
    auto start = std::chrono::high_resolution_clock::now();

    while (!*d_found) {
        search_tron_vanity<<<blocks, threads_per_block>>>(nonce, N, d_found, d_priv, d_addr);
        cudaDeviceSynchronize();
        nonce += (uint64_t)threads_per_block * blocks;
    }

    auto end = std::chrono::high_resolution_clock::now();
    double secs = std::chrono::duration<double>(end - start).count();

    std::cout << "\n=== 找到匹配地址 ===\n";
    std::cout << "私钥(hex): " << d_priv << "\n";
    std::cout << "TRON 地址: " << d_addr << "\n";
    std::cout << "用时: " << secs << " 秒\n";

    FILE *fp = fopen("found.txt", "w");
    if (fp) {
        fprintf(fp, "Private Key: %s\nAddress: %s\n", d_priv, d_addr);
        fclose(fp);
    }

    cudaFree(d_found);
    cudaFree(d_priv);
    cudaFree(d_addr);
    return 0;
}
