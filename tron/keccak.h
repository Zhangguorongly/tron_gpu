#pragma once
#include <stdint.h>
#include <stddef.h>

#define KECCAK_DIGEST_SIZE 32

void keccak_256(const uint8_t *input, size_t inputSize, uint8_t *output);
