#pragma once
#include <stdint.h>
#include <stddef.h>

int b58enc(char *b58, size_t *b58sz, const void *data, size_t binsz);
