#include "base58.h"
#include <string.h>

static const char b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

int b58enc(char *b58, size_t *b58sz, const void *data, size_t binsz) {
    const uint8_t *bin = (const uint8_t *)data;
    size_t i, j, high, zcount = 0;
    size_t size;
    uint32_t carry;
    uint8_t buf[128];

    while (zcount < binsz && !bin[zcount])
        ++zcount;

    size = (binsz - zcount) * 138 / 100 + 1;
    memset(buf, 0, size);

    for (i = zcount; i < binsz; ++i) {
        carry = bin[i];
        for (j = size; j--; ) {
            carry += ((uint32_t)buf[j]) << 8;
            buf[j] = carry % 58;
            carry /= 58;
        }
    }

    i = 0;
    while (i < size && !buf[i])
        ++i;

    if (*b58sz <= zcount + size - i)
        return 0;

    j = zcount;
    while (j--)
        *b58++ = '1';

    while (i < size)
        *b58++ = b58digits_ordered[buf[i++]];

    *b58 = '\0';
    *b58sz = zcount + size - i;
    return 1;
}
