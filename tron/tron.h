#pragma once
#include <stdint.h>

void gen_private_key(uint64_t nonce, uint8_t priv[32]);
void priv_to_hex(const uint8_t priv[32], char hexstr[65]);
void tron_address_from_priv(const uint8_t priv[32], char addr[40]);
