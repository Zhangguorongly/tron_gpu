#include "tron.h"
#include <string.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include "keccak.h"
#include "base58.h"

void gen_private_key(uint64_t nonce, uint8_t priv[32]) {
    RAND_bytes(priv, 32);
    // 这里也可以替换为由 nonce 生成的确定性私钥
}

void priv_to_hex(const uint8_t priv[32], char hexstr[65]) {
    for (int i = 0; i < 32; i++) {
        sprintf(hexstr + i*2, "%02x", priv[i]);
    }
    hexstr[64] = '\0';
}

void tron_address_from_priv(const uint8_t priv[32], char addr[40]) {
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    BIGNUM *priv_bn = BN_bin2bn(priv, 32, NULL);
    EC_KEY_set_private_key(eckey, priv_bn);

    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    EC_POINT *pub_point = EC_POINT_new(group);
    EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, NULL);
    EC_KEY_set_public_key(eckey, pub_point);

    uint8_t pub[65];
    size_t publen = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, pub, sizeof(pub), NULL);

    uint8_t hash[32];
    keccak_256(pub + 1, 64, hash);

    uint8_t tron_raw[21];
    tron_raw[0] = 0x41;
    memcpy(tron_raw + 1, hash + 12, 20);

    uint8_t checksum_full[32];
    SHA256(tron_raw, 21, checksum_full);
    SHA256(checksum_full, 32, checksum_full);

    uint8_t addr_bytes[25];
    memcpy(addr_bytes, tron_raw, 21);
    memcpy(addr_bytes + 21, checksum_full, 4);

    b58enc(addr, NULL, addr_bytes, 25);

    EC_POINT_free(pub_point);
    BN_free(priv_bn);
    EC_KEY_free(eckey);
}
