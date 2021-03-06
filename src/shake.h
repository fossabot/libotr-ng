/*
 *  This file is part of the Off-the-Record Next Generation Messaging
 *  library (libotr-ng).
 *
 *  Copyright (C) 2016-2018, the libotr-ng contributors.
 *
 *  This library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef OTRNG_SHAKE_H
#define OTRNG_SHAKE_H

#include "goldilocks/shake.h"
#include "shared.h"

#define hash_init goldilocks_shake256_init
#define hash_update goldilocks_shake256_update
#define hash_final goldilocks_shake256_final
#define hash_destroy goldilocks_shake256_destroy
#define hash_hash goldilocks_shake256_hash

void hash_init_with_dom(goldilocks_shake256_ctx_p hash);

void hash_init_with_usage(goldilocks_shake256_ctx_p hash, uint8_t usage);

void shake_kkdf(uint8_t *dst, size_t dstlen, const uint8_t *key, size_t keylen,
                const uint8_t *secret, size_t secretlen);

static inline void shake_256_mac(uint8_t *dst, size_t dstlen,
                                 const uint8_t *key, size_t keylen,
                                 const uint8_t *msg, size_t msglen) {
  shake_kkdf(dst, dstlen, key, keylen, msg, msglen);
}

static inline void shake_256_kdf(uint8_t *key, size_t keylen,
                                 const uint8_t magic[1], const uint8_t *secret,
                                 size_t secretlen) {
  shake_kkdf(key, keylen, magic, 1, secret, secretlen);
}

// KDF_1(usageID || values, 64)
void shake_256_kdf1(uint8_t *dst, size_t dstlen, uint8_t usage,
                    const uint8_t *values, size_t valueslen);

void shake_256_hash(uint8_t *dst, size_t dstlen, const uint8_t *secret,
                    size_t secretlen);

#endif
