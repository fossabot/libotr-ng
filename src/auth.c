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

#define OTRNG_AUTH_PRIVATE

#include "auth.h"
#include "constants.h"
#include "random.h"
#include "shake.h"

INTERNAL void otrng_generate_keypair(rsig_pubkey_t pub, rsig_privkey_t priv) {
  ed448_random_scalar(priv);
  goldilocks_448_point_scalarmul(pub, goldilocks_448_point_base, priv);
}

INTERNAL void otrng_rsig_keypair_generate(rsig_keypair_t *keypair) {
  otrng_generate_keypair(keypair->pub, keypair->priv);
}

static const unsigned char base_point_bytes_dup[ED448_POINT_BYTES] = {
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x00,
};

/* in big endian */
static const unsigned char prime_order_bytes_dup[ED448_SCALAR_BYTES] = {
    0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x7c, 0xca, 0x23, 0xe9, 0xc4, 0x4e, 0xdb, 0x49,
    0xae, 0xd6, 0x36, 0x90, 0x21, 0x6c, 0xc2, 0x72, 0x8d, 0xc5, 0x8f, 0x55,
    0x23, 0x78, 0xc2, 0x92, 0xab, 0x58, 0x44, 0xf3,
};

INTERNAL void otrng_rsig_authenticate(ring_sig_t *dst,
                                      const rsig_keypair_t *keypair,
                                      const rsig_pubkey_t A2,
                                      const rsig_pubkey_t A3,
                                      const unsigned char *msg, size_t msglen) {

  goldilocks_shake256_ctx_t hd;
  uint8_t hash[HASH_BYTES];
  unsigned char point_buff[ED448_POINT_BYTES];

  rsig_privkey_t t1;
  rsig_pubkey_t T1, T2, T3, A2c2, A3c3;

  otrng_generate_keypair(T1, t1);

  otrng_generate_keypair(T2, dst->r2);
  ed448_random_scalar(dst->c2);
  goldilocks_448_point_scalarmul(A2c2, A2, dst->c2);
  goldilocks_448_point_add(T2, T2, A2c2);

  otrng_generate_keypair(T3, dst->r3);
  ed448_random_scalar(dst->c3);
  goldilocks_448_point_scalarmul(A3c3, A3, dst->c3);
  goldilocks_448_point_add(T3, T3, A3c3);

  hash_init_with_dom(hd);
  hash_update(hd, base_point_bytes_dup, ED448_POINT_BYTES);
  hash_update(hd, prime_order_bytes_dup, ED448_SCALAR_BYTES);

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff,
                                                          keypair->pub);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, A2);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, A3);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, T1);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, T2);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, T3);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  hash_update(hd, msg, msglen);

  hash_final(hd, hash, sizeof(hash));
  hash_destroy(hd);

  rsig_privkey_t c, c1a1;
  goldilocks_448_scalar_decode_long(c, hash, ED448_SCALAR_BYTES);

  goldilocks_448_scalar_sub(dst->c1, c, dst->c2);
  goldilocks_448_scalar_sub(dst->c1, dst->c1, dst->c3);

  goldilocks_448_scalar_mul(c1a1, dst->c1, keypair->priv);
  goldilocks_448_scalar_sub(dst->r1, t1, c1a1);
}

INTERNAL otrng_bool_t otrng_rsig_verify(
    const ring_sig_t *src, const rsig_pubkey_t A1, const rsig_pubkey_t A2,
    const rsig_pubkey_t A3, const unsigned char *msg, size_t msglen) {

  goldilocks_shake256_ctx_t hd;
  uint8_t hash[HASH_BYTES];
  unsigned char point_buff[ED448_POINT_BYTES];

  hash_init_with_dom(hd);

  rsig_pubkey_t gr1, gr2, gr3, A1c1, A2c2, A3c3;

  goldilocks_448_point_scalarmul(gr1, goldilocks_448_point_base, src->r1);
  goldilocks_448_point_scalarmul(gr2, goldilocks_448_point_base, src->r2);
  goldilocks_448_point_scalarmul(gr3, goldilocks_448_point_base, src->r3);

  goldilocks_448_point_scalarmul(A1c1, A1, src->c1);
  goldilocks_448_point_scalarmul(A2c2, A2, src->c2);
  goldilocks_448_point_scalarmul(A3c3, A3, src->c3);

  goldilocks_448_point_add(A1c1, A1c1, gr1);
  goldilocks_448_point_add(A2c2, A2c2, gr2);
  goldilocks_448_point_add(A3c3, A3c3, gr3);

  hash_update(hd, base_point_bytes_dup, ED448_POINT_BYTES);
  hash_update(hd, prime_order_bytes_dup, ED448_SCALAR_BYTES);

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, A1);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, A2);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, A3);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, A1c1);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, A2c2);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, A3c3);
  hash_update(hd, point_buff, ED448_POINT_BYTES);

  hash_update(hd, msg, msglen);

  hash_final(hd, hash, sizeof(hash));
  hash_destroy(hd);

  rsig_privkey_t c, c1c2c3;
  goldilocks_448_scalar_decode_long(c, hash, ED448_SCALAR_BYTES);

  goldilocks_448_scalar_add(c1c2c3, src->c1, src->c2);
  goldilocks_448_scalar_add(c1c2c3, c1c2c3, src->c3);

  if (GOLDILOCKS_TRUE == goldilocks_448_scalar_eq(c, c1c2c3))
    return otrng_true;

  return otrng_false;
}

INTERNAL void otrng_ring_sig_destroy(ring_sig_t *src) {
  otrng_ec_scalar_destroy(src->c1);
  otrng_ec_scalar_destroy(src->r1);
  otrng_ec_scalar_destroy(src->c2);
  otrng_ec_scalar_destroy(src->r2);
  otrng_ec_scalar_destroy(src->c3);
  otrng_ec_scalar_destroy(src->r3);
}
