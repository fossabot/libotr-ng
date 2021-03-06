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

#ifndef OTRNG_DH_H
#define OTRNG_DH_H

#include <gcrypt.h>
#include <stdint.h>

#include "constants.h"
#include "error.h"
#include "shared.h"

#define DH_KEY_SIZE 80
#define DH3072_MOD_LEN_BITS 3072
// TODO: we have this constant defined twice
#define DH3072_MOD_LEN_BYTES 384
#define DH_MPI_MAX_BYTES (4 + DH3072_MOD_LEN_BYTES)

typedef gcry_mpi_t dh_mpi_p;
typedef dh_mpi_p dh_private_key_p, dh_public_key_p;
typedef uint8_t dh_shared_secret_p[DH3072_MOD_LEN_BYTES];

typedef struct dh_keypair_s {
  dh_public_key_p pub;
  dh_private_key_p priv;
} dh_keypair_s, dh_keypair_p[1];

INTERNAL void otrng_dh_init(void);

INTERNAL void otrng_dh_free(void);

INTERNAL otrng_err otrng_dh_keypair_generate(dh_keypair_p keypair);

/**
 * @param [participant]   If this corresponds to our or their key manager. 'u'
 * for us, 't' for them
 */
INTERNAL otrng_err otrng_dh_keypair_generate_from_shared_secret(
    uint8_t shared_secret[SHARED_SECRET_BYTES], dh_keypair_p keypair,
    const char participant);

INTERNAL void otrng_dh_priv_key_destroy(dh_keypair_p keypair);

INTERNAL void otrng_dh_keypair_destroy(dh_keypair_p keypair);

INTERNAL otrng_err otrng_dh_shared_secret(dh_shared_secret_p buffer,
                                          size_t *written,
                                          const dh_private_key_p our_priv,
                                          const dh_public_key_p their_pub);

INTERNAL otrng_err otrng_dh_mpi_serialize(uint8_t *dst, size_t dst_len,
                                          size_t *written, const dh_mpi_p src);

INTERNAL otrng_err otrng_dh_mpi_deserialize(dh_mpi_p *dst,
                                            const uint8_t *buffer,
                                            size_t buflen, size_t *nread);

INTERNAL otrng_bool otrng_dh_mpi_valid(dh_mpi_p mpi);

INTERNAL dh_mpi_p otrng_dh_mpi_copy(const dh_mpi_p src);

INTERNAL void otrng_dh_mpi_release(dh_mpi_p mpi);

#ifdef OTRNG_DH_PRIVATE

INTERNAL const dh_mpi_p otrng_dh_mpi_generator(void);

#endif

#endif
