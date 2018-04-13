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

#ifndef OTRNG_CONSTANTS_H
#define OTRNG_CONSTANTS_H

#define VERSION 4
#define IDENTITY_MSG_TYPE 0x08
#define AUTH_R_MSG_TYPE 0x91
#define AUTH_I_MSG_TYPE 0x88
#define PRE_KEY_MSG_TYPE 0x0F
#define NON_INT_AUTH_MSG_TYPE 0x8D
#define DATA_MSG_TYPE 0x03

#define DAKE_HEADER_BYTES (2 + 1 + 4 + 4)
#define HASH_BYTES 64

/* size of IDENTITY_MESSAGE without user_profile */
#define IDENTITY_MIN_BYTES                                                     \
  (DAKE_HEADER_BYTES + ED448_POINT_BYTES + DH_MPI_BYTES)
#define PRE_KEY_MIN_BYTES (DAKE_HEADER_BYTES + ED448_POINT_BYTES + DH_MPI_BYTES)

#define AUTH_R_MIN_BYTES                                                       \
  (DAKE_HEADER_BYTES + ED448_POINT_BYTES + DH_MPI_BYTES + SNIZKPK_BYTES)

#define NON_INT_AUTH_BYTES                                                     \
  (DAKE_HEADER_BYTES + ED448_POINT_BYTES + DH_MPI_BYTES + SNIZKPK_BYTES +      \
   HASH_BYTES)

#define DATA_MSG_NONCE_BYTES crypto_secretbox_NONCEBYTES
#define DATA_MSG_MAC_BYTES 64
#define MAC_KEY_BYTES 64
#define BRACE_KEY_BYTES 32
#define SHARED_SECRET_BYTES 64
#define CHAIN_KEY_BYTES 64
#define ROOT_KEY_BYTES 64

#define DATA_MESSAGE_MIN_BYTES                                                 \
  (DAKE_HEADER_BYTES + 1 + 4 + ED448_POINT_BYTES + DATA_MSG_NONCE_BYTES)

#define MSGFLAGS_IGNORE_UNREADABLE 0x01

#endif
