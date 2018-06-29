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

#ifndef OTRNG_RECEIVE_H
#define OTRNG_RECEIVE_H

#include "error.h"
#include "protocol.h"
#include "send.h"
#include "shared.h"

//#include "dake_protocol.h"
//#include "prekey_ensemble.h"
//#include "tlv.h"

INTERNAL otrng_err otrng_receive_defragmented_message(
    otrng_response_s *response, otrng_notif notif, const string_p message,
    otrng_s *otr);

#endif
