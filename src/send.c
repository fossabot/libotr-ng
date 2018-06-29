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

#include "send.h"

INTERNAL otrng_err otrng_send_message(char **to_send, const char *message,
                                      otrng_notif notif, const tlv_list_s *tlvs,
                                      uint8_t flags, otrng_s *otr) {
  if (!otr) {
    return ERROR;
  }

  switch (otr->running_version) {
  case 3:
    return otrng_v3_send_message(to_send, message, tlvs, otr->v3_conn);
  case 4:
    return otrng_prepare_to_send_data_message(to_send, notif, message, tlvs,
                                              otr, flags);
  case 0:
    return ERROR;
  }

  return SUCCESS;
}
