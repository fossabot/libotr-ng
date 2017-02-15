#include "data_message.h"
#include "serialize.h"
#include "deserialize.h"
#include "constants.h"

data_message_t*
data_message_new() {
  data_message_t *ret = malloc(sizeof(data_message_t));
  if (ret == NULL)
    return NULL;

  ret->flags = 0;
  ret->enc_msg = NULL;
  ret->enc_msg_len = 0;
  ret->old_mac_keys = NULL;
  ret->old_mac_keys_len = 0;
  return ret;
}

void
data_message_free(data_message_t *data_msg) {
  if (data_msg == NULL)
    return;

  data_msg->enc_msg_len = 0;
  free(data_msg->enc_msg);
  data_msg->enc_msg = NULL;

  data_msg->old_mac_keys = 0;
  free(data_msg->old_mac_keys);
  data_msg->old_mac_keys = NULL;
}

bool
data_message_body_aprint(uint8_t **body, size_t *bodylen, const data_message_t *data_msg) {
  size_t s = DATA_MESSAGE_MIN_BYTES+4+data_msg->enc_msg_len;
  uint8_t *dst = malloc(s);
  if (dst == NULL)
    return false;

  uint8_t *cursor = dst;
  cursor += serialize_uint16(cursor, OTR_VERSION);
  cursor += serialize_uint8(cursor, OTR_DATA_MSG_TYPE);
  cursor += serialize_uint32(cursor, data_msg->sender_instance_tag);
  cursor += serialize_uint32(cursor, data_msg->receiver_instance_tag);
  cursor += serialize_uint8(cursor, data_msg->flags);
  cursor += serialize_uint32(cursor, data_msg->ratchet_id);
  cursor += serialize_uint32(cursor, data_msg->message_id);
  cursor += serialize_ec_public_key(cursor, data_msg->our_ecdh);
  cursor += serialize_dh_public_key(cursor, data_msg->our_dh);
  cursor += serialize_bytes_array(cursor, data_msg->nonce, DATA_MSG_NONCE_BYTES);
  cursor += serialize_data(cursor, data_msg->enc_msg, data_msg->enc_msg_len);

  *body = dst;
  *bodylen = s;

  return true;
}

bool
data_message_deserialize(data_message_t *dst, uint8_t *buff, size_t bufflen) {
  const uint8_t *cursor = buff;
  int64_t len = bufflen;
  size_t read = 0;

  uint16_t protocol_version = 0;
  if(!deserialize_uint16(&protocol_version, cursor, len, &read)) {
    return false;
  }

  cursor += read;
  len -= read;

  if (protocol_version != OTR_VERSION) {
    return false;
  }

  uint8_t message_type = 0;
  if(!deserialize_uint8(&message_type, cursor, len, &read)) {
    return false;
  }

  cursor += read;
  len -= read;

  if (message_type != OTR_DATA_MSG_TYPE) {
    return false;
  }

  if(!deserialize_uint32(&dst->sender_instance_tag, cursor, len, &read)) {
    return false;
  }

  cursor += read;
  len -= read;

  if(!deserialize_uint32(&dst->receiver_instance_tag, cursor, len, &read)) {
    return false;
  }

  cursor += read;
  len -= read;

  if(!deserialize_uint8(&dst->flags, cursor, len, &read)) {
    return false;
  }

  cursor += read;
  len -= read;

  if(!deserialize_uint32(&dst->ratchet_id, cursor, len, &read)) {
    return false;
  }

  cursor += read;
  len -= read;

  if(!deserialize_uint32(&dst->message_id, cursor, len, &read)) {
    return false;
  }

  cursor += read;
  len -= read;

  if (!deserialize_ec_public_key(dst->our_ecdh, cursor, len, &read)) {
    return false;
  }

  cursor += read;
  len -= read;

  otr_mpi_t b_mpi; // no need to free, because nothing is copied now
  if (!otr_mpi_deserialize_no_copy(b_mpi, cursor, len, &read)) {
    return false;
  }

  cursor += read;
  len -= read;

  if (!dh_mpi_deserialize(&dst->our_dh, b_mpi->data, b_mpi->len, &read)) {
    return false;
  }

  cursor += read;
  len -= read;

  if (!deserialize_bytes_array((uint8_t*) &dst->nonce, DATA_MSG_NONCE_BYTES, cursor, len)) {
    return false;
  }

  cursor += DATA_MSG_NONCE_BYTES;
  len -= DATA_MSG_NONCE_BYTES;

  if (!deserialize_data(&dst->enc_msg, cursor, len, &read)) {
    return false;
  }

  dst->enc_msg_len = read-4;
  cursor += read;
  len -= read;

  if (!deserialize_bytes_array((uint8_t*) &dst->mac, DATA_MSG_MAC_BYTES, cursor, len)) {
    return false;
  }

  return true;
}

bool
data_message_validate(m_mac_key_t mac_key, const data_message_t *data_msg) {
  uint8_t *body = NULL;
  size_t bodylen = 0;

  if(!data_message_body_aprint(&body, &bodylen, data_msg)) {
    return false;
  }

  size_t mac_tag[DATA_MSG_MAC_BYTES];
  if (!sha3_512_mac((uint8_t*) mac_tag, DATA_MSG_MAC_BYTES, mac_key, sizeof(m_mac_key_t), body, bodylen)) {
    free(body);
    return false;
  }

  free(body);

  //TODO: Make constant time
  if (0 != memcmp(mac_tag, data_msg->mac, DATA_MSG_MAC_BYTES)) {
    return false;
  }

  ec_point_t y;
  if (!ec_point_deserialize(y, data_msg->our_ecdh)) {
    return false;
  }

  return ec_point_valid(y) & dh_mpi_valid(data_msg->our_dh);
}
