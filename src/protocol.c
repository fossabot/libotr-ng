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

#include "protocol.h"

#include <libotr/b64.h>

#include "data_message.h"
#include "instance_tag.h"
#include "padding.h"
#include "random.h"
#include "serialize.h"

static otrng_conversation_state_s *
otrng_conversation_new(otrng_client_state_s *state) {
  otrng_conversation_state_s *conversation =
      malloc(sizeof(otrng_conversation_state_s));
  conversation->client = state;
  conversation->peer = NULL;

  return conversation;
}

INTERNAL int allow_version(const otrng_s *otr,
                           otrng_supported_version version) {
  return (otr->supported_versions & version);
}

INTERNAL otrng_response_s *otrng_response_new(void) {
  otrng_response_s *response = malloc(sizeof(otrng_response_s));
  if (!response) {
    return NULL;
  }

  response->to_display = NULL;
  response->to_send = NULL;
  response->warning = OTRNG_WARN_NONE;
  response->tlvs = NULL;

  return response;
}

INTERNAL void otrng_response_free(otrng_response_s *response) {
  if (!response) {
    return;
  }

  if (response->to_display) {
    free(response->to_display);
  }

  if (response->to_send) {
    free(response->to_send);
  }

  otrng_tlv_list_free(response->tlvs);

  free(response);
}

INTERNAL otrng_s *otrng_new(otrng_client_state_s *state,
                            otrng_policy_s policy) {
  otrng_s *otr = malloc(sizeof(otrng_s));
  if (!otr) {
    return NULL;
  }

  otr->conversation = otrng_conversation_new(state);
  otr->state = OTRNG_STATE_START;
  otr->running_version = 0;
  otr->supported_versions = policy.allows;

  otr->their_instance_tag = 0;
  otr->our_instance_tag = otrng_client_state_get_instance_tag(state);

  otr->their_prekeys_id = 0;
  otr->their_client_profile = NULL;
  otr->their_prekey_profile = NULL;

  otr->keys = otrng_key_manager_new();
  otrng_smp_protocol_init(otr->smp);

  otr->pending_fragments = NULL;
  otr->v3_conn = NULL;

  otr->ignore_msg = 0;

  otr->shared_session_state = NULL;
  otr->sending_init_msg = NULL;
  otr->receiving_init_msg = NULL;

  return otr;
}

static void free_fragment_context(void *p) { otrng_fragment_context_free(p); }

INTERNAL void otrng_destroy(/*@only@ */ otrng_s *otr) {
  if (otr->conversation) {
    free(otr->conversation->peer);
    free(otr->conversation);
    otr->conversation = NULL;
  }

  otrng_key_manager_free(otr->keys);
  otr->keys = NULL;

  otrng_client_profile_free(otr->their_client_profile);
  otr->their_client_profile = NULL;

  otrng_prekey_profile_free(otr->their_prekey_profile);
  otr->their_prekey_profile = NULL;

  otrng_smp_destroy(otr->smp);

  otrng_list_free(otr->pending_fragments, free_fragment_context);
  otr->pending_fragments = NULL;

  otrng_v3_conn_free(otr->v3_conn);
  otr->v3_conn = NULL;

  free(otr->shared_session_state);
  otr->shared_session_state = NULL;

  // TODO: @freeing should we free this after being used by phi?
  free(otr->sending_init_msg);
  otr->sending_init_msg = NULL;

  // TODO: @freeing should we free this after being used by phi?;
  free(otr->receiving_init_msg);
  otr->receiving_init_msg = NULL;
}

INTERNAL void otrng_free(/*@only@ */ otrng_s *otr) {
  if (!otr) {
    return;
  }

  otrng_destroy(otr);
  free(otr);
}

INTERNAL otrng_err generate_phi_serialized(uint8_t **dst, size_t *dst_len,
                                           const char *phi_prime,
                                           const char *init_msg,
                                           uint16_t instance_tag1,
                                           uint16_t instance_tag2) {

  if (!phi_prime) {
    return ERROR;
  }

  /*
   * phi = smaller instance tag || larger instance tag || DATA(query message)
   *       || phi'
   */
  size_t init_msg_len = init_msg ? strlen(init_msg) + 1 : 0;
  size_t phi_prime_len = strlen(phi_prime) + 1;
  size_t s = 4 + 4 + (4 + init_msg_len) + (4 + phi_prime_len);
  *dst = malloc(s);
  if (!*dst) {
    return ERROR;
  }

  *dst_len = otrng_serialize_phi(*dst, phi_prime, init_msg, instance_tag1,
                                 instance_tag2);

  return SUCCESS;
}

tstatic otrng_shared_session_state_s
otrng_get_shared_session_state_cb(otrng_s *otr) {
  // TODO: this callback is required, so it will segfault if not provided
  return otr->conversation->client->callbacks->get_shared_session_state(
      otr->conversation);
}

INTERNAL const char *otrng_get_shared_session_state(otrng_s *otr) {
  if (otr->shared_session_state) {
    return otr->shared_session_state;
  }

  otrng_shared_session_state_s state = otrng_get_shared_session_state_cb(otr);
  otr->shared_session_state = otrng_generate_session_state_string(&state);

  free(state.identifier1);
  free(state.identifier2);
  free(state.password);

  return otr->shared_session_state;
}

tstatic void create_privkey_cb_v4(const otrng_conversation_state_s *conv) {
  if (!conv || !conv->client || !conv->client->callbacks) {
    return;
  }

  // TODO: @client Change to receive conv->client
  conv->client->callbacks->create_privkey(conv->client->client_id);
}

tstatic void create_shared_prekey(const otrng_conversation_state_s *conv) {
  if (!conv || !conv->client || !conv->client->callbacks) {
    return;
  }

  // TODO: @client The callback may not be invoked at all if the mode does not
  // support non-interactive DAKE, but this is for later.
  conv->client->callbacks->create_shared_prekey(conv);
}

INTERNAL otrng_err received_sender_instance_tag(uint32_t their_instance_tag,
                                                otrng_s *otr) {
  if (!valid_instance_tag(their_instance_tag)) {
    return ERROR;
  }

  otr->their_instance_tag = their_instance_tag;

  return SUCCESS;
}

INTERNAL void maybe_create_keys(const otrng_conversation_state_s *conv) {
  if (!conv->client->keypair) {
    create_privkey_cb_v4(conv);
  }

  if (!conv->client->shared_prekey_pair) {
    create_shared_prekey(conv);
  }
}

INTERNAL struct goldilocks_448_point_s *our_ecdh(const otrng_s *otr) {
  return &otr->keys->our_ecdh->pub[0];
}

INTERNAL struct goldilocks_448_point_s *their_ecdh(const otrng_s *otr) {
  return &otr->keys->their_ecdh[0];
}

INTERNAL dh_public_key_p our_dh(const otrng_s *otr) {
  return otr->keys->our_dh->pub;
}

INTERNAL dh_public_key_p their_dh(const otrng_s *otr) {
  return otr->keys->their_dh;
}

INTERNAL void forget_our_keys(otrng_s *otr) {
  otrng_key_manager_destroy(otr->keys);
  otrng_key_manager_init(otr->keys);
}

INTERNAL otrng_err generate_phi_receiving(uint8_t **dst, size_t *dst_len,
                                          otrng_s *otr) {
  return generate_phi_serialized(
      dst, dst_len, otrng_get_shared_session_state(otr),
      otr->receiving_init_msg, otr->our_instance_tag, otr->their_instance_tag);
}

INTERNAL const client_profile_s *get_my_client_profile(otrng_s *otr) {
  maybe_create_keys(otr->conversation);
  otrng_client_state_s *state = otr->conversation->client;
  return otrng_client_state_get_or_create_client_profile(state);
}

INTERNAL const otrng_prekey_profile_s *get_my_prekey_profile(otrng_s *otr) {
  maybe_create_keys(otr->conversation);
  otrng_client_state_s *state = otr->conversation->client;
  return otrng_client_state_get_or_create_prekey_profile(state);
}

static char *build_error_message(const char *error_code,
                                 const char *error_name) {
  size_t s = strlen(ERROR_PREFIX) + strlen(error_code) + strlen(error_name) + 1;
  char *err_msg = malloc(s);
  if (!err_msg) {
    return NULL;
  }

  strcpy(err_msg, ERROR_PREFIX);
  strcpy(err_msg + strlen(ERROR_PREFIX), error_code);
  strcat(err_msg, error_name);

  return err_msg;
}

INTERNAL void otrng_error_message(string_p *to_send, otrng_err_code err_code) {
  switch (err_code) {
  case ERR_NONE:
    break;
  case ERR_MSG_UNREADABLE:
    *to_send = build_error_message(ERROR_CODE_1, "OTRNG_ERR_MSG_UNREADABLE");
    break;
  case ERR_MSG_NOT_PRIVATE:
    *to_send =
        build_error_message(ERROR_CODE_2, "OTRNG_ERR_MSG_NOT_PRIVATE_STATE");
    break;
  case ERR_MSG_ENCRYPTION_ERROR:
    *to_send = build_error_message(ERROR_CODE_3, "OTRNG_ERR_ENCRYPTION_ERROR");
    break;
  case ERR_MSG_MALFORMED:
    *to_send = build_error_message(ERROR_CODE_4, "OTRNG_ERR_MALFORMED");
    break;
  }
}

tstatic otrng_err encrypt_data_message(data_message_s *data_msg,
                                       const uint8_t *message,
                                       size_t message_len,
                                       const m_enc_key_p enc_key) {
  uint8_t *c = NULL;

  random_bytes(data_msg->nonce, sizeof(data_msg->nonce));

  c = malloc(message_len);
  if (!c) {
    return ERROR;
  }

  // TODO: @c_logic message is an UTF-8 string. Is there any problem to cast
  // it to (unsigned char *)
  // encrypted_message = XSalsa20_Enc(MKenc, nonce, m)
  int err =
      crypto_stream_xor(c, message, message_len, data_msg->nonce, enc_key);
  if (err) {
    free(c);
    return ERROR;
  }

  data_msg->enc_msg_len = message_len;
  data_msg->enc_msg = c;

#ifdef DEBUG
  printf("\n");
  printf("nonce = ");
  otrng_memdump(data_msg->nonce, DATA_MSG_NONCE_BYTES);
  printf("msg = ");
  otrng_memdump(message, message_len);
  printf("cipher = ");
  otrng_memdump(c, message_len);
#endif

  return SUCCESS;
}

tstatic data_message_s *generate_data_msg(const otrng_s *otr,
                                          const uint32_t ratchet_id) {
  data_message_s *data_msg = otrng_data_message_new();
  if (!data_msg) {
    return NULL;
  }

  data_msg->sender_instance_tag = otr->our_instance_tag;
  data_msg->receiver_instance_tag = otr->their_instance_tag;
  data_msg->previous_chain_n = otr->keys->pn;
  data_msg->ratchet_id = ratchet_id;
  data_msg->message_id = otr->keys->j;
  otrng_ec_point_copy(data_msg->ecdh, our_ecdh(otr));
  data_msg->dh = otrng_dh_mpi_copy(our_dh(otr));

  return data_msg;
}

tstatic otrng_err serialize_and_encode_data_msg(
    string_p *dst, const m_mac_key_p mac_key, uint8_t *to_reveal_mac_keys,
    size_t to_reveal_mac_keys_len, const data_message_s *data_msg) {
  uint8_t *body = NULL;
  size_t bodylen = 0;

  if (!otrng_data_message_body_asprintf(&body, &bodylen, data_msg)) {
    return ERROR;
  }

  size_t serlen = bodylen + MAC_KEY_BYTES + to_reveal_mac_keys_len;

  uint8_t *ser = malloc(serlen);
  if (!ser) {
    free(body);
    return ERROR;
  }

  memcpy(ser, body, bodylen);
  free(body);

  if (!otrng_data_message_authenticator(ser + bodylen, MAC_KEY_BYTES, mac_key,
                                        ser, bodylen)) {
    free(ser);
    return ERROR;
  }

  if (to_reveal_mac_keys) {
    otrng_serialize_bytes_array(ser + bodylen + DATA_MSG_MAC_BYTES,
                                to_reveal_mac_keys, to_reveal_mac_keys_len);
  }

  *dst = otrl_base64_otr_encode(ser, serlen);

  free(ser);
  return SUCCESS;
}

tstatic otrng_err send_data_message(string_p *to_send, const uint8_t *message,
                                    size_t message_len, otrng_s *otr,
                                    unsigned char flags, otrng_notif notif) {
  data_message_s *data_msg = NULL;
  uint32_t ratchet_id = otr->keys->i;
  m_enc_key_p enc_key;
  m_mac_key_p mac_key;

  /* if j == 0 */
  if (!otrng_key_manager_derive_dh_ratchet_keys(
          otr->keys, otr->conversation->client->max_stored_msg_keys,
          otr->keys->j, 0, 's', notif)) {
    return ERROR;
  }

  // TODO: This hides using uninitialized bytes from keys
  memset(enc_key, 0, sizeof enc_key);
  memset(mac_key, 0, sizeof mac_key);

  otrng_key_manager_derive_chain_keys(
      enc_key, mac_key, otr->keys,
      otr->conversation->client->max_stored_msg_keys, 0, 's', notif);

  data_msg = generate_data_msg(otr, ratchet_id);
  if (!data_msg) {
    sodium_memzero(enc_key, sizeof(m_enc_key_p));
    sodium_memzero(mac_key, sizeof(m_mac_key_p));
    return ERROR;
  }

  data_msg->flags = flags;
  data_msg->sender_instance_tag = otr->our_instance_tag;
  data_msg->receiver_instance_tag = otr->their_instance_tag;

  if (!encrypt_data_message(data_msg, message, message_len, enc_key)) {
    otrng_error_message(to_send, ERR_MSG_ENCRYPTION_ERROR);

    sodium_memzero(enc_key, sizeof(m_enc_key_p));
    sodium_memzero(mac_key, sizeof(m_mac_key_p));
    otrng_data_message_free(data_msg);
    return ERROR;
  }

  sodium_memzero(enc_key, sizeof(m_enc_key_p));

  /* Authenticator = KDF_1(0x1C || MKmac || KDF_1(usage_authenticator ||
   * data_message_sections, 64), 64) */
  if (otr->keys->j == 0) {
    size_t ser_mac_keys_len =
        otrng_list_len(otr->keys->old_mac_keys) * MAC_KEY_BYTES;
    uint8_t *ser_mac_keys =
        otrng_serialize_old_mac_keys(otr->keys->old_mac_keys);
    otr->keys->old_mac_keys = NULL;

    if (!serialize_and_encode_data_msg(to_send, mac_key, ser_mac_keys,
                                       ser_mac_keys_len, data_msg)) {
      sodium_memzero(mac_key, sizeof(m_mac_key_p));
      free(ser_mac_keys);
      otrng_data_message_free(data_msg);
      return ERROR;
    }
    free(ser_mac_keys);
  } else {
    if (!serialize_and_encode_data_msg(to_send, mac_key, NULL, 0, data_msg)) {
      sodium_memzero(mac_key, sizeof(m_mac_key_p));
      otrng_data_message_free(data_msg);
      return ERROR;
    }
  }

  otr->keys->j++;

  sodium_memzero(mac_key, sizeof(m_mac_key_p));
  otrng_data_message_free(data_msg);

  return SUCCESS;
}

tstatic otrng_err serialize_tlvs(uint8_t **dst, size_t *dstlen,
                                 const tlv_list_s *tlvs) {
  const tlv_list_s *current = tlvs;
  uint8_t *cursor = NULL;

  *dst = NULL;
  *dstlen = 0;

  if (!tlvs) {
    return SUCCESS;
  }

  for (*dstlen = 0; current; current = current->next) {
    *dstlen += current->data->len + 4;
  }

  *dst = malloc(*dstlen);
  if (!*dst) {
    return ERROR;
  }

  cursor = *dst;
  for (current = tlvs; current; current = current->next) {
    cursor += otrng_tlv_serialize(cursor, current->data);
  }

  return SUCCESS;
}

tstatic otrng_err append_tlvs(uint8_t **dst, size_t *dst_len,
                              const string_p message, const tlv_list_s *tlvs,
                              const otrng_s *otr) {
  uint8_t *ser = NULL;
  size_t len = 0;

  if (!serialize_tlvs(&ser, &len, tlvs)) {
    return ERROR;
  }

  // Append padding
  size_t message_len = strlen(message) + 1 + len;
  uint8_t *padding = NULL;
  size_t padding_len = 0;
  if (!generate_padding(&padding, &padding_len, message_len, otr)) {
    free(ser);
    return ERROR;
  }

  *dst_len = message_len + padding_len;
  *dst = malloc(*dst_len);
  if (!*dst) {
    free(ser);
    free(padding);
    return ERROR;
  }

  memcpy(otrng_stpcpy((char *)*dst, message) + 1, ser, len);

  if (padding) {
    memcpy(*dst + message_len, padding, padding_len);
  }

  free(ser);
  free(padding);
  return SUCCESS;
}

INTERNAL otrng_err otrng_prepare_to_send_data_message(
    string_p *to_send, otrng_notif notif, const string_p message,
    const tlv_list_s *tlvs, otrng_s *otr, unsigned char flags) {
  uint8_t *msg = NULL;
  size_t msg_len = 0;

  if (otr->state == OTRNG_STATE_FINISHED) {
    return ERROR; // Should restart
  }

  if (otr->state != OTRNG_STATE_ENCRYPTED_MESSAGES) {
    notif = NOTIF_STATE_NOT_ENCRYPTED; // TODO: @queing queue message
    return ERROR;
  }

  if (!append_tlvs(&msg, &msg_len, message, tlvs, otr)) {
    return ERROR;
  }

  otrng_err result =
      send_data_message(to_send, msg, msg_len, otr, flags, notif);

  otr->last_sent = time(NULL);

  free(msg);

  return result;
}

tstatic void gone_secure_cb_v4(const otrng_conversation_state_s *conv) {
  if (!conv || !conv->client || !conv->client->callbacks ||
      !conv->client->callbacks->gone_secure) {
    return;
  }

  conv->client->callbacks->gone_secure(conv);
}

INTERNAL otrng_err double_ratcheting_init(otrng_s *otr,
                                          const char participant) {
  if (!otrng_key_manager_ratcheting_init(otr->keys, participant)) {
    return ERROR;
  }

  otr->state = OTRNG_STATE_ENCRYPTED_MESSAGES;
  gone_secure_cb_v4(otr->conversation);
  otrng_key_manager_wipe_shared_prekeys(otr->keys);

  return SUCCESS;
}
