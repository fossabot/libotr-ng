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

#include "receive.h"

#include <libotr/b64.h>
#include <libotr/mem.h>

#include "dake.h"
#include "data_message.h"
#include "deserialize.h"
#include "instance_tag.h"
#include "shake.h"
#include "smp.h"

// TODO: Duplicated for now
tstatic void gone_insecure_cb_v4_dup(const otrng_conversation_state_s *conv) {
  if (!conv || !conv->client || !conv->client->callbacks ||
      !conv->client->callbacks->gone_insecure) {
    return;
  }

  conv->client->callbacks->gone_insecure(conv);
}

tstatic void fingerprint_seen_cb_v4(const otrng_fingerprint_p fp,
                                    const otrng_conversation_state_s *conv) {
  if (!conv || !conv->client || !conv->client->callbacks ||
      !conv->client->callbacks->fingerprint_seen) {
    return;
  }

  conv->client->callbacks->fingerprint_seen(fp, conv);
}

tstatic const otrng_shared_prekey_pair_s *
our_shared_prekey(const otrng_s *otr) {
  return otr->conversation->client->shared_prekey_pair;
}

static inline const otrng_prekey_profile_s *
get_my_prekey_profile_by_id(uint32_t id, otrng_s *otr) {
  otrng_client_state_s *state = otr->conversation->client;
  return otrng_client_state_get_prekey_profile_by_id(id, state);
}

static inline const client_profile_s *
get_my_client_profile_by_id(uint32_t id, otrng_s *otr) {
  maybe_create_keys(otr->conversation);
  otrng_client_state_s *state = otr->conversation->client;
  return otrng_client_state_get_client_profile_by_id(id, state);
}

tstatic otrng_err message_to_display_without_tag(otrng_response_s *response,
                                                 const string_p message,
                                                 size_t msg_len) {
  // TODO: What if there is more than one VERSION TAG?
  size_t tag_length = WHITESPACE_TAG_BASE_BYTES + WHITESPACE_TAG_VERSION_BYTES;
  size_t chars = msg_len - tag_length;

  if (msg_len < tag_length) {
    return ERROR;
  }

  char *found_at = strstr(message, INSTANCE_TAG_BASE);
  if (!found_at) {
    return ERROR;
  }

  string_p buff = malloc(chars + 1);
  if (buff == NULL) {
    return ERROR;
  }

  size_t bytes_before_tag = found_at - message;
  if (!bytes_before_tag) {
    strncpy(buff, message + tag_length, chars);
  } else {
    strncpy(buff, message, bytes_before_tag);
    strncpy(buff, message + bytes_before_tag, chars - bytes_before_tag);
  }
  buff[chars] = '\0';

  response->to_display = otrng_strndup(buff, chars);

  free(buff);
  return SUCCESS;
}

tstatic void set_running_version_from_tag(otrng_s *otr,
                                          const string_p message) {
  if (allow_version(otr, OTRNG_ALLOW_V4) && strstr(message, INSTANCE_TAG_V4)) {
    otr->running_version = 4;
    return;
  }

  if (allow_version(otr, OTRNG_ALLOW_V3) && strstr(message, INSTANCE_TAG_V3)) {
    otr->running_version = 3;
    return;
  }
}

tstatic otrng_err serialize_and_encode_identity_message(
    string_p *dst, const dake_identity_message_s *m) {
  uint8_t *buff = NULL;
  size_t len = 0;

  if (!otrng_dake_identity_message_asprintf(&buff, &len, m)) {
    return ERROR;
  }

  *dst = otrl_base64_otr_encode(buff, len);

  free(buff);
  return SUCCESS;
}

tstatic otrng_err reply_with_identity_msg(otrng_response_s *response,
                                          otrng_s *otr) {
  dake_identity_message_s *m = NULL;

  m = otrng_dake_identity_message_new(get_my_client_profile(otr));
  if (!m) {
    return ERROR;
  }

  m->sender_instance_tag = otr->our_instance_tag;
  m->receiver_instance_tag = otr->their_instance_tag;

  otrng_ec_point_copy(m->Y, our_ecdh(otr));
  m->B = otrng_dh_mpi_copy(our_dh(otr));

  otrng_err result =
      serialize_and_encode_identity_message(&response->to_send, m);
  otrng_dake_identity_message_free(m);

  return result;
}

tstatic otrng_err start_dake(otrng_response_s *response, otrng_s *otr) {
  if (!otrng_key_manager_generate_ephemeral_keys(otr->keys)) {
    return ERROR;
  }

  maybe_create_keys(otr->conversation);
  if (!reply_with_identity_msg(response, otr)) {
    return ERROR;
  }

  otr->state = OTRNG_STATE_WAITING_AUTH_R;

  return SUCCESS;
}

tstatic otrng_err receive_tagged_plaintext(otrng_response_s *response,
                                           const string_p message,
                                           otrng_s *otr) {
  set_running_version_from_tag(otr, message);

  switch (otr->running_version) {
  case 4:
    if (!message_to_display_without_tag(response, message, strlen(message))) {
      return ERROR;
    }
    return start_dake(response, otr);
    break;
  case 3:
    return otrng_v3_receive_message(&response->to_send, &response->to_display,
                                    &response->tlvs, message, otr->v3_conn);
    break;
  case 0:
    /* ignore */
    return SUCCESS;
  }

  return ERROR;
}

tstatic void set_running_version_from_query_msg(otrng_s *otr,
                                                const string_p message) {
  if (allow_version(otr, OTRNG_ALLOW_V4) && strstr(message, "4")) {
    otr->running_version = 4;
  } else if (allow_version(otr, OTRNG_ALLOW_V3) && strstr(message, "3")) {
    otr->running_version = 3;
  }
}

tstatic otrng_err receive_query_message(otrng_response_s *response,
                                        const string_p message, otrng_s *otr) {
  set_running_version_from_query_msg(otr, message);

  // TODO: @refactoring still unsure about this
  if (!otr->receiving_init_msg) {
    otr->receiving_init_msg = otrng_strdup(message);
  }

  switch (otr->running_version) {
  case 4:
    return start_dake(response, otr);
    break;
  case 3:
    return otrng_v3_receive_message(&response->to_send, &response->to_display,
                                    &response->tlvs, message, otr->v3_conn);
    break;
  case 0:
    /* ignore */
    return SUCCESS;
  }

  return ERROR;
}

// TODO move to keys.c?
tstatic otrng_err generate_tmp_key_i(uint8_t *dst, otrng_s *otr) {
  k_ecdh_p k_ecdh;
  k_ecdh_p tmp_ecdh_k1;
  k_ecdh_p tmp_ecdh_k2;

  // TODO: @refactoring this workaround is not the nicest there is
  if (!otrng_ecdh_shared_secret(k_ecdh, otr->keys->our_ecdh,
                                otr->keys->their_ecdh)) {
    return ERROR;
  }

  dh_shared_secret_p k_dh;
  size_t k_dh_len = 0;
  if (!otrng_dh_shared_secret(k_dh, &k_dh_len, otr->keys->our_dh->priv,
                              otr->keys->their_dh)) {
    return ERROR;
  }

  brace_key_p brace_key;
  hash_hash(brace_key, sizeof(brace_key_p), k_dh, k_dh_len);

  sodium_memzero(k_dh, sizeof(k_dh));

#ifdef DEBUG
  printf("\n");
  printf("GENERATING TEMP KEY I\n");
  printf("K_ecdh = ");
  otrng_memdump(k_ecdh, sizeof(k_ecdh_p));
  printf("brace_key = ");
  otrng_memdump(brace_key, sizeof(brace_key_p));
#endif

  if (!otrng_ecdh_shared_secret_from_prekey(tmp_ecdh_k1, our_shared_prekey(otr),
                                            their_ecdh(otr))) {
    return ERROR;
  }

  if (!otrng_ecdh_shared_secret_from_keypair(
          tmp_ecdh_k2, otr->conversation->client->keypair, their_ecdh(otr))) {
    return ERROR;
  }

  otrng_key_manager_calculate_tmp_key(dst, k_ecdh, brace_key, tmp_ecdh_k1,
                                      tmp_ecdh_k2);

#ifdef DEBUG
  printf("\n");
  printf("GENERATING TEMP KEY I\n");
  printf("tmp_key_i = ");
  otrng_memdump(dst, HASH_BYTES);
#endif

  sodium_memzero(tmp_ecdh_k1, ED448_POINT_BYTES);
  sodium_memzero(tmp_ecdh_k2, ED448_POINT_BYTES);

  return SUCCESS;
}

static otrng_err generate_phi_sending(uint8_t **dst, size_t *dst_len,
                                      otrng_s *otr) {
  return generate_phi_serialized(
      dst, dst_len, otrng_get_shared_session_state(otr), otr->sending_init_msg,
      otr->our_instance_tag, otr->their_instance_tag);
}

tstatic otrng_bool verify_non_interactive_auth_message(
    otrng_response_s *response, const dake_non_interactive_auth_message_s *auth,
    otrng_s *otr) {
  const otrng_prekey_profile_s *prekey_profile = get_my_prekey_profile(otr);
  if (!prekey_profile) {
    return otrng_false;
  }

  const otrng_dake_participant_data_s initiator = {
      .client_profile = get_my_client_profile(otr),
      .ecdh = *(otr->keys->our_ecdh->pub),
      .dh = our_dh(otr),
  };

  // clang-format off
  const otrng_dake_participant_data_s responder = {
      .client_profile = auth->profile,
      .ecdh = *(auth->X),
      .dh = auth->A,
  };
  // clang-format on

  uint8_t *phi = NULL;
  size_t phi_len = 0;
  if (!generate_phi_sending(&phi, &phi_len, otr)) {
    return ERROR;
  }

  unsigned char *t = NULL;
  size_t t_len = 0;

  /* t = KDF_2(Bobs_User_Profile) || KDF_2(Alices_User_Profile) ||
   * Y || X || B || A || our_shared_prekey.public */
  if (!build_non_interactive_rsign_tag(&t, &t_len, initiator, responder,
                                       prekey_profile->shared_prekey, phi,
                                       phi_len)) {
    free(phi);
    return ERROR;
  }

  free(phi);

  /* RVrf({H_b, H_a, Y}, sigma, msg) */
  if (!otrng_rsig_verify(auth->sigma,
                         otr->conversation->client->keypair->pub, /* H_b */
                         auth->profile->long_term_pub_key,        /* H_a */
                         our_ecdh(otr),                           /* Y  */
                         t, t_len)) {
    free(t);

    /* here no warning should be passed */
    return otrng_false;
  }

  /* Check mac */
  uint8_t mac_tag[DATA_MSG_MAC_BYTES];
  if (!otrng_dake_non_interactive_auth_message_authenticator(
          mac_tag, auth, t, t_len, otr->keys->tmp_key)) {
    free(t);
    /* here no warning should be passed */
    return otrng_false;
  }

  free(t);

  /* here no warning should be passed */
  if (0 != otrl_mem_differ(mac_tag, auth->auth_mac, DATA_MSG_MAC_BYTES)) {
    sodium_memzero(mac_tag, DATA_MSG_MAC_BYTES);
    return otrng_false;
  }

  return otrng_true;
}

static otrng_bool valid_receiver_instance_tag(uint32_t instance_tag) {
  return (instance_tag == 0 || valid_instance_tag(instance_tag));
}

tstatic otrng_err non_interactive_auth_message_received(
    otrng_response_s *response, const dake_non_interactive_auth_message_p auth,
    otrng_s *otr) {
  otrng_client_state_s *state = otr->conversation->client;

  const otrng_stored_prekeys_s *stored_prekey = NULL;
  const client_profile_s *client_profile = NULL;
  const otrng_prekey_profile_s *prekey_profile = NULL;

  if (!received_sender_instance_tag(auth->sender_instance_tag, otr)) {
    otrng_error_message(&response->to_send, ERR_MSG_MALFORMED);
    return ERROR;
  }

  if (!valid_receiver_instance_tag(auth->receiver_instance_tag)) {
    otrng_error_message(&response->to_send, ERR_MSG_MALFORMED);
    return ERROR;
  }

  if (!otrng_valid_received_values(auth->sender_instance_tag, auth->X, auth->A,
                                   auth->profile)) {
    return ERROR;
  }

  stored_prekey = get_my_prekeys_by_id(auth->prekey_message_id, state);
  client_profile = get_my_client_profile_by_id(auth->long_term_key_id, otr);
  prekey_profile = get_my_prekey_profile_by_id(auth->prekey_profile_id, otr);

  if (!stored_prekey) {
    return ERROR;
  }

  if (!client_profile) {
    return ERROR;
  }

  if (!prekey_profile) {
    return ERROR;
  }

  // Check if the state is consistent. This must be removed and simplified.
  // If the state is not, we may need to update our current  (client and/or
  // prekey) profiles to a profile from the past.

  // Long-term keypair is the same as used to generate my current client
  // profile.
  // Should be always true, though.
  if (!otrng_ec_point_eq(otr->conversation->client->keypair->pub,
                         get_my_client_profile(otr)->long_term_pub_key)) {
    return ERROR;
  }

  // Shared prekey is the same as used to generate my current prekey profile.
  // Should be always true, though.
  if (!otrng_ec_point_eq(our_shared_prekey(otr)->pub,
                         get_my_prekey_profile(otr)->shared_prekey)) {
    return ERROR;
  }

  // The client profile in question must also have the same key.
  if (!otrng_ec_point_eq(client_profile->long_term_pub_key,
                         get_my_client_profile(otr)->long_term_pub_key)) {
    return ERROR;
  }

  /* The prekey profile in question must also have the same key. */
  if (!otrng_ec_point_eq(prekey_profile->shared_prekey,
                         get_my_prekey_profile(otr)->shared_prekey)) {
    return ERROR;
  }

  /* Set our current ephemeral keys, based on the received message */
  otrng_ecdh_keypair_destroy(otr->keys->our_ecdh);
  otrng_ec_scalar_copy(otr->keys->our_ecdh->priv,
                       stored_prekey->our_ecdh->priv);
  otrng_ec_point_copy(otr->keys->our_ecdh->pub, stored_prekey->our_ecdh->pub);

  otrng_dh_keypair_destroy(otr->keys->our_dh);
  otr->keys->our_dh->priv = otrng_dh_mpi_copy(stored_prekey->our_dh->priv);
  otr->keys->our_dh->pub = otrng_dh_mpi_copy(stored_prekey->our_dh->pub);

  if (auth->receiver_instance_tag != stored_prekey->sender_instance_tag) {
    return SUCCESS;
  }

  /* Delete the stored prekeys for this ID so they can't be used again. */
  delete_my_prekey_message_by_id(auth->prekey_message_id, state);

  otrng_key_manager_set_their_ecdh(auth->X, otr->keys);
  otrng_key_manager_set_their_dh(auth->A, otr->keys);

  // TODO: @client_profile Extract function to set_their_client_profile
  otr->their_client_profile = malloc(sizeof(client_profile_s));
  if (!otr->their_client_profile) {
    return ERROR;
  }

  otrng_client_profile_copy(otr->their_client_profile, auth->profile);

  /* tmp_k = KDF_1(usage_tmp_key || K_ecdh ||
   * ECDH(x, our_shared_prekey.secret, their_ecdh) ||
   * ECDH(Ska, X) || brace_key) */
  if (!generate_tmp_key_i(otr->keys->tmp_key, otr)) {
    return ERROR;
  }

  if (!verify_non_interactive_auth_message(response, auth, otr)) {
    return ERROR;
  }

  if (!otrng_key_manager_generate_shared_secret(otr->keys, false)) {
    return ERROR;
  }

  if (!double_ratcheting_init(otr, 'u')) {
    return ERROR;
  }

  otrng_fingerprint_p fp;
  if (otrng_serialize_fingerprint(
          fp, otr->their_client_profile->long_term_pub_key)) {
    fingerprint_seen_cb_v4(fp, otr->conversation);
  }

  return SUCCESS;
}

tstatic otrng_err receive_non_interactive_auth_message(
    otrng_response_s *response, const uint8_t *src, size_t len, otrng_s *otr) {

  if (otr->state == OTRNG_STATE_FINISHED) {
    return SUCCESS; /* ignore the message */
  }

  dake_non_interactive_auth_message_p auth;

  if (!otrng_dake_non_interactive_auth_message_deserialize(auth, src, len)) {
    return ERROR;
  }

  otrng_err ret = non_interactive_auth_message_received(response, auth, otr);
  otrng_dake_non_interactive_auth_message_destroy(auth);

  return ret;
}

tstatic otrng_err serialize_and_encode_auth_r(string_p *dst,
                                              const dake_auth_r_s *m) {
  uint8_t *buff = NULL;
  size_t len = 0;

  if (!otrng_dake_auth_r_asprintf(&buff, &len, m)) {
    return ERROR;
  }

  *dst = otrl_base64_otr_encode(buff, len);

  free(buff);
  return SUCCESS;
}

static otrng_err generate_sending_rsig_tag(uint8_t **dst, size_t *dst_len,
                                           const char auth_tag_type,
                                           otrng_s *otr) {
  const otrng_dake_participant_data_s initiator = {
      .client_profile = otr->their_client_profile,
      .ecdh = *(otr->keys->their_ecdh),
      .dh = their_dh(otr),
  };

  const otrng_dake_participant_data_s responder = {
      .client_profile = get_my_client_profile(otr),
      .ecdh = *(otr->keys->our_ecdh->pub),
      .dh = our_dh(otr),
  };

  uint8_t *phi = NULL;
  size_t phi_len = 0;
  if (!generate_phi_sending(&phi, &phi_len, otr)) {
    return ERROR;
  }

  otrng_err ret = build_interactive_rsign_tag(
      dst, dst_len, auth_tag_type, initiator, responder, phi, phi_len);

  free(phi);
  return ret;
}

tstatic otrng_err reply_with_auth_r_msg(string_p *dst, otrng_s *otr) {
  dake_auth_r_p msg;

  msg->sender_instance_tag = otr->our_instance_tag;
  msg->receiver_instance_tag = otr->their_instance_tag;

  otrng_client_profile_copy(msg->profile, get_my_client_profile(otr));

  otrng_ec_point_copy(msg->X, our_ecdh(otr));
  msg->A = otrng_dh_mpi_copy(our_dh(otr));

  unsigned char *t = NULL;
  size_t t_len = 0;
  if (!generate_sending_rsig_tag(&t, &t_len, 'r', otr)) {
    return ERROR;
  }

  /* sigma = RSig(H_a, sk_ha, {H_b, H_a, Y}, t) */
  otrng_rsig_authenticate(
      msg->sigma, otr->conversation->client->keypair->priv, /* sk_ha */
      otr->conversation->client->keypair->pub,              /* H_a */
      otr->their_client_profile->long_term_pub_key,         /* H_b */
      otr->conversation->client->keypair->pub,              /* H_a */
      their_ecdh(otr),                                      /* Y */
      t, t_len);
  free(t);

  otrng_err result = serialize_and_encode_auth_r(dst, msg);
  otrng_dake_auth_r_destroy(msg);

  return result;
}

tstatic otrng_err receive_identity_message_on_state_start(
    string_p *dst, dake_identity_message_s *identity_message, otrng_s *otr) {
  otr->their_client_profile = malloc(sizeof(client_profile_s));
  if (!otr->their_client_profile) {
    return ERROR;
  }

  otrng_key_manager_set_their_ecdh(identity_message->Y, otr->keys);
  otrng_key_manager_set_their_dh(identity_message->B, otr->keys);
  otrng_client_profile_copy(otr->their_client_profile,
                            identity_message->profile);

  /* @secret the priv parts will be deleted once the mixed shared secret is
   * derived */
  if (!otrng_key_manager_generate_ephemeral_keys(otr->keys)) {
    return ERROR;
  }

  if (!reply_with_auth_r_msg(dst, otr)) {
    return ERROR;
  }

  /* @secret the shared secret will be deleted once the double ratchet is
   * initialized */
  if (!otrng_key_manager_generate_shared_secret(otr->keys, true)) {
    return ERROR;
  }

  otr->state = OTRNG_STATE_WAITING_AUTH_I;
  return SUCCESS;
}

tstatic otrng_err receive_identity_message_on_waiting_auth_r(
    string_p *dst, dake_identity_message_s *msg, otrng_s *otr) {
  int cmp = gcry_mpi_cmp(our_dh(otr), msg->B);

  /* If our is higher, ignore. */
  if (cmp > 0) {
    // TODO: @state_machine this should resend the prev identity message
    return SUCCESS;
  }

  // Every time we call 'otrng_key_manager_generate_ephemeral_keys'
  // keys get deleted and replaced
  // forget_our_keys(otr);
  return receive_identity_message_on_state_start(dst, msg, otr);
}

tstatic otrng_err receive_identity_message_on_waiting_auth_i(
    string_p *dst, dake_identity_message_s *msg, otrng_s *otr) {
  // Every time we call 'otrng_key_manager_generate_ephemeral_keys'
  // keys get deleted and replaced
  // forget_our_keys(otr);
  otrng_client_profile_free(otr->their_client_profile);
  return receive_identity_message_on_state_start(dst, msg, otr);
}

tstatic otrng_err receive_identity_message(string_p *dst, const uint8_t *buff,
                                           size_t buflen, otrng_s *otr) {
  otrng_err result = ERROR;
  dake_identity_message_p m;

  if (!otrng_dake_identity_message_deserialize(m, buff, buflen)) {
    return result;
  }

  if (m->receiver_instance_tag != 0) {
    otrng_dake_identity_message_destroy(m);
    return SUCCESS;
  }

  if (!received_sender_instance_tag(m->sender_instance_tag, otr)) {
    otrng_error_message(dst, ERR_MSG_MALFORMED);
    otrng_dake_identity_message_destroy(m);
    return result;
  }

  if (!otrng_valid_received_values(m->sender_instance_tag, m->Y, m->B,
                                   m->profile)) {
    otrng_dake_identity_message_destroy(m);
    return result;
  }

  switch (otr->state) {
  case OTRNG_STATE_START:
    result = receive_identity_message_on_state_start(dst, m, otr);
    break;
  case OTRNG_STATE_WAITING_AUTH_R:
    result = receive_identity_message_on_waiting_auth_r(dst, m, otr);
    break;
  case OTRNG_STATE_WAITING_AUTH_I:
    result = receive_identity_message_on_waiting_auth_i(dst, m, otr);
    break;
  case OTRNG_STATE_NONE:
  case OTRNG_STATE_ENCRYPTED_MESSAGES:
  case OTRNG_STATE_FINISHED:
    /* Ignore the message, but it is not an error. */
    result = SUCCESS;
  }

  otrng_dake_identity_message_destroy(m);
  return result;
}

tstatic otrng_err serialize_and_encode_auth_i(string_p *dst,
                                              const dake_auth_i_s *m) {
  uint8_t *buff = NULL;
  size_t len = 0;

  if (!otrng_dake_auth_i_asprintf(&buff, &len, m)) {
    return ERROR;
  }

  *dst = otrl_base64_otr_encode(buff, len);

  free(buff);
  return SUCCESS;
}

static otrng_err generate_receiving_rsig_tag(
    uint8_t **dst, size_t *dst_len, const char auth_tag_type,
    const otrng_dake_participant_data_s responder, otrng_s *otr) {
  const otrng_dake_participant_data_s initiator = {
      .client_profile = get_my_client_profile(otr),
      .ecdh = *(otr->keys->our_ecdh->pub),
      .dh = our_dh(otr),
  };

  uint8_t *phi = NULL;
  size_t phi_len = 0;
  if (!generate_phi_receiving(&phi, &phi_len, otr)) {
    return ERROR;
  }

  otrng_err ret = build_interactive_rsign_tag(
      dst, dst_len, auth_tag_type, initiator, responder, phi, phi_len);

  free(phi);
  return ret;
}

tstatic otrng_err reply_with_auth_i_msg(
    string_p *dst, const client_profile_s *their_client_profile, otrng_s *otr) {
  dake_auth_i_p msg;
  msg->sender_instance_tag = otr->our_instance_tag;
  msg->receiver_instance_tag = otr->their_instance_tag;

  const otrng_dake_participant_data_s responder = {
      .client_profile = their_client_profile,
      .ecdh = *(otr->keys->their_ecdh),
      .dh = their_dh(otr),
  };

  unsigned char *t = NULL;
  size_t t_len = 0;
  if (!generate_receiving_rsig_tag(&t, &t_len, 'i', responder, otr)) {
    return ERROR;
  }

  /* sigma = RSig(H_b, sk_hb, {H_b, H_a, X}, t) */
  otrng_rsig_authenticate(msg->sigma,
                          otr->conversation->client->keypair->priv, /* sk_hb */
                          otr->conversation->client->keypair->pub,  /* H_b */
                          otr->conversation->client->keypair->pub,  /* H_b */
                          their_client_profile->long_term_pub_key,  /* H_a */
                          their_ecdh(otr),                          /* X */
                          t, t_len);
  free(t);

  otrng_err result = serialize_and_encode_auth_i(dst, msg);
  otrng_dake_auth_i_destroy(msg);

  return result;
}

tstatic otrng_bool valid_auth_r_message(const dake_auth_r_s *auth,
                                        otrng_s *otr) {
  if (!otrng_valid_received_values(auth->sender_instance_tag, auth->X, auth->A,
                                   auth->profile)) {
    return otrng_false;
  }

  // clang-format off
  const otrng_dake_participant_data_s responder = {
      .client_profile = auth->profile,
      .ecdh = *(auth->X),
      .dh = auth->A,
  };
  // clang-format on

  unsigned char *t = NULL;
  size_t t_len = 0;
  if (!generate_receiving_rsig_tag(&t, &t_len, 'r', responder, otr)) {
    return ERROR;
  }

  /* RVrf({H_b, H_a, Y}, sigma, msg) */
  otrng_bool err = otrng_rsig_verify(
      auth->sigma, otr->conversation->client->keypair->pub, /* H_b */
      auth->profile->long_term_pub_key,                     /* H_a */
      our_ecdh(otr),                                        /* Y */
      t, t_len);

  free(t);
  return err;
}

tstatic otrng_err receive_auth_r(string_p *dst, const uint8_t *buff,
                                 size_t buff_len, otrng_s *otr) {
  if (otr->state != OTRNG_STATE_WAITING_AUTH_R) {
    return SUCCESS; /* ignore the message */
  }

  dake_auth_r_p auth;
  if (!otrng_dake_auth_r_deserialize(auth, buff, buff_len)) {
    return ERROR;
  }

  if (auth->receiver_instance_tag != otr->our_instance_tag) {
    otrng_dake_auth_r_destroy(auth);
    return SUCCESS;
  }

  if (!received_sender_instance_tag(auth->sender_instance_tag, otr)) {
    otrng_error_message(dst, ERR_MSG_MALFORMED);
    otrng_dake_auth_r_destroy(auth);
    return ERROR;
  }

  if (!valid_receiver_instance_tag(auth->receiver_instance_tag)) {
    otrng_error_message(dst, ERR_MSG_MALFORMED);
    otrng_dake_auth_r_destroy(auth);
    return ERROR;
  }

  if (!valid_auth_r_message(auth, otr)) {
    otrng_dake_auth_r_destroy(auth);
    return ERROR;
  }

  otr->their_client_profile = malloc(sizeof(client_profile_s));
  if (!otr->their_client_profile) {
    otrng_dake_auth_r_destroy(auth);
    return ERROR;
  }

  otrng_key_manager_set_their_ecdh(auth->X, otr->keys);
  otrng_key_manager_set_their_dh(auth->A, otr->keys);
  otrng_client_profile_copy(otr->their_client_profile, auth->profile);

  if (!reply_with_auth_i_msg(dst, otr->their_client_profile, otr)) {
    otrng_dake_auth_r_destroy(auth);
    return ERROR;
  }

  otrng_dake_auth_r_destroy(auth);

  otrng_fingerprint_p fp;
  if (otrng_serialize_fingerprint(
          fp, otr->their_client_profile->long_term_pub_key)) {
    fingerprint_seen_cb_v4(fp, otr->conversation);
  }

  /* @secret the shared secret will be deleted once the double ratchet is
   * initialized */
  if (!otrng_key_manager_generate_shared_secret(otr->keys, true)) {
    return ERROR;
  }

  return double_ratcheting_init(otr, 'u');
}

tstatic otrng_bool valid_auth_i_message(const dake_auth_i_s *auth,
                                        otrng_s *otr) {
  unsigned char *t = NULL;
  size_t t_len = 0;
  if (!generate_sending_rsig_tag(&t, &t_len, 'i', otr)) {
    return ERROR;
  }

  /* RVrf({H_b, H_a, X}, sigma, msg) */
  otrng_bool err = otrng_rsig_verify(
      auth->sigma, otr->their_client_profile->long_term_pub_key, /* H_b */
      otr->conversation->client->keypair->pub,                   /* H_a */
      our_ecdh(otr),                                             /* X */
      t, t_len);

  free(t);

  return err;
}

tstatic otrng_err receive_auth_i(const uint8_t *buff, size_t buff_len,
                                 otrng_s *otr) {
  if (otr->state != OTRNG_STATE_WAITING_AUTH_I) {
    return SUCCESS; /* Ignore the message */
  }

  dake_auth_i_p auth;
  if (!otrng_dake_auth_i_deserialize(auth, buff, buff_len)) {
    return ERROR;
  }

  if (auth->receiver_instance_tag != otr->our_instance_tag) {
    otrng_dake_auth_i_destroy(auth);
    return SUCCESS;
  }

  if (!received_sender_instance_tag(auth->sender_instance_tag, otr)) {
    otrng_dake_auth_i_destroy(auth);
    return ERROR;
  }

  if (!valid_receiver_instance_tag(auth->receiver_instance_tag)) {
    otrng_dake_auth_i_destroy(auth);
    return ERROR;
  }

  if (!valid_auth_i_message(auth, otr)) {
    otrng_dake_auth_i_destroy(auth);
    return ERROR;
  }

  otrng_dake_auth_i_destroy(auth);

  otrng_fingerprint_p fp;
  if (otrng_serialize_fingerprint(
          fp, otr->their_client_profile->long_term_pub_key)) {
    fingerprint_seen_cb_v4(fp, otr->conversation);
  }

  return double_ratcheting_init(otr, 't');
}

tstatic tlv_list_s *deserialize_received_tlvs(const uint8_t *src, size_t len) {
  uint8_t *tlvs_start = memchr(src, 0, len);
  if (!tlvs_start) {
    return NULL;
  }

  size_t tlvs_len = len - (tlvs_start + 1 - src);
  return otrng_parse_tlvs(tlvs_start + 1, tlvs_len);
}

tstatic otrng_err decrypt_data_msg(otrng_response_s *response,
                                   const m_enc_key_p enc_key,
                                   const data_message_s *msg) {
  string_p *dst = &response->to_display;

#ifdef DEBUG
  printf("\n");
  printf("DECRYPTING\n");
  printf("enc_key = ");
  otrng_memdump(enc_key, sizeof(m_enc_key_p));
  printf("nonce = ");
  otrng_memdump(msg->nonce, DATA_MSG_NONCE_BYTES);
#endif

  // TODO: @initialization What if msg->enc_msg_len == 0?
  uint8_t *plain = malloc(msg->enc_msg_len);
  if (!plain) {
    return ERROR;
  }

  int err = crypto_stream_xor(plain, msg->enc_msg, msg->enc_msg_len, msg->nonce,
                              enc_key);

  if (err) {
    free(plain);
    return ERROR;
  }

  /* If plain != "" and msg->enc_msg_len != 0 */
  if (otrng_strnlen((string_p)plain, msg->enc_msg_len)) {
    *dst = otrng_strndup((char *)plain, msg->enc_msg_len);
  }

  response->tlvs = deserialize_received_tlvs(plain, msg->enc_msg_len);
  free(plain);
  return SUCCESS;
}

tstatic void received_extra_sym_key(const otrng_client_conversation_s *conv,
                                    unsigned int use,
                                    const unsigned char *use_data,
                                    size_t use_data_len,
                                    const unsigned char *extra_sym_key) {

  if (!conv || !conv->client || !conv->client->callbacks ||
      !conv->client->callbacks->received_extra_symm_key)
    return;

  conv->client->callbacks->received_extra_symm_key(conv, use, use_data,
                                                   use_data_len, extra_sym_key);

#ifdef DEBUG
  printf("\n");
  printf("Received symkey use: %08x\n", use);
  printf("Usedata lenght: %zu\n", use_data_len);
  printf("Usedata = ");
  for (int i = 0; i < use_data_len; i++) {
    printf("%02x", use_data[i]);
  }
  printf("\n");
  printf("Symkey = ");
  for (int i = 0; i < EXTRA_SYMMETRIC_KEY_BYTES; i++) {
    printf("%02x", extra_symm_key[i]);
  }
#endif
}

tstatic unsigned int extract_word(unsigned char *bufp) {
  // unsigned int use =
  //    (bufp[0] << 24) | (bufp[1] << 16) | (bufp[2] << 8) | bufp[3];

  uint32_t use = 0;
  if (!otrng_deserialize_uint32(&use, bufp, 4, NULL)) {
    return 0;
  }

  return use;
}

tstatic tlv_s *process_tlv(const tlv_s *tlv, otrng_s *otr) {
  if (tlv->type == OTRNG_TLV_NONE || tlv->type == OTRNG_TLV_PADDING) {
    return NULL;
  }

  if (tlv->type == OTRNG_TLV_DISCONNECTED) {
    forget_our_keys(otr);
    otr->state = OTRNG_STATE_FINISHED;
    gone_insecure_cb_v4_dup(otr->conversation);
    return NULL;
  }

  if (tlv->type == OTRNG_TLV_SYM_KEY && tlv->len >= 4) {
    uint32_t use = extract_word(tlv->data);
    received_extra_sym_key(otr->conversation, use, tlv->data + 4, tlv->len - 4,
                           otr->keys->extra_symmetric_key);
    sodium_memzero(otr->keys->extra_symmetric_key,
                   sizeof(otr->keys->extra_symmetric_key));
    return NULL;
  }

  sodium_memzero(otr->keys->extra_symmetric_key, sizeof(extra_symmetric_key_p));

  return otrng_process_smp_tlv(tlv, otr);
}

tstatic otrng_err process_received_tlvs(tlv_list_s **to_send,
                                        otrng_response_s *response,
                                        otrng_s *otr) {
  const tlv_list_s *current = response->tlvs;
  while (current) {
    tlv_s *tlv = process_tlv(current->data, otr);
    current = current->next;

    if (!tlv) {
      continue;
    }

    *to_send = otrng_append_tlv(*to_send, tlv);
    if (!*to_send) {
      return ERROR;
    }
  }

  return SUCCESS;
}

tstatic otrng_err receive_tlvs(otrng_response_s *response, otrng_s *otr) {
  tlv_list_s *reply_tlvs = NULL;
  otrng_err ret = process_received_tlvs(&reply_tlvs, response, otr);
  if (!reply_tlvs) {
    return ret;
  }

  if (!ret) {
    return ret;
  }

  // Serialize response message to send
  ret = otrng_send_message(&response->to_send, "", NOTIF_NONE, reply_tlvs,
                           MSGFLAGS_IGNORE_UNREADABLE, otr);
  otrng_tlv_list_free(reply_tlvs);
  return ret;
}

tstatic otrng_err otrng_receive_data_message(otrng_response_s *response,
                                             otrng_notif notif,
                                             const uint8_t *buff, size_t buflen,
                                             otrng_s *otr) {
  data_message_s *msg = otrng_data_message_new();
  m_enc_key_p enc_key;
  m_mac_key_p mac_key;

  // TODO: This hides using uninitialized bytes from keys
  memset(enc_key, 0, sizeof enc_key);
  memset(mac_key, 0, sizeof mac_key);

  response->to_display = NULL;

  if (otr->state != OTRNG_STATE_ENCRYPTED_MESSAGES) {
    otrng_error_message(&response->to_send, ERR_MSG_NOT_PRIVATE);
    otrng_data_message_free(msg);
    return ERROR;
  }

  size_t read = 0;
  if (!otrng_data_message_deserialize(msg, buff, buflen, &read)) {
    otrng_data_message_free(msg);
    return ERROR;
  }

  // TODO: @freeing Do we care if the buffer had more than the data message?
  // if (read < buffer)
  //  return ERROR;

  if (msg->receiver_instance_tag != otr->our_instance_tag) {
    otrng_data_message_free(msg);
    return SUCCESS;
  }

  if (!received_sender_instance_tag(msg->sender_instance_tag, otr)) {
    otrng_error_message(&response->to_send, ERR_MSG_MALFORMED);
    return ERROR;
  }

  if (!valid_receiver_instance_tag(msg->receiver_instance_tag)) {
    otrng_error_message(&response->to_send, ERR_MSG_MALFORMED);
    return ERROR;
  }

  otrng_key_manager_set_their_keys(msg->ecdh, msg->dh, otr->keys);

  do {
    /* Try to decrypt the message with a stored skipped message key */
    if (!otrng_key_get_skipped_keys(enc_key, mac_key, msg->ratchet_id,
                                    msg->message_id, otr->keys)) {
      // TODO: @double_ratchet Why we do not care if this message is not a
      // duplicated skipped message and just derive the next ratchet key, and
      // increase the K (meaning the message was received)? if (msg->ratchet_id
      // < otr->keys->i) { continue; } if (msg->ratchet_id == otr->keys->i &&
      // msg->message_id < otr->keys->k)
      //{ continue; }
      /* if a new ratchet */
      if (!otrng_key_manager_derive_dh_ratchet_keys(
              otr->keys, otr->conversation->client->max_stored_msg_keys,
              msg->message_id, msg->previous_chain_n, 'r', notif)) {
        return ERROR;
      }

      otrng_key_manager_derive_chain_keys(
          enc_key, mac_key, otr->keys,
          otr->conversation->client->max_stored_msg_keys, msg->message_id, 'r',
          notif);
      otr->keys->k++;
    }

    if (!otrng_valid_data_message(mac_key, msg)) {
      sodium_memzero(enc_key, sizeof(enc_key));
      sodium_memzero(mac_key, sizeof(mac_key));
      otrng_data_message_free(msg);

      response->warning = OTRNG_WARN_RECEIVED_NOT_VALID;
      notif = NOTIF_MSG_NOT_VALID;

      return ERROR;
    }

    if (!decrypt_data_msg(response, enc_key, msg)) {
      if (msg->flags != MSGFLAGS_IGNORE_UNREADABLE) {
        otrng_error_message(&response->to_send, ERR_MSG_UNREADABLE);
        sodium_memzero(enc_key, sizeof(enc_key));
        sodium_memzero(mac_key, sizeof(mac_key));
        otrng_data_message_free(msg);

        return ERROR;
      } else if (msg->flags == MSGFLAGS_IGNORE_UNREADABLE) {
        sodium_memzero(enc_key, sizeof(enc_key));
        sodium_memzero(mac_key, sizeof(mac_key));
        otrng_data_message_free(msg);

        return ERROR;
      }
    }

    sodium_memzero(enc_key, sizeof(enc_key));
    sodium_memzero(mac_key, sizeof(mac_key));

    if (!receive_tlvs(response, otr)) {
      continue;
    }

    if (!otrng_store_old_mac_keys(otr->keys, mac_key)) {
      continue;
    }

    // TODO: @client this displays an event on otrv3..
    if (!response->to_display) {
      otr->ignore_msg = 1;
      sodium_memzero(mac_key, sizeof(m_mac_key_p));
      otrng_data_message_free(msg);
      return SUCCESS;
    } else if (otr->ignore_msg != 1) {
      if (otr->conversation->client->should_heartbeat(otr->last_sent)) {
        if (!otrng_send_message(&response->to_send, "", NOTIF_NONE, NULL,
                                MSGFLAGS_IGNORE_UNREADABLE, otr)) {
          sodium_memzero(mac_key, sizeof(m_mac_key_p));
          otrng_data_message_free(msg);
          return ERROR;
        }
        otr->last_sent = time(NULL);
      }
    }

    sodium_memzero(mac_key, sizeof(m_mac_key_p));
    otrng_data_message_free(msg);

    return SUCCESS;
  } while (0);

  sodium_memzero(mac_key, sizeof(m_mac_key_p));
  otrng_data_message_free(msg);

  return ERROR;
}

tstatic otrng_err extract_header(otrng_header_s *dst, const uint8_t *buffer,
                                 const size_t bufflen) {
  if (bufflen == 0) {
    return ERROR;
  }

  size_t read = 0;
  uint16_t version = 0;
  uint8_t type = 0;
  if (!otrng_deserialize_uint16(&version, buffer, bufflen, &read)) {
    return ERROR;
  }

  buffer += read;

  if (!otrng_deserialize_uint8(&type, buffer, bufflen - read, &read)) {
    return ERROR;
  }

  dst->version = OTRNG_ALLOW_NONE;
  if (version == 0x04) {
    dst->version = OTRNG_ALLOW_V4;
  } else if (version == 0x03) {
    dst->version = OTRNG_ALLOW_V3;
  }
  dst->type = type;

  return SUCCESS;
}

tstatic otrng_err receive_decoded_message(otrng_response_s *response,
                                          otrng_notif notif,
                                          const uint8_t *decoded,
                                          size_t dec_len, otrng_s *otr) {
  otrng_header_s header;
  if (!extract_header(&header, decoded, dec_len)) {
    return ERROR;
  }

  if (!allow_version(otr, header.version)) {
    return ERROR;
  }

  // TODO: @refactoring Why the version in the header is a ALLOWED VERSION?
  // This is the message version, not the version the protocol allows
  if (header.version != OTRNG_ALLOW_V4) {
    return ERROR;
  }

  maybe_create_keys(otr->conversation);

  response->to_send = NULL;

  switch (header.type) {
  case IDENTITY_MSG_TYPE:
    otr->running_version = 4;
    return receive_identity_message(&response->to_send, decoded, dec_len, otr);
  case AUTH_R_MSG_TYPE:
    return receive_auth_r(&response->to_send, decoded, dec_len, otr);
  case AUTH_I_MSG_TYPE:
    return receive_auth_i(decoded, dec_len, otr);
  case NON_INT_AUTH_MSG_TYPE:
    otr->running_version = 4;
    return receive_non_interactive_auth_message(response, decoded, dec_len,
                                                otr);
  case DATA_MSG_TYPE:
    return otrng_receive_data_message(response, notif, decoded, dec_len, otr);
  default:
    /* error. bad message type */
    return ERROR;
  }

  return ERROR;
}

tstatic otrng_err receive_encoded_message(otrng_response_s *response,
                                          otrng_notif notif,
                                          const string_p message,
                                          otrng_s *otr) {
  size_t dec_len = 0;
  uint8_t *decoded = NULL;
  if (otrl_base64_otr_decode(message, &decoded, &dec_len)) {
    return ERROR;
  }

  otrng_err result =
      receive_decoded_message(response, notif, decoded, dec_len, otr);
  free(decoded);

  return result;
}

tstatic otrng_err receive_error_message(otrng_response_s *response,
                                        const string_p message) {
  const char *unreadable_msg_error = "Unreadable message";
  const char *not_in_private_error = "Not in private state message";
  const char *encryption_error = "Encryption error";
  const char *malformed_error = "Malformed message";

  if (strncmp(message, "ERROR_1:", 8) == 0) {
    response->to_display =
        otrng_strndup(unreadable_msg_error, strlen(unreadable_msg_error));
    return SUCCESS;
  } else if (strncmp(message, "ERROR_2:", 8) == 0) {
    response->to_display =
        otrng_strndup(not_in_private_error, strlen(not_in_private_error));
    return SUCCESS;
  } else if (strncmp(message, "ERROR_3:", 8) == 0) {
    response->to_display =
        otrng_strndup(encryption_error, strlen(encryption_error));
    return SUCCESS;
  } else if (strncmp(message, "ERROR_4:", 8) == 0) {
    response->to_display =
        otrng_strndup(malformed_error, strlen(malformed_error));
    return SUCCESS;
  }
  return ERROR;
}

tstatic otrng_bool message_contains_tag(const string_p message) {
  return strstr(message, INSTANCE_TAG_BASE) != NULL;
}

tstatic bool message_is_query(const string_p message) {
  return strstr(message, QUERY_HEADER) != NULL;
}

tstatic bool message_is_otr_encoded(const string_p message) {
#define OTR_HEADER "?OTR:"
  return strstr(message, OTR_HEADER) != NULL;
}

tstatic bool message_is_otr_error(const string_p message) {
#define OTR_ERROR_HEADER "?OTR Error:"
  return strncmp(message, OTR_ERROR_HEADER, strlen(OTR_ERROR_HEADER)) == 0;
}

#define MSG_PLAINTEXT 1
#define MSG_TAGGED_PLAINTEXT 2
#define MSG_QUERY_STRING 3
#define MSG_OTR_ENCODED 4
#define MSG_OTR_ERROR 5

tstatic int get_message_type(const string_p message) {
  if (message_contains_tag(message)) {
    return MSG_TAGGED_PLAINTEXT;
  } else if (message_is_query(message)) {
    return MSG_QUERY_STRING;
  } else if (message_is_otr_error(message)) {
    return MSG_OTR_ERROR;
  } else if (message_is_otr_encoded(message)) {
    return MSG_OTR_ENCODED;
  }

  return MSG_PLAINTEXT;
}

tstatic void set_to_display(otrng_response_s *response,
                            const string_p message) {
  size_t msg_len = strlen(message);
  response->to_display = otrng_strndup(message, msg_len);
}

// TODO: @erroing Is not receiving a plaintext a problem?
tstatic void receive_plaintext(otrng_response_s *response,
                               const string_p message, const otrng_s *otr) {
  set_to_display(response, message);

  if (otr->state != OTRNG_STATE_START) {
    response->warning = OTRNG_WARN_RECEIVED_UNENCRYPTED;
  }
}

tstatic otrng_err receive_message_v4_only(otrng_response_s *response,
                                          otrng_notif notif,
                                          const string_p message,
                                          otrng_s *otr) {
  switch (get_message_type(message)) {
  case MSG_PLAINTEXT:
    receive_plaintext(response, message, otr);
    return SUCCESS;

  case MSG_TAGGED_PLAINTEXT:
    return receive_tagged_plaintext(response, message, otr);

  case MSG_QUERY_STRING:
    return receive_query_message(response, message, otr);

  case MSG_OTR_ENCODED:
    return receive_encoded_message(response, notif, message, otr);

  case MSG_OTR_ERROR:
    return receive_error_message(response, message + strlen(ERROR_PREFIX));
  }

  return SUCCESS;
}

INTERNAL otrng_err otrng_receive_defragmented_message(
    otrng_response_s *response, otrng_notif notif, const string_p message,
    otrng_s *otr) {

  if (!message || !response) {
    return ERROR;
  }

  response->to_display = NULL;

  /* A DH-Commit sets our running version to 3 */
  if (allow_version(otr, OTRNG_ALLOW_V3) && strstr(message, "?OTR:AAMC")) {
    otr->running_version = 3;
  }

  switch (otr->running_version) {
  case 3:
    return otrng_v3_receive_message(&response->to_send, &response->to_display,
                                    &response->tlvs, message, otr->v3_conn);
  case 4:
  case 0:
    return receive_message_v4_only(response, notif, message, otr);
  }

  return ERROR;
}
