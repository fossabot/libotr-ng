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

#include "otrng.h"

#include <libotr/b64.h>
#include <libotr/mem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define OTRNG_OTRNG_PRIVATE

#include "constants.h"
#include "dake.h"
#include "data_message.h"
#include "deserialize.h"
#include "gcrypt.h"
#include "instance_tag.h"
#include "padding.h"
#include "random.h"
#include "receive.h"
#include "serialize.h"
#include "shake.h"
#include "smp.h"
#include "tlv.h"

#include "debug.h"

#define QUERY_MESSAGE_TAG_BYTES 5

tstatic void gone_insecure_cb_v4(const otrng_conversation_state_s *conv) {
  if (!conv || !conv->client || !conv->client->callbacks ||
      !conv->client->callbacks->gone_insecure) {
    return;
  }

  conv->client->callbacks->gone_insecure(conv);
}

/* dst must be at least 3 bytes long. */
tstatic void allowed_versions(string_p dst, const otrng_s *otr) {
  if (allow_version(otr, OTRNG_ALLOW_V4)) {
    *dst++ = '4';
  }

  if (allow_version(otr, OTRNG_ALLOW_V3)) {
    *dst++ = '3';
  }

  *dst = 0;
}

INTERNAL otrng_err otrng_build_query_message(string_p *dst,
                                             const string_p message,
                                             otrng_s *otr) {
  if (otr->state == OTRNG_STATE_ENCRYPTED_MESSAGES) {
    return ERROR;
  }

  /* size = qm tag + versions + msg length + versions
   * + question mark + whitespace + null byte */
  size_t qm_size = QUERY_MESSAGE_TAG_BYTES + 3 + strlen(message) + 2 + 1;
  string_p buff = NULL;
  char allowed[3] = {0};
  *dst = NULL;

  buff = malloc(qm_size);
  if (!buff) {
    return ERROR;
  }

  allowed_versions(allowed, otr);

  char *cursor = otrng_stpcpy(buff, QUERY_HEADER);
  cursor = otrng_stpcpy(cursor, allowed);
  cursor = otrng_stpcpy(cursor, "? ");

  int rem = cursor - buff;

  /* Add '\0' */
  if (*otrng_stpncpy(cursor, message, qm_size - rem)) {
    free(buff);
    return ERROR; /* could not zero-terminate the string */
  }

  if (otr->sending_init_msg) {
    free(otr->sending_init_msg);
  }

  otr->sending_init_msg = otrng_strdup(buff);
  *dst = buff;

  return SUCCESS;
}

API otrng_err otrng_build_whitespace_tag(string_p *whitespace_tag,
                                         const string_p message, otrng_s *otr) {
  int allows_v4 = allow_version(otr, OTRNG_ALLOW_V4);
  int allows_v3 = allow_version(otr, OTRNG_ALLOW_V3);
  string_p cursor = NULL;

  char *buff = malloc(WHITESPACE_TAG_MAX_BYTES + strlen(message) + 1);
  if (!buff) {
    return ERROR;
  }

  cursor = otrng_stpcpy(buff, INSTANCE_TAG_BASE);

  if (allows_v4) {
    cursor = otrng_stpcpy(cursor, INSTANCE_TAG_V4);
  }

  if (allows_v3) {
    cursor = otrng_stpcpy(cursor, INSTANCE_TAG_V3);
  }

  otrng_stpcpy(cursor, message);

  if (otr->sending_init_msg) {
    free(otr->sending_init_msg);
  }

  otr->sending_init_msg = otrng_strdup(buff);
  *whitespace_tag = buff;

  return SUCCESS;
}

tstatic otrng_err generate_tmp_key_r(uint8_t *dst, otrng_s *otr) {
  k_ecdh_p tmp_ecdh_k1;
  k_ecdh_p tmp_ecdh_k2;
  k_ecdh_p k_ecdh;

  // TODO: @refactoring this will be calculated again later
  if (!otrng_ecdh_shared_secret(k_ecdh, otr->keys->our_ecdh,
                                otr->keys->their_ecdh)) {
    return ERROR;
  }

  dh_shared_secret_p k_dh;
  size_t k_dh_len = 0;
  // TODO: @refactoring this will be calculated again later
  if (!otrng_dh_shared_secret(k_dh, &k_dh_len, otr->keys->our_dh->priv,
                              otr->keys->their_dh)) {
    return ERROR;
  }

  brace_key_p brace_key;
  hash_hash(brace_key, sizeof(brace_key_p), k_dh, k_dh_len);

  sodium_memzero(k_dh, sizeof(k_dh));

#ifdef DEBUG
  printf("\n");
  printf("GENERATING TEMP KEY R\n");
  printf("K_ecdh = ");
  otrng_memdump(k_ecdh, sizeof(k_ecdh_p));
  printf("brace_key = ");
  otrng_memdump(brace_key, sizeof(brace_key_p));
#endif

  if (!otrng_ecdh_shared_secret(tmp_ecdh_k1, otr->keys->our_ecdh,
                                otr->keys->their_shared_prekey)) {
    return ERROR;
  }

  if (!otrng_ecdh_shared_secret(tmp_ecdh_k2, otr->keys->our_ecdh,
                                otr->their_client_profile->long_term_pub_key)) {
    return ERROR;
  }

  otrng_key_manager_calculate_tmp_key(dst, k_ecdh, brace_key, tmp_ecdh_k1,
                                      tmp_ecdh_k2);

#ifdef DEBUG
  printf("\n");
  printf("GENERATING TEMP KEY R\n");
  printf("tmp_key_r = ");
  otrng_memdump(dst, HASH_BYTES);
#endif

  sodium_memzero(tmp_ecdh_k1, ED448_POINT_BYTES);
  sodium_memzero(tmp_ecdh_k2, ED448_POINT_BYTES);

  return SUCCESS;
}

tstatic otrng_err serialize_and_encode_non_interactive_auth(
    string_p *dst, const dake_non_interactive_auth_message_s *m) {
  uint8_t *buff = NULL;
  size_t len = 0;

  if (!otrng_dake_non_interactive_auth_message_asprintf(&buff, &len, m)) {
    return ERROR;
  }

  *dst = otrl_base64_otr_encode(buff, len);

  free(buff);
  return SUCCESS;
}

tstatic void
non_interactive_auth_message_init(dake_non_interactive_auth_message_p auth,
                                  otrng_s *otr) {
  auth->sender_instance_tag = otr->our_instance_tag;
  auth->receiver_instance_tag = otr->their_instance_tag;
  otrng_client_profile_copy(auth->profile, get_my_client_profile(otr));

  // TODO: is this set?
  otrng_ec_point_copy(auth->X, our_ecdh(otr));
  auth->A = otrng_dh_mpi_copy(our_dh(otr));

  auth->prekey_message_id = 0;
  auth->long_term_key_id = 0;
  auth->prekey_profile_id = 0;
}

tstatic otrng_err build_non_interactive_auth_message(
    dake_non_interactive_auth_message_p auth, otrng_s *otr) {
  non_interactive_auth_message_init(auth, otr);

  auth->prekey_message_id = otr->their_prekeys_id;
  otr->their_prekeys_id = 0;

  auth->long_term_key_id = otr->their_client_profile->id;
  auth->prekey_profile_id = otr->their_prekey_profile->id;

  /* tmp_k = KDF_1(usage_tmp_key || K_ecdh || ECDH(x, their_shared_prekey) ||
     ECDH(x, Pkb) || brace_key)
     @secret this should be deleted when the mixed shared secret is generated
  */
  if (!generate_tmp_key_r(otr->keys->tmp_key, otr)) {
    return ERROR;
  }

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
  if (!generate_phi_receiving(&phi, &phi_len, otr)) {
    return ERROR;
  }

  unsigned char *t = NULL;
  size_t t_len = 0;

  /* t = KDF_1(0x0E || Bobs_Client_Profile, 64) || KDF_1(0x0F ||
   * Alices_Client_Profile, 64) || Y || X || B || A || their_shared_prekey ||
   * KDF_1(0x10 || phi, 64) */
  if (!build_non_interactive_rsign_tag(&t, &t_len, initiator, responder,
                                       otr->keys->their_shared_prekey, phi,
                                       phi_len)) {
    free(phi);
    return ERROR;
  }

  free(phi);

  /* sigma = RSig(H_a, sk_ha, {H_b, H_a, Y}, t) */
  otrng_rsig_authenticate(
      auth->sigma, otr->conversation->client->keypair->priv, /* sk_ha */
      otr->conversation->client->keypair->pub,               /* H_a */
      otr->their_client_profile->long_term_pub_key,          /* H_b */
      otr->conversation->client->keypair->pub,               /* H_a */
      their_ecdh(otr),                                       /* Y */
      t, t_len);

  otrng_err ret = otrng_dake_non_interactive_auth_message_authenticator(
      auth->auth_mac, auth, t, t_len, otr->keys->tmp_key);

  free(t);

  return ret;
}

tstatic otrng_err reply_with_non_interactive_auth_msg(string_p *dst,
                                                      otrng_s *otr) {
  maybe_create_keys(otr->conversation);

  dake_non_interactive_auth_message_p auth;
  otrng_err ret = build_non_interactive_auth_message(auth, otr);

  if (ret == SUCCESS) {
    ret = serialize_and_encode_non_interactive_auth(dst, auth);
  }

  if (!otrng_key_manager_generate_shared_secret(otr->keys, false)) {
    return ERROR;
  }

  if (!double_ratcheting_init(otr, 't')) {
    return ERROR;
  }

  otrng_dake_non_interactive_auth_message_destroy(auth);
  return ret;
}

// TODO: @non_interactive Should maybe return a serialized ensemble, ready to
// publish to the server
INTERNAL prekey_ensemble_s *otrng_build_prekey_ensemble(otrng_s *otr) {
  prekey_ensemble_s *ensemble = malloc(sizeof(prekey_ensemble_s));
  if (!ensemble) {
    return NULL;
  }

  otrng_client_profile_copy(ensemble->client_profile,
                            get_my_client_profile(otr));
  otrng_prekey_profile_copy(ensemble->prekey_profile,
                            get_my_prekey_profile(otr));

  ecdh_keypair_p ecdh;
  dh_keypair_p dh;
  otrng_generate_ephemeral_keys(ecdh, dh);
  ensemble->message = otrng_dake_prekey_message_build(otr->our_instance_tag,
                                                      ecdh->pub, dh->pub);
  if (!ensemble->message) {
    otrng_prekey_ensemble_free(ensemble);
    return NULL;
  }

  // TODO: @client @non_interactive should this ID be random? It should probably
  // be unique for us, so we need to store this in client state (?)
  ensemble->message->id = 0x301;

  otrng_client_state_s *state = otr->conversation->client;
  store_my_prekey_message(ensemble->message->id, otr->our_instance_tag, ecdh,
                          dh, state);
  otrng_ecdh_keypair_destroy(ecdh);
  otrng_dh_keypair_destroy(dh);

  return ensemble;
}

tstatic otrng_err set_their_client_profile(const client_profile_s *profile,
                                           otrng_s *otr) {
  // The protocol is already committed to a specific profile, and receives an
  // ensemble with another profile.
  // How should the protocol behave? I am failling for now.
  if (otr->their_client_profile) {
    return ERROR;
  }

  otr->their_client_profile = malloc(sizeof(client_profile_s));
  if (!otr->their_client_profile) {
    return ERROR;
  }

  otrng_client_profile_copy(otr->their_client_profile, profile);

  return SUCCESS;
}

tstatic otrng_err
set_their_prekey_profile(const otrng_prekey_profile_s *profile, otrng_s *otr) {
  // The protocol is already committed to a specific profile, and receives an
  // ensemble with another profile.
  // How should the protocol behave? I am failling for now.
  if (otr->their_prekey_profile) {
    return ERROR;
  }

  otr->their_prekey_profile = malloc(sizeof(otrng_prekey_profile_s));
  if (!otr->their_prekey_profile) {
    return ERROR;
  }

  otrng_prekey_profile_copy(otr->their_prekey_profile, profile);

  // TODO: @refactoring Extract otrng_key_manager_set_their_shared_prekey()
  otrng_ec_point_copy(otr->keys->their_shared_prekey,
                      otr->their_prekey_profile->shared_prekey);

  return SUCCESS;
}

tstatic otrng_err prekey_message_received(const dake_prekey_message_s *m,
                                          otrng_notif notif, otrng_s *otr) {
  if (!otr->their_client_profile) {
    return ERROR;
  }

  if (!otr->their_prekey_profile) {
    return ERROR;
  }

  if (!received_sender_instance_tag(m->sender_instance_tag, otr)) {
    notif = NOTIF_MALFORMED;
    return ERROR;
  }

  if (!otrng_valid_received_values(m->sender_instance_tag, m->Y, m->B,
                                   otr->their_client_profile)) {
    return ERROR;
  }

  otr->their_prekeys_id = m->id; // Stores to send in the non-interactive-auth
  otrng_key_manager_set_their_ecdh(m->Y, otr->keys);
  otrng_key_manager_set_their_dh(m->B, otr->keys);

  if (!otrng_key_manager_generate_ephemeral_keys(otr->keys)) {
    return ERROR;
  }

  return SUCCESS;
}

tstatic otrng_err receive_prekey_ensemble(string_p *dst,
                                          const prekey_ensemble_s *ensemble,
                                          otrng_s *otr) {
  if (!otrng_prekey_ensemble_validate(ensemble)) {
    return ERROR;
  }

  // TODO: @client_profile As part of validating the prekey ensemble, we should
  // also:
  // 1. If the Transitional Signature is present, verify its validity using the
  // OTRv3 DSA key.
  //    (the OTRv3 key needed to validate the signature should be somewhere in
  //    client_state maybe).
  // 1. Check if the Client Profile's version is supported by the receiver.

  // TODO: @non_interactive Decide whether to send a message using this Prekey
  // Ensemble if the long-term key within the Client Profile is trusted or not.
  // Maybe use a callback for this.

  if (!set_their_client_profile(ensemble->client_profile, otr)) {
    return ERROR;
  }

  if (!set_their_prekey_profile(ensemble->prekey_profile, otr)) {
    return ERROR;
  }

  otrng_notif notif = NOTIF_NONE;
  // Set their ephemeral keys, instance tag, and their_prekeys_id
  if (!prekey_message_received(ensemble->message, notif, otr)) {
    if (notif == NOTIF_MALFORMED) {
      otrng_error_message(dst, ERR_MSG_MALFORMED);
    }
    return ERROR;
  }

  return SUCCESS;
}

API otrng_err otrng_send_offline_message(string_p *dst,
                                         const prekey_ensemble_s *ensemble,
                                         otrng_s *otr) {
  *dst = NULL;

  // TODO: @non_interactive Would deserialize the received ensemble and set the
  // running version
  otr->running_version = 4;

  if (!receive_prekey_ensemble(dst, ensemble, otr)) {
    return ERROR; // should unset the stored things from ensemble
  }

  return reply_with_non_interactive_auth_msg(dst, otr);
}

// TODO: @refactoring this is the same as otrng_close
INTERNAL otrng_err otrng_expire_session(string_p *to_send, otrng_s *otr) {
  size_t serlen = otrng_list_len(otr->keys->skipped_keys) * MAC_KEY_BYTES;
  uint8_t *ser_mac_keys = otrng_reveal_mac_keys_on_tlv(otr->keys);
  otr->keys->skipped_keys = NULL;

  tlv_list_s *disconnected = otrng_tlv_list_one(
      otrng_tlv_new(OTRNG_TLV_DISCONNECTED, serlen, ser_mac_keys));
  free(ser_mac_keys);

  if (!disconnected) {
    return ERROR;
  }

  otrng_notif notif = NOTIF_NONE;
  otrng_err result = otrng_send_message(to_send, "", notif, disconnected,
                                        MSGFLAGS_IGNORE_UNREADABLE, otr);

  forget_our_keys(otr);
  otr->state = OTRNG_STATE_START;
  gone_insecure_cb_v4(otr->conversation);

  return result;
}

/* Receive a possibly OTR message. */
INTERNAL otrng_err otrng_receive_message(otrng_response_s *response,
                                         otrng_notif notif,
                                         const string_p message, otrng_s *otr) {
  response->warning = OTRNG_WARN_NONE;
  response->to_display = otrng_strndup(NULL, 0);

  char *defrag = NULL;
  if (!otrng_unfragment_message(&defrag, &otr->pending_fragments, message,
                                otr->our_instance_tag)) {
    return ERROR;
  }

  otrng_err ret =
      otrng_receive_defragmented_message(response, notif, defrag, otr);
  free(defrag);
  return ret;
}

tstatic otrng_err otrng_close_v4(string_p *to_send, otrng_s *otr) {
  if (otr->state != OTRNG_STATE_ENCRYPTED_MESSAGES) {
    return SUCCESS;
  }

  size_t serlen = otrng_list_len(otr->keys->skipped_keys) * MAC_KEY_BYTES;
  uint8_t *ser_mac_keys = otrng_reveal_mac_keys_on_tlv(otr->keys);
  otr->keys->skipped_keys = NULL;

  tlv_list_s *disconnected = otrng_tlv_list_one(
      otrng_tlv_new(OTRNG_TLV_DISCONNECTED, serlen, ser_mac_keys));
  free(ser_mac_keys);

  if (!disconnected) {
    return ERROR;
  }

  otrng_notif notif = NOTIF_NONE;
  otrng_err result = otrng_send_message(to_send, "", notif, disconnected,
                                        MSGFLAGS_IGNORE_UNREADABLE, otr);

  otrng_tlv_list_free(disconnected);
  forget_our_keys(otr);
  otr->state = OTRNG_STATE_START;
  gone_insecure_cb_v4(otr->conversation);

  return result;
}

INTERNAL otrng_err otrng_close(string_p *to_send, otrng_s *otr) {
  if (!otr) {
    return ERROR;
  }

  switch (otr->running_version) {
  case 3:
    otrng_v3_close(to_send,
                   otr->v3_conn); // TODO: @client This should return an error
                                  // but errors are reported on a
                                  // callback
    gone_insecure_cb_v4(otr->conversation); // TODO: @client Only if success
    return SUCCESS;
  case 4:
    return otrng_close_v4(to_send, otr);
  case 0:
    return ERROR;
  }

  return ERROR;
}

tstatic otrng_err otrng_send_symkey_message_v4(string_p *to_send,
                                               unsigned int use,
                                               const unsigned char *usedata,
                                               size_t usedatalen, otrng_s *otr,
                                               unsigned char *extra_key) {
  if (usedatalen > 0 && !usedata) {
    return ERROR;
  }

  if (otr->state != OTRNG_STATE_ENCRYPTED_MESSAGES) {
    return ERROR;
  }

  unsigned char *tlv_data = malloc(usedatalen + 4);

  tlv_data[0] = (use >> 24) & 0xff;
  tlv_data[1] = (use >> 16) & 0xff;
  tlv_data[2] = (use >> 8) & 0xff;
  tlv_data[3] = (use)&0xff;

  if (usedatalen > 0) {
    memmove(tlv_data + 4, usedata, usedatalen);
  }

  memmove(extra_key, otr->keys->extra_symmetric_key, EXTRA_SYMMETRIC_KEY_BYTES);

  tlv_list_s *tlvs = otrng_tlv_list_one(
      otrng_tlv_new(OTRNG_TLV_SYM_KEY, usedatalen + 4, tlv_data));
  free(tlv_data);

  // TODO: @freeing Should not extra_key be zeroed if any error happens from
  // here on?
  if (!tlvs) {
    return ERROR;
  }

  otrng_notif notif = NOTIF_NONE;
  // TODO: @refactoring in v3 the extra_key is passed as a param to this
  // do the same?
  otrng_err ret = otrng_send_message(to_send, "", notif, tlvs,
                                     MSGFLAGS_IGNORE_UNREADABLE, otr);
  otrng_tlv_list_free(tlvs);

  return ret;
}

API otrng_err otrng_send_symkey_message(string_p *to_send, unsigned int use,
                                        const unsigned char *usedata,
                                        size_t usedatalen, uint8_t *extra_key,
                                        otrng_s *otr) {
  if (!otr) {
    return ERROR;
  }

  switch (otr->running_version) {
  case 3:
    otrng_v3_send_symkey_message(to_send, otr->v3_conn, use, usedata,
                                 usedatalen,
                                 extra_key); // TODO: @client This should return
                                             // an error but errors are reported
                                             // on a callback
    return SUCCESS;
  case 4:
    return otrng_send_symkey_message_v4(to_send, use, usedata, usedatalen, otr,
                                        extra_key);
  case 0:
    return ERROR;
  }

  return ERROR;
}

static int otrl_initialized = 0;
API void otrng_v3_init(void) {
  if (otrl_initialized) {
    return;
  }

  if (otrl_init(OTRL_VERSION_MAJOR, OTRL_VERSION_MINOR, OTRL_VERSION_SUB)) {
    exit(1);
  }

  otrl_initialized = 1;
}

char *
otrng_generate_session_state_string(const otrng_shared_session_state_s *state) {
  if (!state || !state->identifier1 || !state->identifier2) {
    return NULL;
  }

  char *sss;
  size_t sss_len = strlen(state->identifier1) + strlen(state->identifier2) + 1;
  if (state->password) {
    sss_len += strlen(state->password);
  }

  sss = malloc(sss_len);
  if (!sss) {
    return NULL;
  }

  if (strcmp(state->identifier1, state->identifier2) < 0) {
    strcpy(sss, state->identifier1);
    strcat(sss, state->identifier2);
  } else {
    strcpy(sss, state->identifier2);
    strcat(sss, state->identifier1);
  }

  if (state->password) {
    strcat(sss, state->password);
  }

  return sss;
}
