// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#ifndef IYA_WSFED_H
#define IYA_WSFED_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct iya_wsfed_error {
  char code[64];
  char message[4096];
} iya_wsfed_error;

typedef struct iya_wsfed_resolved iya_wsfed_resolved;
typedef struct iya_wsfed_party iya_wsfed_party;
typedef struct iya_wsfed_login iya_wsfed_login;
typedef struct iya_wsfed_login_request iya_wsfed_login_request;
typedef struct iya_wsfed_keypair iya_wsfed_keypair;
typedef struct iya_wsfed_receiver iya_wsfed_receiver;
typedef struct iya_http_response iya_http_response;
typedef struct iya_http_server iya_http_server;

typedef struct iya_wsfed_subject {
  int has_person;
  char person[1024];
  int has_email;
  char email[1024];
  int has_idp_session;
  char idp_session[1024];
} iya_wsfed_subject;

typedef struct iya_wsfed_event {
  const char *type;
  const char *jti;
  const char *payload_json;
  int ended;
  int session_count;
  const char *const *sessions;
  int has_person;
  const char *person;
  int has_email;
  const char *email;
  int has_idp_session;
  const char *idp_session;
} iya_wsfed_event;

typedef int (*iya_wsfed_end_fn)(const iya_wsfed_event *event, void *user, char *err, size_t err_len);
typedef int (*iya_wsfed_handler_fn)(const iya_wsfed_event *event, void *user, char *err, size_t err_len);
typedef void (*iya_wsfed_log_fn)(const char *level, const char *message, void *user);
typedef void (*iya_http_handler_fn)(const char *method, const char *target, const char *body, void *user,
                                    int *status, char **response_body);

const char *iya_wsfed_status_success(void);
const char *iya_wsfed_rsa_sha256(void);
const char *iya_wsfed_default_subject(void);
const char *iya_wsfed_event_uri(const char *name);
int iya_wsfed_caep_count(void);
int iya_wsfed_risc_count(void);
int iya_wsfed_caep_has(const char *uri);
int iya_wsfed_risc_has(const char *uri);

iya_wsfed_resolved *iya_wsfed_resolve(const char *json, const char *base_dir, iya_wsfed_error *err);
const char *iya_wsfed_resolved_realm(const iya_wsfed_resolved *cfg);
const char *iya_wsfed_resolved_reply(const iya_wsfed_resolved *cfg);
const char *iya_wsfed_resolved_idp_metadata(const iya_wsfed_resolved *cfg);
int iya_wsfed_resolved_clock_skew_ms(const iya_wsfed_resolved *cfg);
int iya_wsfed_resolved_want_encrypted(const iya_wsfed_resolved *cfg);
int iya_wsfed_resolved_allow_unsolicited(const iya_wsfed_resolved *cfg);
int iya_wsfed_resolved_request_token_type(const iya_wsfed_resolved *cfg);
int iya_wsfed_resolved_signals_set(const iya_wsfed_resolved *cfg);
int iya_wsfed_resolved_signals(const iya_wsfed_resolved *cfg);
int iya_wsfed_resolved_has_key(const iya_wsfed_resolved *cfg);
const char *iya_wsfed_resolved_idp_ca(const iya_wsfed_resolved *cfg);
const char *iya_wsfed_resolved_idp_entity(const iya_wsfed_resolved *cfg);
void iya_wsfed_resolved_free(iya_wsfed_resolved *cfg);

iya_wsfed_party *iya_wsfed_party_create(const char *json, const char *base_dir, iya_wsfed_error *err);
const iya_wsfed_resolved *iya_wsfed_party_config(const iya_wsfed_party *party);
const char *iya_wsfed_party_idp_entity(const iya_wsfed_party *party);
const char *iya_wsfed_party_passive(const iya_wsfed_party *party);
int iya_wsfed_party_offers(const iya_wsfed_party *party, const char *token);
int iya_wsfed_party_signing_certs(const iya_wsfed_party *party);
char *iya_wsfed_party_metadata(const iya_wsfed_party *party);
void iya_wsfed_party_free(iya_wsfed_party *party);

typedef struct iya_wsfed_login_opts {
  int has_relay;
  const char *relay;
  int force_authn;
  int has_freshness;
  int freshness;
  const char *authentication_method;
  const char *home_realm;
  const char *const *param_keys;
  const char *const *param_values;
  int param_count;
} iya_wsfed_login_opts;

iya_wsfed_login_request *iya_wsfed_begin_login(iya_wsfed_party *party, const iya_wsfed_login_opts *opts,
                                         iya_wsfed_error *err);
const char *iya_wsfed_login_request_id(const iya_wsfed_login_request *req);
const char *iya_wsfed_login_request_url(const iya_wsfed_login_request *req);
const char *iya_wsfed_login_request_wctx(const iya_wsfed_login_request *req);
void iya_wsfed_login_request_free(iya_wsfed_login_request *req);

iya_wsfed_login *iya_wsfed_handle_reply(iya_wsfed_party *party, const char *method, const char *url,
                                        const char *body, const char *const *request_ids, int request_id_count,
                                        iya_wsfed_error *err);
const char *iya_wsfed_login_name_id(const iya_wsfed_login *login);
int iya_wsfed_login_has_format(const iya_wsfed_login *login);
const char *iya_wsfed_login_format(const iya_wsfed_login *login);
int iya_wsfed_login_has_session(const iya_wsfed_login *login);
const char *iya_wsfed_login_session(const iya_wsfed_login *login);
int iya_wsfed_login_has_relay(const iya_wsfed_login *login);
const char *iya_wsfed_login_relay(const iya_wsfed_login *login);
int iya_wsfed_login_has_request(const iya_wsfed_login *login);
const char *iya_wsfed_login_request_id_of(const iya_wsfed_login *login);
const char *iya_wsfed_login_trust(const iya_wsfed_login *login);
const char *iya_wsfed_login_realm(const iya_wsfed_login *login);
int iya_wsfed_login_encrypted(const iya_wsfed_login *login);
long long iya_wsfed_login_not_on_or_after_ms(const iya_wsfed_login *login);
int iya_wsfed_login_has_class(const iya_wsfed_login *login);
const char *iya_wsfed_login_class(const iya_wsfed_login *login);
int iya_wsfed_login_attr_count(const iya_wsfed_login *login, const char *name);
const char *iya_wsfed_login_attr_at(const iya_wsfed_login *login, const char *name, int index);
const char *iya_wsfed_login_friendly(const iya_wsfed_login *login, const char *name);
void iya_wsfed_login_free(iya_wsfed_login *login);

char *iya_wsfed_logout(iya_wsfed_party *party, const char *reply, iya_wsfed_error *err);
int iya_wsfed_is_signout(iya_wsfed_party *party, const char *method, const char *url, const char *body);

iya_wsfed_keypair *iya_wsfed_generate_keys(const char *common_name, int days, int bits, iya_wsfed_error *err);
const char *iya_wsfed_keypair_key(const iya_wsfed_keypair *pair);
const char *iya_wsfed_keypair_cert(const iya_wsfed_keypair *pair);
const char *iya_wsfed_keypair_cn(const iya_wsfed_keypair *pair);
void iya_wsfed_keypair_free(iya_wsfed_keypair *pair);

char *iya_wsfed_sign(const char *xml, const char *element_id, const char *key_pem, const char *cert_pem,
                     iya_wsfed_error *err);

int iya_wsfed_cli(int argc, char **argv);

int iya_wsfed_subject_of(const char *sub_json, const char *issuer, iya_wsfed_subject *out, iya_wsfed_error *err);
char *iya_wsfed_jws_verify(const char *token, const char *keys_json, iya_wsfed_error *err);

iya_wsfed_receiver *iya_wsfed_receiver_new(const char *transmitter, iya_wsfed_end_fn on_end, void *user,
                                           int poll_interval_ms, iya_wsfed_log_fn log, void *log_user,
                                           iya_wsfed_error *err);
int iya_wsfed_receiver_start(iya_wsfed_receiver *receiver, iya_wsfed_error *err);
void iya_wsfed_receiver_stop(iya_wsfed_receiver *receiver);
int iya_wsfed_receiver_poll(iya_wsfed_receiver *receiver, int *more, iya_wsfed_error *err);
void iya_wsfed_receiver_on(iya_wsfed_receiver *receiver, const char *event_type, iya_wsfed_handler_fn handler,
                           void *user);
void iya_wsfed_receiver_track(iya_wsfed_receiver *receiver, const char *local_id, const char *name_id,
                              const char *name_id_format, const char *session_index, const char *subject_value,
                              const char *email);
int iya_wsfed_receiver_person_count(iya_wsfed_receiver *receiver, const char *person);
const char *iya_wsfed_receiver_person_id(iya_wsfed_receiver *receiver, const char *person, int index);
const char *iya_wsfed_receiver_stream_id(iya_wsfed_receiver *receiver);
void iya_wsfed_receiver_free(iya_wsfed_receiver *receiver);

iya_http_server *iya_http_serve(iya_http_handler_fn handler, void *user, int *port);
void iya_http_server_close(iya_http_server *server);

iya_http_response *iya_http_call(const char *method, const char *url, const char *content_type, const char *body,
                                 const char *cookie, iya_wsfed_error *err);
int iya_http_status(const iya_http_response *response);
const char *iya_http_body(const iya_http_response *response);
int iya_http_header_count(const iya_http_response *response, const char *name);
const char *iya_http_header_at(const iya_http_response *response, const char *name, int index);
void iya_http_response_free(iya_http_response *response);

void iya_wsfed_string_free(char *value);

#ifdef __cplusplus
}
#endif

#endif
