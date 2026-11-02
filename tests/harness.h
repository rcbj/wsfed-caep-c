// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#ifndef WSFED_HARNESS_H
#define WSFED_HARNESS_H

#include "iya_wsfed.h"

#include <stddef.h>

#define REALM "https://rp.test/"
#define REPLY "https://rp.test/wsfed"
#define IDP_ENTITY "https://idp.test"
#define PASSIVE "https://idp.test/wsfed"
#define SAML2 "urn:oasis:names:tc:SAML:2.0:assertion"

typedef struct AssertionOpt {
  const char *audience;
  int recipient_set;
  const char *recipient;
  const char *in_response_to;
  int not_on_set;
  int not_on_ms;
  const char *issuer;
  const char *name_id;
  const char *session;
  const char *extra;
  int bare;
  int no_conditions_expiry;
} AssertionOpt;

void harness_begin(const char *name);
void die(const char *msg);
void dief(const char *fmt, ...);
int msg_has(const char *msg, const char *pat);
void expect_err(int failed, const iya_wsfed_error *err, const char *code, const char *pat);
void ensure_keys(void);
const char *rp_key_pem(void);
const char *rp_cert_pem(void);
const char *idp_key_pem(void);
const char *idp_cert_pem(void);
const char *default_meta_path(void);
char *write_temp(const char *body);
char *meta_custom(const char *fed, int no_sts, const char *key_in, const char *types);
char *cfg_json(const char *meta_path, int keys_mode, const char *extra);
iya_wsfed_party *must_party(const char *json);
void must_fail_party(const char *json, const char *code, const char *pat);
char *assertion_xml(const AssertionOpt *opt, char *id_out, size_t id_len);
char *sign_xml(const char *xml, const char *id, const char *key_pem, const char *cert_pem);
char *signed_assertion(const AssertionOpt *opt, char *id_out, size_t id_len);
char *wresult_xml(const char *token, const char *trust, const char *applies, const char *token_type, int expires_ms,
                  int expires_set);
char *encrypt_xml(const char *plain, const char *cipher, const char *transport, const char *wrapper);
char *form_body(const char *wresult, const char *wctx);
iya_wsfed_login *submit(iya_wsfed_party *party, const char *result, const char *wctx, const char *const *ids, int n,
                        iya_wsfed_error *err);
void expect_submit(iya_wsfed_party *party, const char *result, const char *wctx, const char *const *ids, int n,
                   const char *code, const char *pat);
char *query_get(const char *url, const char *key);
char *query_unescape_dup(const char *in);
long long wall_ms(void);
char *pem_body(const char *pem);
int contains(const char *hay, const char *needle);

#endif
