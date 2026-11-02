// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "harness.h"

#include <openssl/bio.h>
#include <openssl/evp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static char *replace_first(const char *s, const char *from, const char *to) {
  const char *at = strstr(s, from);
  if (!at) return strdup(s);
  size_t head = (size_t)(at - s);
  size_t n = head + strlen(to) + strlen(at + strlen(from));
  char *out = malloc(n + 1);
  memcpy(out, s, head);
  memcpy(out + head, to, strlen(to));
  strcpy(out + head + strlen(to), at + strlen(from));
  return out;
}

static char *replace_id(const char *xml, const char *id) {
  const char *at = strstr(xml, "ID=\"");
  if (!at) die("no ID");
  const char *end = strchr(at + 4, '"');
  if (!end) die("no ID end");
  size_t n = strlen(xml) - (size_t)(end - (at + 4)) + strlen(id);
  char *out = malloc(n + 1);
  size_t head = (size_t)(at + 4 - xml);
  memcpy(out, xml, head);
  memcpy(out + head, id, strlen(id));
  strcpy(out + head + strlen(id), end);
  return out;
}

static const char *one = "_r";
static const char *const ids_r[] = {"_r"};

static iya_wsfed_login *post_id(iya_wsfed_party *party, const char *result, const char *id) {
  char wctx[128];
  snprintf(wctx, sizeof wctx, "id=%s", id);
  const char *ids[] = {id};
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  iya_wsfed_login *login = submit(party, result, wctx, ids, 1, &err);
  if (!login) die(err.message);
  return login;
}

static void TestConfigurationRequiresRealmReplyAndAMatchingKey(void) {
  char *json = cfg_json(NULL, 1, "\"realm\":\"\"");
  must_fail_party(json, "config", "realm");
  free(json);
  json = cfg_json(NULL, 1, "\"replyUrl\":\"/wsfed\"");
  must_fail_party(json, "config", "absolute");
  free(json);
  json = cfg_json(NULL, 2, NULL);
  must_fail_party(json, "config", "not for the private key");
  free(json);
  json = cfg_json(NULL, 3, NULL);
  must_fail_party(json, "config", "together");
  free(json);
  json = cfg_json(NULL, 0, "\"wantAssertionsEncrypted\":true");
  must_fail_party(json, "config", "needs privateKey");
  free(json);
  json = cfg_json(NULL, 0, NULL);
  iya_wsfed_party *party = must_party(json);
  char *meta = iya_wsfed_party_metadata(party);
  if (contains(meta, "KeyDescriptor")) die("keyless metadata named a key");
  iya_wsfed_string_free(meta);
  iya_wsfed_party_free(party);
  free(json);
}

static void resolve_check(const char *json, int signals_set, int signals) {
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  iya_wsfed_resolved *cfg = iya_wsfed_resolve(json, "", &err);
  if (!cfg) die(err.message);
  if (iya_wsfed_resolved_signals_set(cfg) != signals_set || iya_wsfed_resolved_signals(cfg) != signals) die("signals");
  if (strcmp(iya_wsfed_resolved_realm(cfg), REALM) != 0 || strcmp(iya_wsfed_resolved_reply(cfg), REPLY) != 0) die("endpoints");
  if (!iya_wsfed_resolved_request_token_type(cfg)) die("requestTokenType");
  iya_wsfed_resolved_free(cfg);
}

static void TestSignalsOmittedOrTrueIsLeftOff(void) {
  const char *base =
      "{\"realm\":\"https://rp.test/\",\"replyUrl\":\"https://rp.test/wsfed\",\"idpMetadata\":\"https://idp.example/"
      "FederationMetadata/2007-06/FederationMetadata.xml\"}";
  resolve_check(base, 0, 0);
  const char *on =
      "{\"realm\":\"https://rp.test/\",\"replyUrl\":\"https://rp.test/wsfed\",\"idpMetadata\":\"https://idp.example/"
      "FederationMetadata/2007-06/FederationMetadata.xml\",\"signals\":true}";
  resolve_check(on, 0, 0);
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  iya_wsfed_resolved *a = iya_wsfed_resolve(base, "", &err);
  iya_wsfed_resolved *b = iya_wsfed_resolve(on, "", &err);
  if (strcmp(iya_wsfed_resolved_idp_metadata(a), iya_wsfed_resolved_idp_metadata(b)) != 0) die("metadata");
  if (iya_wsfed_resolved_clock_skew_ms(a) != iya_wsfed_resolved_clock_skew_ms(b)) die("skew");
  iya_wsfed_resolved_free(a);
  iya_wsfed_resolved_free(b);
}

static void TestSignalsFalseIsRecorded(void) {
  const char *base =
      "{\"realm\":\"https://rp.test/\",\"replyUrl\":\"https://rp.test/wsfed\",\"idpMetadata\":\"https://idp.example/"
      "FederationMetadata/2007-06/FederationMetadata.xml\"}";
  const char *off =
      "{\"realm\":\"https://rp.test/\",\"replyUrl\":\"https://rp.test/wsfed\",\"idpMetadata\":\"https://idp.example/"
      "FederationMetadata/2007-06/FederationMetadata.xml\",\"signals\":false}";
  resolve_check(off, 1, 0);
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  iya_wsfed_resolved *a = iya_wsfed_resolve(base, "", &err);
  iya_wsfed_resolved *b = iya_wsfed_resolve(off, "", &err);
  if (iya_wsfed_resolved_signals_set(a)) die("omitted was recorded");
  if (strcmp(iya_wsfed_resolved_realm(a), iya_wsfed_resolved_realm(b)) != 0) die("realm");
  if (strcmp(iya_wsfed_resolved_reply(a), iya_wsfed_resolved_reply(b)) != 0) die("reply");
  if (strcmp(iya_wsfed_resolved_idp_metadata(a), iya_wsfed_resolved_idp_metadata(b)) != 0) die("metadata");
  if (strcmp(iya_wsfed_resolved_idp_metadata(b), "https://idp.example/FederationMetadata/2007-06/FederationMetadata.xml") != 0)
    die("idp metadata");
  iya_wsfed_resolved_free(a);
  iya_wsfed_resolved_free(b);
}

static void TestSignalsMustBeTrueOrFalse(void) {
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  iya_wsfed_resolved *cfg = iya_wsfed_resolve(
      "{\"realm\":\"https://rp.test/\",\"replyUrl\":\"https://rp.test/wsfed\",\"idpMetadata\":\"https://idp.example/"
      "metadata\",\"signals\":\"no\"}",
      "", &err);
  if (cfg) die("accepted");
  expect_err(1, &err, "config", NULL);
  if (strcmp(err.message, "signals must be true or false") != 0) die(err.message);
}

static void TestReadsTheSecurityTokenServiceRole(void) {
  char *json = cfg_json(NULL, 1, NULL);
  iya_wsfed_party *party = must_party(json);
  if (strcmp(iya_wsfed_party_idp_entity(party), IDP_ENTITY) != 0) die("entity");
  if (strcmp(iya_wsfed_party_passive(party), PASSIVE) != 0) die("passive");
  if (!iya_wsfed_party_offers(party, SAML2)) die("token");
  if (iya_wsfed_party_signing_certs(party) != 1) die("certs");
  iya_wsfed_party_free(party);
  free(json);
}

static void TestXsiTypeAndIdpRoleFallback(void) {
  char *path = meta_custom("wsfed", 0, "sts", NULL);
  char *json = cfg_json(path, 1, NULL);
  iya_wsfed_party *party = must_party(json);
  if (strcmp(iya_wsfed_party_passive(party), PASSIVE) != 0) die("prefix");
  iya_wsfed_party_free(party);
  free(json);
  free(path);
  path = meta_custom("fed", 0, "idpsso", NULL);
  json = cfg_json(path, 1, NULL);
  party = must_party(json);
  if (iya_wsfed_party_signing_certs(party) != 1) die("fallback key");
  iya_wsfed_party_free(party);
  free(json);
  free(path);
}

static void TestRefusesMetadataWithoutAnSTSOrSAML2(void) {
  char *path = meta_custom("fed", 1, "sts", NULL);
  char *json = cfg_json(path, 1, NULL);
  must_fail_party(json, "metadata", "SecurityTokenServiceType");
  free(json);
  free(path);
  path = meta_custom("fed", 0, "sts", "<fed:TokenType Uri=\"urn:oasis:names:tc:SAML:1.0:assertion\"/>");
  json = cfg_json(path, 1, NULL);
  must_fail_party(json, "metadata", "no SAML 2.0");
  free(json);
  free(path);
}

static void TestWritesApplicationServiceMetadata(void) {
  char *json = cfg_json(NULL, 1, NULL);
  iya_wsfed_party *party = must_party(json);
  char *xml = iya_wsfed_party_metadata(party);
  char want_entity[128];
  snprintf(want_entity, sizeof want_entity, "entityID=\"%s\"", REALM);
  if (!contains(xml, want_entity)) die(xml);
  if (!contains(xml, "xsi:type=\"fed:ApplicationServiceType\"")) die(xml);
  char passive[256];
  snprintf(passive, sizeof passive, "<fed:PassiveRequestorEndpoint><wsa:EndpointReference><wsa:Address>%s</wsa:Address>",
           REPLY);
  if (!contains(xml, passive)) die(xml);
  char scope[256];
  snprintf(scope, sizeof scope, "<fed:TargetScopes><wsa:EndpointReference><wsa:Address>%s</wsa:Address>", REALM);
  if (!contains(xml, scope)) die(xml);
  if (!contains(xml, "<md:KeyDescriptor use=\"encryption\">") || !contains(xml, "xmlenc11#aes256-gcm")) die(xml);
  iya_wsfed_string_free(xml);
  iya_wsfed_party_free(party);
  free(json);
}

static iya_wsfed_login_request *must_login(iya_wsfed_party *party, const iya_wsfed_login_opts *opts) {
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  iya_wsfed_login_request *req = iya_wsfed_begin_login(party, opts, &err);
  if (!req) die(err.message);
  return req;
}

static void TestSigninNamesRealmReplyWctxAndSAML2(void) {
  char *json = cfg_json(NULL, 1, NULL);
  iya_wsfed_party *party = must_party(json);
  iya_wsfed_login_opts opts;
  memset(&opts, 0, sizeof opts);
  opts.has_relay = 1;
  opts.relay = "/home é";
  iya_wsfed_login_request *req = must_login(party, &opts);
  const char *url = iya_wsfed_login_request_url(req);
  if (strncmp(url, PASSIVE, strlen(PASSIVE)) != 0 || url[strlen(PASSIVE)] != '?') die(url);
  char *wa = query_get(url, "wa");
  char *realm = query_get(url, "wtrealm");
  char *reply = query_get(url, "wreply");
  char *wctx = query_get(url, "wctx");
  char *wreq = query_get(url, "wreq");
  char *wct = query_get(url, "wct");
  char *wfresh = query_get(url, "wfresh");
  if (!wa || strcmp(wa, "wsignin1.0") != 0 || !realm || strcmp(realm, REALM) != 0 || !reply || strcmp(reply, REPLY) != 0)
    die("params");
  char *wctx_q = malloc(strlen(wctx ? wctx : "") + 2);
  sprintf(wctx_q, "?%s", wctx ? wctx : "");
  char *id = query_get(wctx_q, "id");
  char *ru = query_get(wctx_q, "ru");
  free(wctx_q);
  if (!id || strcmp(id, iya_wsfed_login_request_id(req)) != 0 || !ru || strcmp(ru, "/home é") != 0) die(wctx ? wctx : "wctx");
  if (!wreq || !contains(wreq, "<wst:TokenType>urn:oasis:names:tc:SAML:2.0:assertion</wst:TokenType>")) die(wreq);
  if (!wct || strlen(wct) != 20 || wct[4] != '-' || wct[10] != 'T' || wct[19] != 'Z') die(wct);
  if (wfresh) die("wfresh");
  free(wa);
  free(realm);
  free(reply);
  free(wctx);
  free(wreq);
  free(wct);
  free(wfresh);
  free(id);
  free(ru);
  iya_wsfed_login_request_free(req);
  iya_wsfed_party_free(party);
  free(json);
}

static void TestForceAuthnAndProtocolParams(void) {
  char *json = cfg_json(NULL, 1, "\"requestTokenType\":false");
  iya_wsfed_party *party = must_party(json);
  const char *keys[] = {"login_hint"};
  const char *values[] = {"alice"};
  iya_wsfed_login_opts opts;
  memset(&opts, 0, sizeof opts);
  opts.force_authn = 1;
  opts.authentication_method = "http://schemas.microsoft.com/claims/multipleauthn";
  opts.home_realm = "urn:partner";
  opts.param_keys = keys;
  opts.param_values = values;
  opts.param_count = 1;
  iya_wsfed_login_request *req = must_login(party, &opts);
  const char *url = iya_wsfed_login_request_url(req);
  char *wfresh = query_get(url, "wfresh");
  char *wauth = query_get(url, "wauth");
  char *whr = query_get(url, "whr");
  char *hint = query_get(url, "login_hint");
  char *wreq = query_get(url, "wreq");
  if (!wfresh || strcmp(wfresh, "0") != 0 || !wauth || strcmp(wauth, opts.authentication_method) != 0 || !whr ||
      strcmp(whr, "urn:partner") != 0 || !hint || strcmp(hint, "alice") != 0)
    die("params");
  if (wreq) die("wreq");
  free(wfresh);
  free(wauth);
  free(whr);
  free(hint);
  free(wreq);
  iya_wsfed_login_request_free(req);
  const char *bad_keys[] = {"wtrealm"};
  const char *bad_values[] = {"urn:evil"};
  memset(&opts, 0, sizeof opts);
  opts.param_keys = bad_keys;
  opts.param_values = bad_values;
  opts.param_count = 1;
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  req = iya_wsfed_begin_login(party, &opts, &err);
  if (req) die("accepted wtrealm");
  expect_err(1, &err, "config", "protocol's own");
  char relay[1026];
  memset(relay, 'x', 1025);
  relay[1025] = 0;
  memset(&opts, 0, sizeof opts);
  opts.has_relay = 1;
  opts.relay = relay;
  memset(&err, 0, sizeof err);
  req = iya_wsfed_begin_login(party, &opts, &err);
  if (req) die("accepted relay");
  expect_err(1, &err, "config", "1024 bytes");
  iya_wsfed_party_free(party);
  free(json);
}

static void TestSignoutRequest(void) {
  char *json = cfg_json(NULL, 1, NULL);
  iya_wsfed_party *party = must_party(json);
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  char *url = iya_wsfed_logout(party, "https://rp.test/", &err);
  if (!url) die(err.message);
  char *wa = query_get(url, "wa");
  char *realm = query_get(url, "wtrealm");
  char *reply = query_get(url, "wreply");
  if (!wa || strcmp(wa, "wsignout1.0") != 0 || !realm || strcmp(realm, REALM) != 0 || !reply ||
      strcmp(reply, "https://rp.test/") != 0)
    die(url);
  free(wa);
  free(realm);
  free(reply);
  iya_wsfed_string_free(url);
  iya_wsfed_party_free(party);
  free(json);
}

static void TestSignedAssertionInA2005Response(void) {
  char *json = cfg_json(NULL, 1, NULL);
  iya_wsfed_party *party = must_party(json);
  iya_wsfed_login_opts opts;
  memset(&opts, 0, sizeof opts);
  opts.has_relay = 1;
  opts.relay = "/home";
  iya_wsfed_login_request *req = must_login(party, &opts);
  char *result = wresult_xml(NULL, NULL, NULL, NULL, 0, 0);
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  const char *ids[] = {iya_wsfed_login_request_id(req)};
  iya_wsfed_login *who = submit(party, result, iya_wsfed_login_request_wctx(req), ids, 1, &err);
  if (!who) die(err.message);
  if (strcmp(iya_wsfed_login_name_id(who), "alice-1234") != 0) die("name");
  if (!iya_wsfed_login_has_format(who) ||
      strcmp(iya_wsfed_login_format(who), "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent") != 0)
    die("format");
  if (!iya_wsfed_login_has_session(who) || strcmp(iya_wsfed_login_session(who), "_session1") != 0) die("session");
  if (!iya_wsfed_login_has_relay(who) || strcmp(iya_wsfed_login_relay(who), "/home") != 0) die("relay");
  if (!iya_wsfed_login_has_request(who) || strcmp(iya_wsfed_login_request_id_of(who), iya_wsfed_login_request_id(req)) != 0)
    die("request");
  if (strcmp(iya_wsfed_login_trust(who), "2005/02") != 0 || iya_wsfed_login_encrypted(who)) die("trust");
  const char *role = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";
  if (iya_wsfed_login_attr_count(who, role) != 2 || strcmp(iya_wsfed_login_attr_at(who, role, 0), "staff") != 0 ||
      strcmp(iya_wsfed_login_attr_at(who, role, 1), "admins") != 0)
    die("roles");
  const char *mail = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";
  if (strcmp(iya_wsfed_login_friendly(who, mail), "mail") != 0) die("friendly");
  if (!iya_wsfed_login_has_class(who) ||
      strcmp(iya_wsfed_login_class(who), "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport") != 0)
    die("class");
  iya_wsfed_login_free(who);
  iya_wsfed_login_request_free(req);
  free(result);
  iya_wsfed_party_free(party);
  free(json);
}

static void TestTrust13AndARawFormBody(void) {
  char *json = cfg_json(NULL, 1, NULL);
  iya_wsfed_party *party = must_party(json);
  char *result = wresult_xml(NULL, "1.3", NULL, NULL, 0, 0);
  iya_wsfed_login *who = post_id(party, result, "_r");
  if (strcmp(iya_wsfed_login_trust(who), "1.3") != 0) die(iya_wsfed_login_trust(who));
  iya_wsfed_login_free(who);
  free(result);
  char *signed_xml = signed_assertion(NULL, NULL, 0);
  result = wresult_xml(signed_xml, NULL, NULL, NULL, 0, 0);
  free(signed_xml);
  const char *ids[] = {"_x", "_s"};
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  who = submit(party, result, "id=_s", ids, 2, &err);
  if (!who) die(err.message);
  if (strcmp(iya_wsfed_login_name_id(who), "alice-1234") != 0) die(iya_wsfed_login_name_id(who));
  iya_wsfed_login_free(who);
  free(result);
  iya_wsfed_party_free(party);
  free(json);
}

static void TestRecipientOptionalAndChecked(void) {
  char *json = cfg_json(NULL, 1, NULL);
  iya_wsfed_party *party = must_party(json);
  AssertionOpt opt;
  memset(&opt, 0, sizeof opt);
  opt.recipient_set = 1;
  opt.recipient = "";
  char *token = signed_assertion(&opt, NULL, 0);
  char *result = wresult_xml(token, NULL, NULL, NULL, 0, 0);
  free(token);
  iya_wsfed_login *who = post_id(party, result, "_r");
  if (strcmp(iya_wsfed_login_name_id(who), "alice-1234") != 0) die("name");
  iya_wsfed_login_free(who);
  free(result);
  memset(&opt, 0, sizeof opt);
  opt.recipient_set = 1;
  opt.recipient = "https://other.test/wsfed";
  token = signed_assertion(&opt, NULL, 0);
  result = wresult_xml(token, NULL, NULL, NULL, 0, 0);
  free(token);
  expect_submit(party, result, "id=_r", ids_r, 1, "validation", "Recipient");
  free(result);
  iya_wsfed_party_free(party);
  free(json);
}

static void TestBareBearerConfirmation(void) {
  char *json = cfg_json(NULL, 1, NULL);
  iya_wsfed_party *party = must_party(json);
  AssertionOpt opt;
  memset(&opt, 0, sizeof opt);
  opt.bare = 1;
  char *token = signed_assertion(&opt, NULL, 0);
  char *result = wresult_xml(token, NULL, NULL, NULL, 0, 0);
  free(token);
  iya_wsfed_login *who = post_id(party, result, "_r");
  if (strcmp(iya_wsfed_login_name_id(who), "alice-1234") != 0) die("name");
  if (iya_wsfed_login_not_on_or_after_ms(who) <= wall_ms()) die("expiry");
  iya_wsfed_login_free(who);
  free(result);
  memset(&opt, 0, sizeof opt);
  opt.bare = 1;
  opt.not_on_set = 1;
  opt.not_on_ms = -120000;
  token = signed_assertion(&opt, NULL, 0);
  result = wresult_xml(token, NULL, NULL, NULL, 0, 0);
  free(token);
  expect_submit(party, result, "id=_r", ids_r, 1, "validation", "expired");
  free(result);
  memset(&opt, 0, sizeof opt);
  opt.bare = 1;
  opt.no_conditions_expiry = 1;
  token = signed_assertion(&opt, NULL, 0);
  result = wresult_xml(token, NULL, NULL, NULL, 0, 0);
  free(token);
  expect_submit(party, result, "id=_r", ids_r, 1, "validation", "nothing|no Conditions NotOnOrAfter");
  free(result);
  iya_wsfed_party_free(party);
  free(json);
}

static void TestUnsignedAssertionIsRefused(void) {
  char *json = cfg_json(NULL, 1, NULL);
  iya_wsfed_party *party = must_party(json);
  char id[128];
  char *token = assertion_xml(NULL, id, sizeof id);
  char *result = wresult_xml(token, NULL, NULL, NULL, 0, 0);
  free(token);
  expect_submit(party, result, "id=_r", ids_r, 1, "validation", "not signed");
  free(result);
  iya_wsfed_party_free(party);
  free(json);
}

static void TestAlteredOrWrongKeyIsRefused(void) {
  char *json = cfg_json(NULL, 1, NULL);
  iya_wsfed_party *party = must_party(json);
  char *signed_xml = signed_assertion(NULL, NULL, 0);
  char *altered = replace_first(signed_xml, "alice-1234", "mallory");
  char *result = wresult_xml(altered, NULL, NULL, NULL, 0, 0);
  expect_submit(party, result, "id=_r", ids_r, 1, "signature", NULL);
  free(result);
  free(altered);
  free(signed_xml);
  char id[128];
  char *plain = assertion_xml(NULL, id, sizeof id);
  char *wrong = sign_xml(plain, id, rp_key_pem(), rp_cert_pem());
  free(plain);
  result = wresult_xml(wrong, NULL, NULL, NULL, 0, 0);
  free(wrong);
  expect_submit(party, result, "id=_r", ids_r, 1, "signature", "does not verify");
  free(result);
  iya_wsfed_party_free(party);
  free(json);
}

static void TestSignatureWrapping(void) {
  char *json = cfg_json(NULL, 1, NULL);
  iya_wsfed_party *party = must_party(json);
  char signed_id[128];
  char *signed_xml = signed_assertion(NULL, signed_id, sizeof signed_id);
  AssertionOpt opt;
  memset(&opt, 0, sizeof opt);
  opt.name_id = "mallory";
  char forged_id[128];
  char *forged = assertion_xml(&opt, forged_id, sizeof forged_id);
  char *both = malloc(strlen(forged) + strlen(signed_xml) + 1);
  sprintf(both, "%s%s", forged, signed_xml);
  char *result = wresult_xml(both, NULL, NULL, NULL, 0, 0);
  expect_submit(party, result, "id=_r", ids_r, 1, "message", "exactly one");
  free(result);
  free(both);
  char *hidden = replace_id(forged, signed_id);
  char *close = strstr(hidden, "</saml:Assertion>");
  if (!close) die("close");
  char *advice = malloc(strlen(hidden) + strlen(signed_xml) + 64);
  size_t head = (size_t)(close - hidden);
  memcpy(advice, hidden, head);
  sprintf(advice + head, "<saml:Advice>%s</saml:Advice></saml:Assertion>", signed_xml);
  result = wresult_xml(advice, NULL, NULL, NULL, 0, 0);
  expect_submit(party, result, "id=_r", ids_r, 1, "signature", "two elements");
  free(result);
  free(advice);
  free(hidden);
  char *decoy = wresult_xml(signed_xml, NULL, NULL, NULL, 0, 0);
  char marked[256];
  snprintf(marked, sizeof marked,
           "<t:Lifetime xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" "
           "wsu:Id=\"%s\">",
           signed_id);
  char *moved_life = replace_first(decoy, "<t:Lifetime>", marked);
  expect_submit(party, moved_life, "id=_r", ids_r, 1, "signature", "two elements");
  free(moved_life);
  free(decoy);
  const char *sig_at = strstr(signed_xml, "<ds:Signature");
  const char *sig_end = sig_at ? strstr(sig_at, "</ds:Signature>") : NULL;
  if (!sig_end) die("signature");
  sig_end += strlen("</ds:Signature>");
  char *sig = strndup(sig_at, (size_t)(sig_end - sig_at));
  char *issuer_end = strstr(forged, "</saml:Issuer>");
  if (!issuer_end) die("issuer");
  issuer_end += strlen("</saml:Issuer>");
  char *moved = malloc(strlen(forged) + strlen(sig) + 1);
  size_t h = (size_t)(issuer_end - forged);
  memcpy(moved, forged, h);
  memcpy(moved + h, sig, strlen(sig));
  strcpy(moved + h + strlen(sig), issuer_end);
  result = wresult_xml(moved, NULL, NULL, NULL, 0, 0);
  expect_submit(party, result, "id=_r", ids_r, 1, "signature", "refers to");
  free(result);
  free(moved);
  free(sig);
  free(forged);
  free(signed_xml);
  iya_wsfed_party_free(party);
  free(json);
}

static void TestWrongRealmIssuerOrExpiry(void) {
  char *json = cfg_json(NULL, 1, NULL);
  iya_wsfed_party *party = must_party(json);
  AssertionOpt opt;
  memset(&opt, 0, sizeof opt);
  opt.audience = "https://other.test/";
  char *token = signed_assertion(&opt, NULL, 0);
  char *result = wresult_xml(token, NULL, NULL, NULL, 0, 0);
  free(token);
  expect_submit(party, result, "id=_r", ids_r, 1, "validation", "not for");
  free(result);
  memset(&opt, 0, sizeof opt);
  opt.issuer = "https://evil.test";
  token = signed_assertion(&opt, NULL, 0);
  result = wresult_xml(token, NULL, NULL, NULL, 0, 0);
  free(token);
  expect_submit(party, result, "id=_r", ids_r, 1, "validation", "issued by");
  free(result);
  memset(&opt, 0, sizeof opt);
  opt.not_on_set = 1;
  opt.not_on_ms = -120000;
  token = signed_assertion(&opt, NULL, 0);
  result = wresult_xml(token, NULL, NULL, NULL, 0, 0);
  free(token);
  expect_submit(party, result, "id=_r", ids_r, 1, "validation", "expired");
  free(result);
  result = wresult_xml(NULL, NULL, "https://other.test/", NULL, 0, 0);
  expect_submit(party, result, "id=_r", ids_r, 1, "validation", "applies to");
  free(result);
  result = wresult_xml(NULL, NULL, NULL, NULL, -120000, 1);
  expect_submit(party, result, "id=_r", ids_r, 1, "validation", "response expired");
  free(result);
  iya_wsfed_party_free(party);
  free(json);
}

static void TestInResponseToIsRefused(void) {
  char *json = cfg_json(NULL, 1, NULL);
  iya_wsfed_party *party = must_party(json);
  AssertionOpt opt;
  memset(&opt, 0, sizeof opt);
  opt.in_response_to = "_samlreq";
  char *token = signed_assertion(&opt, NULL, 0);
  char *result = wresult_xml(token, NULL, NULL, NULL, 0, 0);
  free(token);
  expect_submit(party, result, "id=_r", ids_r, 1, "validation", "InResponseTo");
  free(result);
  iya_wsfed_party_free(party);
  free(json);
}

static void TestSaml11AndNonTrustAreRefused(void) {
  char *json = cfg_json(NULL, 1, NULL);
  iya_wsfed_party *party = must_party(json);
  char instant[40];
  time_t now = time(NULL);
  struct tm tm;
  gmtime_r(&now, &tm);
  snprintf(instant, sizeof instant, "%04d-%02d-%02dT%02d:%02d:%02d.000Z", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
           tm.tm_hour, tm.tm_min, tm.tm_sec);
  char saml11[1024];
  snprintf(saml11, sizeof saml11,
           "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\" MajorVersion=\"1\" MinorVersion=\"1\" "
           "AssertionID=\"_s11\" Issuer=\"%s\" IssueInstant=\"%s\"><saml:AttributeStatement><saml:Subject><saml:"
           "NameIdentifier>alice</saml:NameIdentifier></saml:Subject></saml:AttributeStatement></saml:Assertion>",
           IDP_ENTITY, instant);
  char *result = wresult_xml(saml11, NULL, NULL, SAML2, 0, 0);
  expect_submit(party, result, "id=_r", ids_r, 1, "message", "SAML 1.1");
  free(result);
  result = wresult_xml(NULL, NULL, NULL, "urn:oasis:names:tc:SAML:1.0:assertion", 0, 0);
  expect_submit(party, result, "id=_r", ids_r, 1, "message", "SAML 2.0 assertions only");
  free(result);
  char *signed_xml = signed_assertion(NULL, NULL, 0);
  expect_submit(party, signed_xml, "id=_r", ids_r, 1, "message", "not a WS-Trust");
  free(signed_xml);
  result = wresult_xml(NULL, NULL, NULL, NULL, 0, 0);
  char *doctype = malloc(strlen(result) + 64);
  sprintf(doctype, "<!DOCTYPE x [<!ENTITY e \"x\">]>%s", result);
  expect_submit(party, doctype, "id=_r", ids_r, 1, "xml", "DOCTYPE");
  free(doctype);
  free(result);
  iya_wsfed_party_free(party);
  free(json);
}

static void TestUnsolicitedAndUnknownRequests(void) {
  char *json = cfg_json(NULL, 1, NULL);
  iya_wsfed_party *party = must_party(json);
  char *result = wresult_xml(NULL, NULL, NULL, NULL, 0, 0);
  const char *other[] = {"_other"};
  expect_submit(party, result, "id=_r", other, 1, "validation", "not a sign-in this browser");
  expect_submit(party, result, "id=_r", NULL, 0, "validation", "not a sign-in this browser");
  expect_submit(party, result, NULL, NULL, 0, "validation", "unsolicited");
  iya_wsfed_party_free(party);
  free(json);
  json = cfg_json(NULL, 1, "\"allowUnsolicited\":true");
  party = must_party(json);
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  iya_wsfed_login *who = submit(party, result, "ru=%2Fthere", NULL, 0, &err);
  if (!who) die(err.message);
  if (iya_wsfed_login_has_request(who) || !iya_wsfed_login_has_relay(who) || strcmp(iya_wsfed_login_relay(who), "/there") != 0)
    die("unsolicited relay");
  iya_wsfed_login_free(who);
  free(result);
  iya_wsfed_party_free(party);
  free(json);
}

static void TestReplay(void) {
  char *json = cfg_json(NULL, 1, NULL);
  iya_wsfed_party *party = must_party(json);
  char *result = wresult_xml(NULL, NULL, NULL, NULL, 0, 0);
  iya_wsfed_login *who = post_id(party, result, "_r");
  iya_wsfed_login_free(who);
  expect_submit(party, result, "id=_r", ids_r, 1, "replay", NULL);
  free(result);
  iya_wsfed_party_free(party);
  free(json);
}

static void TestDecryptsEncryptedAssertions(void) {
  char *json = cfg_json(NULL, 1, NULL);
  iya_wsfed_party *party = must_party(json);
  const char *ciphers[] = {"aes-256-gcm", "aes-128-cbc"};
  for (int i = 0; i < 2; i++) {
    char *signed_xml = signed_assertion(NULL, NULL, 0);
    char *enc = encrypt_xml(signed_xml, ciphers[i], "", "");
    free(signed_xml);
    char *result = wresult_xml(enc, NULL, NULL, NULL, 0, 0);
    free(enc);
    iya_wsfed_login *who = post_id(party, result, "_r");
    if (strcmp(iya_wsfed_login_name_id(who), "alice-1234") != 0 || !iya_wsfed_login_encrypted(who)) die(ciphers[i]);
    iya_wsfed_login_free(who);
    free(result);
  }
  char *signed_xml = signed_assertion(NULL, NULL, 0);
  char *enc = encrypt_xml(signed_xml, "aes-256-gcm", "oaep256", "none");
  free(signed_xml);
  char *result = wresult_xml(enc, NULL, NULL, NULL, 0, 0);
  free(enc);
  iya_wsfed_login *who = post_id(party, result, "_r");
  if (!iya_wsfed_login_encrypted(who)) die("expected encrypted");
  iya_wsfed_login_free(who);
  free(result);
  iya_wsfed_party_free(party);
  free(json);
}

static char *tamper_last_cipher(const char *xml) {
  const char *open = NULL;
  const char *cursor = xml;
  while ((cursor = strstr(cursor, "<xenc:CipherValue>"))) {
    open = cursor;
    cursor += 18;
  }
  if (!open) die("cipher");
  open += strlen("<xenc:CipherValue>");
  const char *end = strstr(open, "</xenc:CipherValue>");
  if (!end) die("cipher end");
  char *b64 = strndup(open, (size_t)(end - open));
  BIO *b64f = BIO_new(BIO_f_base64());
  BIO *mem = BIO_new_mem_buf(b64, (int)strlen(b64));
  BIO_set_flags(b64f, BIO_FLAGS_BASE64_NO_NL);
  mem = BIO_push(b64f, mem);
  unsigned char raw[65536];
  int n = BIO_read(mem, raw, sizeof raw);
  BIO_free_all(mem);
  if (n < 21) die("short cipher");
  raw[20] ^= 1;
  char *again = malloc((size_t)n * 2 + 8);
  int out = EVP_EncodeBlock((unsigned char *)again, raw, n);
  again[out] = 0;
  char *replaced = malloc(strlen(xml) + strlen(again) + 8);
  size_t head = (size_t)(open - xml);
  memcpy(replaced, xml, head);
  memcpy(replaced + head, again, (size_t)out);
  strcpy(replaced + head + out, end);
  free(again);
  free(b64);
  return replaced;
}

static void TestWantAssertionsEncryptedAndTamperedCiphertext(void) {
  char *json = cfg_json(NULL, 1, "\"wantAssertionsEncrypted\":true");
  iya_wsfed_party *party = must_party(json);
  char *result = wresult_xml(NULL, NULL, NULL, NULL, 0, 0);
  expect_submit(party, result, "id=_r", ids_r, 1, "validation", "not encrypted");
  free(result);
  char id[128];
  char *plain = assertion_xml(NULL, id, sizeof id);
  char *enc = encrypt_xml(plain, "", "", "");
  free(plain);
  result = wresult_xml(enc, NULL, NULL, NULL, 0, 0);
  free(enc);
  expect_submit(party, result, "id=_r", ids_r, 1, "validation", "not signed");
  free(result);
  char *signed_xml = signed_assertion(NULL, NULL, 0);
  enc = encrypt_xml(signed_xml, "", "", "");
  free(signed_xml);
  char *tampered = tamper_last_cipher(enc);
  free(enc);
  result = wresult_xml(tampered, NULL, NULL, NULL, 0, 0);
  free(tampered);
  expect_submit(party, result, "id=_r", ids_r, 1, "decryption", NULL);
  free(result);
  iya_wsfed_party_free(party);
  free(json);
}

static void TestEncryptedAttributeAndMissingKey(void) {
  char *json = cfg_json(NULL, 0, NULL);
  iya_wsfed_party *keyless = must_party(json);
  char *signed_xml = signed_assertion(NULL, NULL, 0);
  char *enc = encrypt_xml(signed_xml, "", "", "");
  free(signed_xml);
  char *result = wresult_xml(enc, NULL, NULL, NULL, 0, 0);
  free(enc);
  expect_submit(keyless, result, "id=_r", ids_r, 1, "decryption", "no privateKey");
  free(result);
  iya_wsfed_party_free(keyless);
  free(json);
  json = cfg_json(NULL, 1, NULL);
  iya_wsfed_party *party = must_party(json);
  const char *attr =
      "<saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"employeeNumber\"><saml:AttributeValue>E-42</saml:AttributeValue></saml:Attribute>";
  char *secret = encrypt_xml(attr, "aes-256-gcm", "oaep256", "EncryptedAttribute");
  AssertionOpt opt;
  memset(&opt, 0, sizeof opt);
  opt.extra = secret;
  char id[128];
  char *plain = assertion_xml(&opt, id, sizeof id);
  char *signed_attr = sign_xml(plain, id, NULL, NULL);
  free(plain);
  free(secret);
  result = wresult_xml(signed_attr, NULL, NULL, NULL, 0, 0);
  free(signed_attr);
  iya_wsfed_login *who = post_id(party, result, "_r");
  if (iya_wsfed_login_attr_count(who, "employeeNumber") != 1 ||
      strcmp(iya_wsfed_login_attr_at(who, "employeeNumber", 0), "E-42") != 0)
    die("attribute");
  iya_wsfed_login_free(who);
  free(result);
  iya_wsfed_party_free(party);
  free(json);
}

static void TestReplyURLRefusesGetWrongWaAndWresultptr(void) {
  char *json = cfg_json(NULL, 1, NULL);
  iya_wsfed_party *party = must_party(json);
  char *result = wresult_xml(NULL, NULL, NULL, NULL, 0, 0);
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  char *escaped = form_body(result, NULL);
  char url[65536];
  snprintf(url, sizeof url, "/wsfed?%s", escaped);
  iya_wsfed_login *who = iya_wsfed_handle_reply(party, "GET", url, "", NULL, 0, &err);
  if (who) die("get accepted");
  expect_err(1, &err, "message", "POSTed");
  free(escaped);
  char *body = malloc(strlen(result) * 3 + 64);
  char *er = NULL;
  {
    /* form with a different wa */
  }
  size_t cap = strlen(result) * 3 + 128;
  body = realloc(body, cap);
  char *enc = NULL;
  {
    extern char *query_unescape_dup(const char *);
    (void)query_unescape_dup;
  }
  /* encode with the same rules as form_body by rebuilding */
  free(body);
  {
    char *encoded = form_body(result, NULL);
    char *wa = strstr(encoded, "wa=wsignin1.0");
    memcpy(wa, "wa=wattr1.0&", 12);
    /* "wa=wsignin1.0" is 14 chars; replacing with shorter text shifts. Rebuild. */
    free(encoded);
  }
  {
    size_t n = strlen(result) * 3 + 64;
    char *raw = malloc(n);
    char *value = form_body(result, NULL);
    /* value starts with wa=wsignin1.0&wresult= */
    const char *rest = strstr(value, "&wresult=");
    snprintf(raw, n, "wa=wattr1.0%s", rest);
    memset(&err, 0, sizeof err);
    who = iya_wsfed_handle_reply(party, "POST", "/wsfed", raw, NULL, 0, &err);
    if (who) die("wrong wa");
    expect_err(1, &err, "message", "not wsignin1.0");
    free(raw);
    free(value);
  }
  memset(&err, 0, sizeof err);
  who = iya_wsfed_handle_reply(party, "POST", "/wsfed", "wa=wsignin1.0&wresultptr=https%3A%2F%2Fevil.test%2F", NULL, 0, &err);
  if (who) die("ptr");
  expect_err(1, &err, "message", "wresultptr");
  memset(&err, 0, sizeof err);
  who = iya_wsfed_handle_reply(party, "POST", "/wsfed", "wa=wsignin1.0", NULL, 0, &err);
  if (who) die("missing");
  expect_err(1, &err, "message", "no wresult");
  free(result);
  iya_wsfed_party_free(party);
  free(json);
  (void)enc;
  (void)one;
}

static void TestSignOutCleanup(void) {
  char *json = cfg_json(NULL, 1, NULL);
  iya_wsfed_party *party = must_party(json);
  if (!iya_wsfed_is_signout(party, "GET", "/wsfed?wa=wsignoutcleanup1.0", "")) die("cleanup");
  if (!iya_wsfed_is_signout(party, "POST", "/wsfed", "wa=wsignout1.0")) die("signout");
  if (iya_wsfed_is_signout(party, "POST", "/wsfed", "wa=wsignin1.0")) die("signin");
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  iya_wsfed_login *who = iya_wsfed_handle_reply(party, "GET", "/wsfed?wa=wsignoutcleanup1.0", "", NULL, 0, &err);
  if (who) die("accepted sign-out");
  expect_err(1, &err, "message", "sign-out");
  iya_wsfed_party_free(party);
  free(json);
}

static void TestStatusSuccessConstant(void) {
  if (strcmp(iya_wsfed_status_success(), "urn:oasis:names:tc:SAML:2.0:status:Success") != 0) die("status");
  if (strcmp(iya_wsfed_rsa_sha256(), "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256") != 0) die("rsa");
  if (strcmp(iya_wsfed_default_subject(), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier") != 0)
    die("subject");
}

void TestVerifiesASetAndRefusesTheWrongKey(void);
void TestSubjects(void);
void TestPollStreamEndsTheNamedSessions(void);
void TestForgedSetsAreReported(void);
void TestEventCatalog(void);
void TestHandlerAndOnEndErrorsAreStillAcknowledged(void);
void TestOverlappingPollsHandleASetOnce(void);
void TestRefusesATransmitterWithoutPollDelivery(void);
void TestConfigureSignalsBehavior(void);
void TestSignsItselfAndNamesItsKey(void);
void TestTwoCertificatesOfOneNameHaveDifferentKeyIdentifiers(void);
void TestGenerateKeysNamesTheCertificateAfterTheRealm(void);
void TestSignInCleanupAndLogout(void);
void TestLiveStatusReportsTheSignInWithoutTokens(void);
void TestIdpCaChainIsTheTrustStore(void);
void TestHostNameIsChecked(void);
void TestConfigureWritesTheWholeChain(void);

int main(int argc, char **argv) {
  if (argc < 2) return 2;
  harness_begin(argv[1]);
  const char *name = argv[1];
#define RUN(fn) \
  if (strcmp(name, #fn) == 0) { \
    fn(); \
    return 0; \
  }
  RUN(TestConfigurationRequiresRealmReplyAndAMatchingKey)
  RUN(TestSignalsOmittedOrTrueIsLeftOff)
  RUN(TestSignalsFalseIsRecorded)
  RUN(TestSignalsMustBeTrueOrFalse)
  RUN(TestReadsTheSecurityTokenServiceRole)
  RUN(TestXsiTypeAndIdpRoleFallback)
  RUN(TestRefusesMetadataWithoutAnSTSOrSAML2)
  RUN(TestWritesApplicationServiceMetadata)
  RUN(TestSigninNamesRealmReplyWctxAndSAML2)
  RUN(TestForceAuthnAndProtocolParams)
  RUN(TestSignoutRequest)
  RUN(TestSignedAssertionInA2005Response)
  RUN(TestTrust13AndARawFormBody)
  RUN(TestRecipientOptionalAndChecked)
  RUN(TestBareBearerConfirmation)
  RUN(TestUnsignedAssertionIsRefused)
  RUN(TestAlteredOrWrongKeyIsRefused)
  RUN(TestSignatureWrapping)
  RUN(TestWrongRealmIssuerOrExpiry)
  RUN(TestInResponseToIsRefused)
  RUN(TestSaml11AndNonTrustAreRefused)
  RUN(TestUnsolicitedAndUnknownRequests)
  RUN(TestReplay)
  RUN(TestDecryptsEncryptedAssertions)
  RUN(TestWantAssertionsEncryptedAndTamperedCiphertext)
  RUN(TestEncryptedAttributeAndMissingKey)
  RUN(TestReplyURLRefusesGetWrongWaAndWresultptr)
  RUN(TestSignOutCleanup)
  RUN(TestStatusSuccessConstant)
  RUN(TestVerifiesASetAndRefusesTheWrongKey)
  RUN(TestSubjects)
  RUN(TestPollStreamEndsTheNamedSessions)
  RUN(TestForgedSetsAreReported)
  RUN(TestEventCatalog)
  RUN(TestHandlerAndOnEndErrorsAreStillAcknowledged)
  RUN(TestOverlappingPollsHandleASetOnce)
  RUN(TestRefusesATransmitterWithoutPollDelivery)
  RUN(TestConfigureSignalsBehavior)
  RUN(TestSignsItselfAndNamesItsKey)
  RUN(TestTwoCertificatesOfOneNameHaveDifferentKeyIdentifiers)
  RUN(TestGenerateKeysNamesTheCertificateAfterTheRealm)
  RUN(TestSignInCleanupAndLogout)
  RUN(TestLiveStatusReportsTheSignInWithoutTokens)
  RUN(TestIdpCaChainIsTheTrustStore)
  RUN(TestHostNameIsChecked)
  RUN(TestConfigureWritesTheWholeChain)
#undef RUN
  fprintf(stderr, "unknown test %s\n", name);
  return 2;
}
