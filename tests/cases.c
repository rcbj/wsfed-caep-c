// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#define _GNU_SOURCE

#include "harness.h"
#include "iya_wsfed_demo.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char *aprintf(const char *fmt, ...) {
  va_list ap, copy;
  va_start(ap, fmt);
  va_copy(copy, ap);
  int n = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);
  if (n < 0) die("format");
  char *out = malloc((size_t)n + 1);
  if (!out) die("oom");
  vsnprintf(out, (size_t)n + 1, fmt, copy);
  va_end(copy);
  return out;
}

static char *b64url_dup(const unsigned char *data, size_t n) {
  int enc = 4 * ((int)n + 2) / 3;
  unsigned char *tmp = malloc((size_t)enc + 4);
  int out = EVP_EncodeBlock(tmp, data, (int)n);
  char *s = malloc((size_t)out + 1);
  size_t j = 0;
  for (int i = 0; i < out; i++) {
    if (tmp[i] == '+') s[j++] = '-';
    else if (tmp[i] == '/') s[j++] = '_';
    else if (tmp[i] == '=') continue;
    else s[j++] = (char)tmp[i];
  }
  s[j] = 0;
  free(tmp);
  return s;
}

static EVP_PKEY *gen_rsa(void) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  EVP_PKEY *key = NULL;
  if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
      EVP_PKEY_keygen(ctx, &key) <= 0) {
    if (ctx) EVP_PKEY_CTX_free(ctx);
    die("rsa");
  }
  EVP_PKEY_CTX_free(ctx);
  return key;
}

static char *jwk_of(EVP_PKEY *key) {
  BIGNUM *n = NULL;
  BIGNUM *e = NULL;
  if (EVP_PKEY_get_bn_param(key, "n", &n) != 1 || EVP_PKEY_get_bn_param(key, "e", &e) != 1) die("jwk");
  int nl = BN_num_bytes(n);
  int el = BN_num_bytes(e);
  unsigned char *nb = malloc((size_t)nl);
  unsigned char *eb = malloc((size_t)el);
  BN_bn2bin(n, nb);
  BN_bn2bin(e, eb);
  char *ns = b64url_dup(nb, (size_t)nl);
  char *es = b64url_dup(eb, (size_t)el);
  char *jwk = aprintf("{\"kty\":\"RSA\",\"kid\":\"k1\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\"%s\",\"e\":\"%s\"}", ns, es);
  free(ns);
  free(es);
  free(nb);
  free(eb);
  BN_free(n);
  BN_free(e);
  return jwk;
}

static char *sign_jws(const char *payload, EVP_PKEY *key, const char *header) {
  if (!header) header = "{\"alg\":\"RS256\",\"kid\":\"k1\",\"typ\":\"secevent+jwt\"}";
  char *hb = b64url_dup((const unsigned char *)header, strlen(header));
  char *pb = b64url_dup((const unsigned char *)payload, strlen(payload));
  char *input = aprintf("%s.%s", hb, pb);
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  size_t siglen = 0;
  if (!ctx || EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key) != 1 ||
      EVP_DigestSignUpdate(ctx, input, strlen(input)) != 1 || EVP_DigestSignFinal(ctx, NULL, &siglen) != 1) {
    die("sign");
  }
  unsigned char *sig = malloc(siglen);
  if (EVP_DigestSignFinal(ctx, sig, &siglen) != 1) die("sign final");
  EVP_MD_CTX_free(ctx);
  char *sb = b64url_dup(sig, siglen);
  char *token = aprintf("%s.%s", input, sb);
  free(hb);
  free(pb);
  free(input);
  free(sig);
  free(sb);
  return token;
}

static void expect_verify_fail(const char *token, const char *keys, const char *pat) {
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  char *payload = iya_wsfed_jws_verify(token, keys, &err);
  if (payload) die("accepted");
  expect_err(1, &err, "signature", pat);
  free(payload);
}

void TestVerifiesASetAndRefusesTheWrongKey(void) {
  EVP_PKEY *key = gen_rsa();
  EVP_PKEY *other = gen_rsa();
  char *jwk = jwk_of(key);
  char *keys = aprintf("{\"keys\":[%s]}", jwk);
  char *good = sign_jws("{\"a\":1}", key, NULL);
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  char *payload = iya_wsfed_jws_verify(good, keys, &err);
  if (!payload || !strstr(payload, "\"a\":1")) die(payload ? payload : err.message);
  free(payload);
  char *wrong = sign_jws("{\"a\":1}", other, NULL);
  expect_verify_fail(wrong, keys, "does not verify");
  char *nope = sign_jws("{\"a\":1}", key, "{\"alg\":\"RS256\",\"kid\":\"nope\"}");
  expect_verify_fail(nope, keys, "no RSA signing key with kid nope");
  char *none = sign_jws("{\"a\":1}", key, "{\"alg\":\"none\"}");
  expect_verify_fail(none, keys, "does not verify");
  char *hmac = sign_jws("{\"a\":1}", key, "{\"alg\":\"HS256\",\"kid\":\"k1\"}");
  expect_verify_fail(hmac, keys, "does not verify");
  free(good);
  free(wrong);
  free(nope);
  free(none);
  free(hmac);
  free(keys);
  free(jwk);
  EVP_PKEY_free(key);
  EVP_PKEY_free(other);
}

void TestSubjects(void) {
  iya_wsfed_subject got;
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  const char *complex =
      "{\"format\":\"complex\",\"user\":{\"format\":\"iss_sub\",\"iss\":\"https://i\",\"sub\":\"urn:uuid:a\"},"
      "\"session\":{\"format\":\"opaque\",\"id\":\"S1\"}}";
  if (iya_wsfed_subject_of(complex, "https://i", &got, &err) != 0) die(err.message);
  if (!got.has_person || strcmp(got.person, "urn:uuid:a") != 0 || !got.has_idp_session || strcmp(got.idp_session, "S1") != 0)
    die("complex");
  memset(&got, 0, sizeof got);
  if (iya_wsfed_subject_of("{\"format\":\"iss_sub\",\"iss\":\"https://other\",\"sub\":\"urn:uuid:a\"}", "https://i", &got, &err) != 0)
    die(err.message);
  if (got.has_person || got.has_email || got.has_idp_session) die("foreign iss");
  memset(&got, 0, sizeof got);
  if (iya_wsfed_subject_of("{\"format\":\"email\",\"email\":\"A@x.com\"}", "https://i", &got, &err) != 0) die(err.message);
  if (!got.has_email || strcmp(got.email, "A@x.com") != 0) die("email");
}

#define QMAX 16

typedef struct Stub {
  pthread_mutex_t mu;
  char base[160];
  int created;
  char jwk[4096];
  char jti[QMAX][160];
  char *token[QMAX];
  int nqueue;
  char acked[32][160];
  int nacked;
  char errs[32][160];
  int nerrs;
  EVP_PKEY *key;
  EVP_PKEY *other;
} Stub;

static int stub_has_locked(char list[][160], int n, const char *jti) {
  for (int i = 0; i < n; i++) {
    if (strcmp(list[i], jti) == 0) return 1;
  }
  return 0;
}

static int stub_has(Stub *stub, int errs, const char *jti) {
  pthread_mutex_lock(&stub->mu);
  int hit = errs ? stub_has_locked(stub->errs, stub->nerrs, jti) : stub_has_locked(stub->acked, stub->nacked, jti);
  pthread_mutex_unlock(&stub->mu);
  return hit;
}

static void drop_jti(Stub *stub, const char *jti, int as_err) {
  for (int i = 0; i < stub->nqueue; i++) {
    if (strcmp(stub->jti[i], jti) != 0) continue;
    free(stub->token[i]);
    for (int k = i; k + 1 < stub->nqueue; k++) {
      memcpy(stub->jti[k], stub->jti[k + 1], sizeof stub->jti[k]);
      stub->token[k] = stub->token[k + 1];
    }
    stub->nqueue--;
    i--;
  }
  if (as_err) {
    if (stub->nerrs < 32) snprintf(stub->errs[stub->nerrs++], 160, "%s", jti);
  } else if (stub->nacked < 32) {
    snprintf(stub->acked[stub->nacked++], 160, "%s", jti);
  }
}

static int collect_quoted(const char *start, const char *end, char out[][160], int max) {
  int n = 0;
  const char *p = start;
  while (p < end && n < max) {
    if (*p != '"') {
      p++;
      continue;
    }
    p++;
    size_t j = 0;
    while (p < end && *p && *p != '"') {
      if (*p == '\\' && p + 1 < end) p++;
      if (j + 1 < 160) out[n][j++] = *p;
      p++;
    }
    out[n][j] = 0;
    if (p < end && *p == '"') p++;
    n++;
  }
  return n;
}

static int collect_keys(const char *object, char out[][160], int max) {
  const char *p = strchr(object, '{');
  if (!p) return 0;
  int depth = 0;
  int n = 0;
  while (*p && n < max) {
    if (*p == '"') {
      p++;
      char buf[160];
      size_t j = 0;
      while (*p && *p != '"') {
        if (*p == '\\' && p[1]) p++;
        if (j + 1 < sizeof buf) buf[j++] = *p;
        p++;
      }
      if (*p == '"') p++;
      buf[j] = 0;
      const char *q = p;
      while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r') q++;
      if (depth == 1 && *q == ':') snprintf(out[n++], 160, "%s", buf);
      continue;
    }
    if (*p == '{') depth++;
    else if (*p == '}') {
      depth--;
      if (depth == 0) break;
    }
    p++;
  }
  return n;
}

static char *sets_json(Stub *stub) {
  size_t cap = 64;
  for (int i = 0; i < stub->nqueue; i++) cap += strlen(stub->token[i]) + strlen(stub->jti[i]) + 8;
  char *body = malloc(cap);
  strcpy(body, "{\"sets\":{");
  for (int i = 0; i < stub->nqueue; i++) {
    if (i) strcat(body, ",");
    strcat(body, "\"");
    strcat(body, stub->jti[i]);
    strcat(body, "\":\"");
    strcat(body, stub->token[i]);
    strcat(body, "\"");
  }
  strcat(body, "},\"moreAvailable\":false}");
  return body;
}

static char *stream_json(Stub *stub, const char *id) {
  return aprintf(
      "{\"stream_id\":\"%s\",\"iss\":\"%s\",\"aud\":\"my-app\",\"delivery\":{\"method\":\"urn:ietf:rfc:8936\","
      "\"endpoint_url\":\"%s/ssf/poll/%s\"},\"events_requested\":[],\"events_delivered\":[]}",
      id, stub->base, stub->base, id);
}

static void stub_handle(const char *method, const char *target, const char *body, void *user, int *status, char **response_body) {
  Stub *stub = user;
  const char *path = target ? target : "";
  const char *q = strchr(path, '?');
  char pathbuf[256];
  if (q) {
    size_t n = (size_t)(q - path);
    if (n >= sizeof pathbuf) n = sizeof pathbuf - 1;
    memcpy(pathbuf, path, n);
    pathbuf[n] = 0;
    path = pathbuf;
  }
  pthread_mutex_lock(&stub->mu);
  if (strcmp(path, "/.well-known/ssf-configuration") == 0) {
    *status = 200;
    *response_body = aprintf(
        "{\"issuer\":\"%s\",\"jwks_uri\":\"%s/jwks\",\"configuration_endpoint\":\"%s/ssf/stream\","
        "\"verification_endpoint\":\"%s/ssf/verify\",\"delivery_methods_supported\":[\"urn:ietf:rfc:8936\"]}",
        stub->base, stub->base, stub->base, stub->base);
  } else if (strcmp(path, "/jwks") == 0) {
    *status = 200;
    *response_body = aprintf("{\"keys\":[%s]}", stub->jwk);
  } else if (strcmp(path, "/ssf/stream") == 0 && method && strcmp(method, "GET") == 0) {
    *status = 200;
    if (stub->created == 0) *response_body = strdup("[]");
    else {
      char *one = stream_json(stub, "s1");
      *response_body = aprintf("[%s]", one);
      free(one);
    }
  } else if (strcmp(path, "/ssf/stream") == 0 && method && strcmp(method, "POST") == 0) {
    stub->created++;
    char id[16];
    snprintf(id, sizeof id, "s%d", stub->created);
    *status = 201;
    *response_body = stream_json(stub, id);
  } else if (strncmp(path, "/ssf/poll/", 10) == 0) {
    if (body && strstr(body, "\"ack\"")) {
      const char *lb = strchr(strstr(body, "\"ack\""), '[');
      const char *rb = lb ? strchr(lb, ']') : NULL;
      char names[32][160];
      int n = lb && rb ? collect_quoted(lb + 1, rb, names, 32) : 0;
      for (int i = 0; i < n; i++) drop_jti(stub, names[i], 0);
    }
    if (body && strstr(body, "\"setErrs\"")) {
      char names[32][160];
      int n = collect_keys(strstr(body, "\"setErrs\""), names, 32);
      for (int i = 0; i < n; i++) drop_jti(stub, names[i], 1);
    }
    *status = 200;
    *response_body = sets_json(stub);
  } else {
    *status = 404;
    *response_body = strdup("{\"err\":\"not found\"}");
  }
  pthread_mutex_unlock(&stub->mu);
}

static Stub *stub_open(iya_http_server **server) {
  Stub *stub = calloc(1, sizeof *stub);
  pthread_mutex_init(&stub->mu, NULL);
  stub->key = gen_rsa();
  stub->other = gen_rsa();
  char *jwk = jwk_of(stub->key);
  snprintf(stub->jwk, sizeof stub->jwk, "%s", jwk);
  free(jwk);
  int port = 0;
  *server = iya_http_serve(stub_handle, stub, &port);
  if (!*server || port <= 0) die("ssf stub");
  snprintf(stub->base, sizeof stub->base, "http://127.0.0.1:%d", port);
  return stub;
}

static void stub_close(Stub *stub, iya_http_server *server) {
  if (server) iya_http_server_close(server);
  if (!stub) return;
  for (int i = 0; i < stub->nqueue; i++) free(stub->token[i]);
  EVP_PKEY_free(stub->key);
  EVP_PKEY_free(stub->other);
  pthread_mutex_destroy(&stub->mu);
  free(stub);
}

static char *event_body(const char *fields) {
  if (!fields || !fields[0]) return strdup("{\"event_timestamp\":1}");
  return aprintf("{\"event_timestamp\":1,%s}", fields);
}

static char *stub_put(Stub *stub, const char *event_uri, const char *sub_json, const char *fields, EVP_PKEY *key,
                      const char *aud, const char *iss) {
  unsigned char rnd[16];
  if (RAND_bytes(rnd, sizeof rnd) != 1) die("rand");
  char *jti = b64url_dup(rnd, sizeof rnd);
  char *inner = event_body(fields);
  const char *use_aud = aud && aud[0] ? aud : "my-app";
  const char *use_iss = iss && iss[0] ? iss : stub->base;
  char *payload = aprintf("{\"iss\":\"%s\",\"aud\":\"%s\",\"jti\":\"%s\",\"iat\":1,\"sub_id\":%s,\"events\":{\"%s\":%s}}",
                          use_iss, use_aud, jti, sub_json, event_uri, inner);
  char *token = sign_jws(payload, key ? key : stub->key, NULL);
  pthread_mutex_lock(&stub->mu);
  if (stub->nqueue >= QMAX) die("queue");
  snprintf(stub->jti[stub->nqueue], 160, "%s", jti);
  stub->token[stub->nqueue] = token;
  stub->nqueue++;
  pthread_mutex_unlock(&stub->mu);
  free(inner);
  free(payload);
  return jti;
}

typedef struct EndState {
  pthread_mutex_t mu;
  int n;
  int counts[8];
  char ids[8][8][64];
} EndState;

typedef struct SeenState {
  pthread_mutex_t mu;
  int n;
  char jti[16][160];
  int ended[16];
  int nses[16];
  char ses[16][4][64];
} SeenState;

typedef struct LogState {
  pthread_mutex_t mu;
  int n;
  char msg[16][1024];
} LogState;

static int remember_end(const iya_wsfed_event *event, void *user, char *err, size_t err_len) {
  (void)err;
  (void)err_len;
  EndState *st = user;
  pthread_mutex_lock(&st->mu);
  if (st->n < 8) {
    int c = event->session_count;
    if (c > 8) c = 8;
    st->counts[st->n] = c;
    for (int i = 0; i < c; i++) snprintf(st->ids[st->n][i], 64, "%s", event->sessions[i] ? event->sessions[i] : "");
    st->n++;
  }
  pthread_mutex_unlock(&st->mu);
  return 0;
}

static int remember_seen(const iya_wsfed_event *event, void *user, char *err, size_t err_len) {
  (void)err;
  (void)err_len;
  SeenState *st = user;
  pthread_mutex_lock(&st->mu);
  if (st->n < 16) {
    int at = st->n++;
    snprintf(st->jti[at], 160, "%s", event->jti ? event->jti : "");
    st->ended[at] = event->ended;
    int c = event->session_count;
    if (c > 4) c = 4;
    st->nses[at] = c;
    for (int i = 0; i < c; i++) snprintf(st->ses[at][i], 64, "%s", event->sessions[i] ? event->sessions[i] : "");
  }
  pthread_mutex_unlock(&st->mu);
  return 0;
}

static int end_ok(const iya_wsfed_event *event, void *user, char *err, size_t err_len) {
  (void)event;
  (void)user;
  (void)err;
  (void)err_len;
  return 0;
}

static void track_login(iya_wsfed_receiver *receiver, const char *local, const char *person, const char *session) {
  char subject[128];
  char email[128];
  snprintf(subject, sizeof subject, "urn:uuid:%s", person);
  snprintf(email, sizeof email, "%s@example.com", person);
  iya_wsfed_receiver_track(receiver, local, person, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", session, subject,
                           email);
}

static iya_wsfed_receiver *must_receiver(const char *url, iya_wsfed_end_fn on_end, void *user, iya_wsfed_log_fn log, void *log_user) {
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  iya_wsfed_receiver *receiver = iya_wsfed_receiver_new(url, on_end, user, 60000, log, log_user, &err);
  if (!receiver) die(err.message[0] ? err.message : "receiver");
  return receiver;
}

static void must_start(iya_wsfed_receiver *receiver) {
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  if (iya_wsfed_receiver_start(receiver, &err) != 0) die(err.message);
}

static void must_poll(iya_wsfed_receiver *receiver) {
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  int more = 0;
  if (iya_wsfed_receiver_poll(receiver, &more, &err) != 0) die(err.message[0] ? err.message : "poll");
}

static const char *ev(const char *name) {
  const char *uri = iya_wsfed_event_uri(name);
  if (!uri) die(name);
  return uri;
}

void TestPollStreamEndsTheNamedSessions(void) {
  iya_http_server *server = NULL;
  Stub *stub = stub_open(&server);
  EndState ended;
  SeenState seen;
  memset(&ended, 0, sizeof ended);
  memset(&seen, 0, sizeof seen);
  pthread_mutex_init(&ended.mu, NULL);
  pthread_mutex_init(&seen.mu, NULL);
  iya_wsfed_receiver *receiver = must_receiver(stub->base, remember_end, &ended, NULL, NULL);
  iya_wsfed_receiver_on(receiver, "*", remember_seen, &seen);
  must_start(receiver);
  iya_wsfed_receiver_stop(receiver);
  if (stub->created != 1 || strcmp(iya_wsfed_receiver_stream_id(receiver), "s1") != 0) dief("stream %d %s", stub->created, iya_wsfed_receiver_stream_id(receiver));
  track_login(receiver, "L-a1", "alice", "IDP-A1");
  track_login(receiver, "L-a2", "alice", "IDP-A2");
  track_login(receiver, "L-b1", "bob", "IDP-B1");
  char *alice_session = aprintf(
      "{\"format\":\"complex\",\"user\":{\"format\":\"iss_sub\",\"iss\":\"%s\",\"sub\":\"urn:uuid:alice\"},\"session\":{\"format\":\"opaque\",\"id\":\"IDP-A1\"}}",
      stub->base);
  char *bob_user = aprintf("{\"format\":\"complex\",\"user\":{\"format\":\"iss_sub\",\"iss\":\"%s\",\"sub\":\"urn:uuid:bob\"}}", stub->base);
  char *j1 = stub_put(stub, ev("session_revoked"), alice_session, NULL, NULL, NULL, NULL);
  char *j2 = stub_put(stub, ev("credential_change"), bob_user, "\"credential_type\":\"password\",\"change_type\":\"update\"", NULL, NULL, NULL);
  must_poll(receiver);
  if (ended.n != 1 || ended.counts[0] != 1 || strcmp(ended.ids[0][0], "L-a1") != 0) dief("ended %d", ended.n);
  int change = -1;
  for (int i = 0; i < seen.n; i++) {
    if (strcmp(seen.jti[i], j2) == 0) change = i;
  }
  if (change < 0 || seen.ended[change] || seen.nses[change] != 1 || strcmp(seen.ses[change][0], "L-b1") != 0) die("credential change");
  char *alice = aprintf("{\"format\":\"iss_sub\",\"iss\":\"%s\",\"sub\":\"urn:uuid:alice\"}", stub->base);
  char *j3 = stub_put(stub, ev("account_disabled"), alice, NULL, NULL, NULL, NULL);
  must_poll(receiver);
  if (ended.n != 2 || strcmp(ended.ids[1][0], "L-a2") != 0) die("account disabled");
  if (!stub_has(stub, 0, j1) || !stub_has(stub, 0, j2)) die("acks");
  char *bob_mail = strdup("{\"format\":\"email\",\"email\":\"BOB@example.com\"}");
  stub_put(stub, ev("credential_compromise"), bob_mail, "\"credential_type\":\"password\"", NULL, NULL, NULL);
  must_poll(receiver);
  if (ended.n < 3 || strcmp(ended.ids[2][0], "L-b1") != 0) die("compromise");
  must_poll(receiver);
  if (!stub_has(stub, 0, j3)) die("j3 ack");
  iya_wsfed_receiver *again = must_receiver(stub->base, end_ok, NULL, NULL, NULL);
  must_start(again);
  iya_wsfed_receiver_stop(again);
  if (stub->created != 1 || strcmp(iya_wsfed_receiver_stream_id(again), "s1") != 0) dief("reattach %d %s", stub->created, iya_wsfed_receiver_stream_id(again));
  iya_wsfed_receiver_free(again);
  iya_wsfed_receiver_free(receiver);
  free(alice_session);
  free(bob_user);
  free(alice);
  free(bob_mail);
  free(j1);
  free(j2);
  free(j3);
  pthread_mutex_destroy(&ended.mu);
  pthread_mutex_destroy(&seen.mu);
  stub_close(stub, server);
}

void TestForgedSetsAreReported(void) {
  iya_http_server *server = NULL;
  Stub *stub = stub_open(&server);
  EndState ended;
  memset(&ended, 0, sizeof ended);
  pthread_mutex_init(&ended.mu, NULL);
  iya_wsfed_receiver *receiver = must_receiver(stub->base, remember_end, &ended, NULL, NULL);
  must_start(receiver);
  iya_wsfed_receiver_stop(receiver);
  track_login(receiver, "L-c1", "carol", "IDP-C1");
  char *subject = aprintf(
      "{\"format\":\"complex\",\"user\":{\"format\":\"iss_sub\",\"iss\":\"%s\",\"sub\":\"urn:uuid:carol\"},\"session\":{\"format\":\"opaque\",\"id\":\"IDP-C1\"}}",
      stub->base);
  char *forged = stub_put(stub, ev("session_revoked"), subject, NULL, stub->other, NULL, NULL);
  char *mis = stub_put(stub, ev("session_revoked"), subject, NULL, NULL, "someone-else", NULL);
  char *foreign = stub_put(stub, ev("session_revoked"), subject, NULL, NULL, NULL, "https://evil.example");
  must_poll(receiver);
  int people = iya_wsfed_receiver_person_count(receiver, "urn:uuid:carol");
  const char *only = iya_wsfed_receiver_person_id(receiver, "urn:uuid:carol", 0);
  if (ended.n != 0 || people != 1 || !only || strcmp(only, "L-c1") != 0) die("session stayed");
  must_poll(receiver);
  if (!stub_has(stub, 1, forged) || !stub_has(stub, 1, mis) || !stub_has(stub, 1, foreign)) die("setErrs");
  iya_wsfed_receiver_free(receiver);
  free(subject);
  free(forged);
  free(mis);
  free(foreign);
  pthread_mutex_destroy(&ended.mu);
  stub_close(stub, server);
}

void TestEventCatalog(void) {
  if (iya_wsfed_caep_count() != 8 || iya_wsfed_risc_count() != 14) dief("catalog %d %d", iya_wsfed_caep_count(), iya_wsfed_risc_count());
  if (!iya_wsfed_caep_has(ev("risk_level_change")) || !iya_wsfed_risc_has(ev("opt_out_effective"))) die("names");
}

static int end_down(const iya_wsfed_event *event, void *user, char *err, size_t err_len) {
  (void)event;
  (void)user;
  snprintf(err, err_len, "store down");
  return 1;
}

static int handler_bug(const iya_wsfed_event *event, void *user, char *err, size_t err_len) {
  (void)event;
  (void)user;
  snprintf(err, err_len, "handler bug");
  return 1;
}

static void capture_log(const char *level, const char *message, void *user) {
  if (!level || strcmp(level, "error") != 0) return;
  LogState *st = user;
  pthread_mutex_lock(&st->mu);
  if (st->n < 16) snprintf(st->msg[st->n++], 1024, "%s", message ? message : "");
  pthread_mutex_unlock(&st->mu);
}

void TestHandlerAndOnEndErrorsAreStillAcknowledged(void) {
  iya_http_server *server = NULL;
  Stub *stub = stub_open(&server);
  SeenState seen;
  LogState log;
  memset(&seen, 0, sizeof seen);
  memset(&log, 0, sizeof log);
  pthread_mutex_init(&seen.mu, NULL);
  pthread_mutex_init(&log.mu, NULL);
  iya_wsfed_receiver *receiver = must_receiver(stub->base, end_down, NULL, capture_log, &log);
  iya_wsfed_receiver_on(receiver, ev("credential_change"), handler_bug, NULL);
  iya_wsfed_receiver_on(receiver, "*", remember_seen, &seen);
  must_start(receiver);
  iya_wsfed_receiver_stop(receiver);
  track_login(receiver, "L-d1", "dave", "IDP-D1");
  char *user = aprintf("{\"format\":\"complex\",\"user\":{\"format\":\"iss_sub\",\"iss\":\"%s\",\"sub\":\"urn:uuid:dave\"}}", stub->base);
  char *session = aprintf(
      "{\"format\":\"complex\",\"user\":{\"format\":\"iss_sub\",\"iss\":\"%s\",\"sub\":\"urn:uuid:dave\"},\"session\":{\"format\":\"opaque\",\"id\":\"IDP-D1\"}}",
      stub->base);
  char *j1 = stub_put(stub, ev("credential_change"), user, "\"credential_type\":\"password\",\"change_type\":\"update\"", NULL, NULL, NULL);
  char *j2 = stub_put(stub, ev("session_revoked"), session, NULL, NULL, NULL, NULL);
  for (int i = 0; i < 3; i++) must_poll(receiver);
  if (!stub_has(stub, 0, j1) || !stub_has(stub, 0, j2)) die("acks");
  if (stub_has(stub, 1, j1) || stub_has(stub, 1, j2)) die("errs");
  int saw1 = 0, saw2 = 0;
  for (int i = 0; i < seen.n; i++) {
    if (strcmp(seen.jti[i], j1) == 0) saw1 = 1;
    if (strcmp(seen.jti[i], j2) == 0) saw2 = 1;
  }
  if (!saw1 || !saw2) die("seen");
  int handler = 0, ended = 0;
  for (int i = 0; i < log.n; i++) {
    if (strstr(log.msg[i], "handler for") && strstr(log.msg[i], "credential-change") && strstr(log.msg[i], "threw")) handler = 1;
    if (strstr(log.msg[i], "onEndSessions threw")) ended = 1;
  }
  if (!handler || !ended) die(log.n ? log.msg[0] : "no log");
  iya_wsfed_receiver_free(receiver);
  free(user);
  free(session);
  free(j1);
  free(j2);
  pthread_mutex_destroy(&seen.mu);
  pthread_mutex_destroy(&log.mu);
  stub_close(stub, server);
}

typedef struct PollJob {
  iya_wsfed_receiver *receiver;
  int rc;
} PollJob;

static void *poll_thread(void *arg) {
  PollJob *job = arg;
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  int more = 0;
  job->rc = iya_wsfed_receiver_poll(job->receiver, &more, &err);
  return NULL;
}

void TestOverlappingPollsHandleASetOnce(void) {
  iya_http_server *server = NULL;
  Stub *stub = stub_open(&server);
  SeenState seen;
  memset(&seen, 0, sizeof seen);
  pthread_mutex_init(&seen.mu, NULL);
  iya_wsfed_receiver *receiver = must_receiver(stub->base, end_ok, NULL, NULL, NULL);
  iya_wsfed_receiver_on(receiver, "*", remember_seen, &seen);
  must_start(receiver);
  iya_wsfed_receiver_stop(receiver);
  char *subject = aprintf("{\"format\":\"iss_sub\",\"iss\":\"%s\",\"sub\":\"urn:uuid:erin\"}", stub->base);
  char *jti = stub_put(stub, ev("account_enabled"), subject, NULL, NULL, NULL, NULL);
  PollJob jobs[3];
  pthread_t threads[3];
  for (int i = 0; i < 3; i++) {
    jobs[i].receiver = receiver;
    jobs[i].rc = -1;
    if (pthread_create(&threads[i], NULL, poll_thread, &jobs[i]) != 0) die("thread");
  }
  for (int i = 0; i < 3; i++) pthread_join(threads[i], NULL);
  for (int i = 0; i < 3; i++) {
    if (jobs[i].rc != 0) die("overlap poll");
  }
  must_poll(receiver);
  int count = 0;
  for (int i = 0; i < seen.n; i++) {
    if (strcmp(seen.jti[i], jti) == 0) count++;
  }
  if (count != 1) dief("handled %d", count);
  iya_wsfed_receiver_free(receiver);
  free(subject);
  free(jti);
  pthread_mutex_destroy(&seen.mu);
  stub_close(stub, server);
}

/* Plain http off loopback (#14). These run inside two registered tests:
 * PlainHttpMetadataChecks() from TestReadsTheSecurityTokenServiceRole
 * (suite.c), and PlainHttpTransmitterChecks() from
 * TestRefusesATransmitterWithoutPollDelivery below. Each fetch (metadata, the
 * transmitter's configuration and JWKS) is refused before a connection is
 * opened. http://example.com names a host off this machine;
 * http://0.0.0.0:<port> is not loopback either, but Linux delivers it to a
 * socket on 127.0.0.1, so a listener there shows whether the library opened a
 * connection at all. */
typedef struct {
  int fd;
  int port;
} Tripwire;

static Tripwire tripwire_open(void) {
  Tripwire t = {-1, 0};
  t.fd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (t.fd < 0 || bind(t.fd, (struct sockaddr *)&addr, sizeof addr) != 0 || listen(t.fd, 8) != 0) die("tripwire");
  socklen_t len = sizeof addr;
  getsockname(t.fd, (struct sockaddr *)&addr, &len);
  t.port = ntohs(addr.sin_port);
  return t;
}

/* Dies when a connection is waiting to be accepted, then closes the listener. */
static void tripwire_close_untouched(Tripwire *t) {
  fd_set fds;
  FD_ZERO(&fds);
  FD_SET(t->fd, &fds);
  struct timeval tv = {0, 200000};
  int waiting = select(t->fd + 1, &fds, NULL, NULL, &tv) > 0;
  close(t->fd);
  if (waiting) die("a connection was opened");
}

static void expect_plain_refusal(const iya_wsfed_error *err, const char *code, const char *host, const char *secret) {
  char *want = aprintf("http://%s is refused: plain http is allowed only to a loopback host", host);
  int ok = strcmp(err->code, code) == 0 && strncmp(err->message, want, strlen(want)) == 0 && msg_has(err->message, "use https");
  free(want);
  if (!ok) dief("plain http: code %s want %s: %s", err->code, code, err->message);
  if (secret && msg_has(err->message, secret)) dief("the secret is in the message: %s", err->message);
  if (msg_has(err->message, "/md") || msg_has(err->message, "/jwks") || msg_has(err->message, "?")) dief("path or query in %s", err->message);
}

static void expect_unsafe(const iya_wsfed_error *err, const char *code) {
  if (strcmp(err->code, code) != 0 || !msg_has(err->message, "whitespace or a control character")) dief("unsafe URL: %s %s", err->code, err->message);
}

/* Creates a relying party whose idpMetadata is `source` (a JSON string body) and requires it to fail. */
static void party_fails(const char *source, iya_wsfed_error *err) {
  char *json = cfg_json(source, 1, NULL);
  memset(err, 0, sizeof *err);
  iya_wsfed_party *party = iya_wsfed_party_create(json, "", err);
  free(json);
  if (party) {
    iya_wsfed_party_free(party);
    dief("metadata at %s was read", source);
  }
}

static char *read_all(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) die(path);
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *out = malloc((size_t)n + 1);
  if (fread(out, 1, (size_t)n, f) != (size_t)n) die("read");
  out[n] = 0;
  fclose(f);
  return out;
}

static void meta_handle(const char *method, const char *target, const char *body, void *user, int *status,
                        char **response_body) {
  (void)method;
  (void)target;
  (void)body;
  *status = 200;
  *response_body = strdup((const char *)user);
}

static void metadata_over(const char *host) {
  char *xml = read_all(default_meta_path());
  int port = 0;
  iya_http_server *server = iya_http_serve(meta_handle, xml, &port);
  if (!server || port <= 0) die("metadata server");
  char *url = aprintf("http://%s:%d/md", host, port);
  char *json = cfg_json(url, 1, NULL);
  iya_wsfed_party *party = must_party(json);
  if (strcmp(iya_wsfed_party_idp_entity(party), IDP_ENTITY) != 0) dief("entity over %s", host);
  iya_wsfed_party_free(party);
  free(json);
  free(url);
  iya_http_server_close(server);
  free(xml);
}

void PlainHttpMetadataChecks(void) {
  iya_wsfed_error err;
  party_fails("http://example.com/md?x=1", &err);
  expect_plain_refusal(&err, "metadata", "example.com", NULL);
  Tripwire t = tripwire_open();
  char *url = aprintf("http://0.0.0.0:%d/md", t.port);
  char *host = aprintf("0.0.0.0:%d", t.port);
  party_fails(url, &err);
  expect_plain_refusal(&err, "metadata", host, NULL);
  free(url);
  free(host);
  /* Userinfo is never loopback, and never in the message. */
  url = aprintf("http://localhost:%d@example.com/md", t.port);
  party_fails(url, &err);
  expect_plain_refusal(&err, "metadata", "example.com", NULL);
  free(url);
  url = aprintf("http://alice:s3cret-pw@localhost:%d/md", t.port);
  host = aprintf("localhost:%d", t.port);
  party_fails(url, &err);
  expect_plain_refusal(&err, "metadata", host, "s3cret-pw");
  if (msg_has(err.message, "alice")) die("the user name is in the message");
  free(url);
  free(host);
  /* Whitespace or a control character anywhere (JSON escapes; the
   * configuration trims only the ends). */
  const char *unsafe[] = {"http://127.0.0.1:%d/m\\td", "http://127.0.0.1:%d/m\\nd", "https://127.0.0.1:%d/m d",
                          "http://127.0.0.1:%d/m\\u007fd"};
  for (size_t i = 0; i < sizeof unsafe / sizeof unsafe[0]; i++) {
    url = aprintf(unsafe[i], t.port);
    party_fails(url, &err);
    expect_unsafe(&err, "metadata");
    free(url);
  }
  tripwire_close_untouched(&t);
  /* Plain http to loopback still works: 127.0.0.1 and localhost. */
  metadata_over("127.0.0.1");
  metadata_over("localhost");
  /* https is not touched by the rule: a closed port fails as a connection
   * failure, not as a refusal of plain http. */
  party_fails("https://127.0.0.1:1/md", &err);
  if (strcmp(err.code, "metadata") != 0 || msg_has(err.message, "plain http")) dief("https: %s %s", err.code, err.message);
}

static void transmitter_refused(const char *transmitter, const char *host, const char *secret) {
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  iya_wsfed_receiver *receiver = iya_wsfed_receiver_new(transmitter, end_ok, NULL, 60000, NULL, NULL, &err);
  if (!receiver) die(err.message);
  memset(&err, 0, sizeof err);
  if (iya_wsfed_receiver_start(receiver, &err) == 0) dief("the receiver started at %s", transmitter);
  if (host) expect_plain_refusal(&err, "ssf", host, secret);
  else expect_unsafe(&err, "ssf");
  iya_wsfed_receiver_free(receiver);
}

/* A loopback transmitter whose configuration names `user` as its jwks_uri. */
static void jwks_naming_handle(const char *method, const char *target, const char *body, void *user, int *status,
                               char **response_body) {
  (void)method;
  (void)body;
  *status = 200;
  if (target && strcmp(target, "/.well-known/ssf-configuration") == 0) {
    *response_body = aprintf(
        "{\"issuer\":\"http://127.0.0.1\",\"jwks_uri\":\"%s\",\"configuration_endpoint\":\"http://127.0.0.1:1/ssf/stream\","
        "\"delivery_methods_supported\":[\"urn:ietf:rfc:8936\"]}",
        (const char *)user);
  } else {
    *response_body = strdup("{}");
  }
}

static void jwks_refused(const char *jwks_uri, const char *host) {
  int port = 0;
  iya_http_server *server = iya_http_serve(jwks_naming_handle, (void *)jwks_uri, &port);
  if (!server || port <= 0) die("transmitter stub");
  char *base = aprintf("http://127.0.0.1:%d", port);
  transmitter_refused(base, host, NULL);
  free(base);
  iya_http_server_close(server);
}

static void PlainHttpTransmitterChecks(void) {
  transmitter_refused("http://example.com:8080", "example.com:8080", NULL);
  jwks_refused("http://example.com/jwks", "example.com");
  Tripwire t = tripwire_open();
  char *url = aprintf("http://0.0.0.0:%d", t.port);
  char *host = aprintf("0.0.0.0:%d", t.port);
  transmitter_refused(url, host, NULL);
  free(url);
  url = aprintf("http://0.0.0.0:%d/jwks", t.port);
  jwks_refused(url, host);
  free(url);
  free(host);
  url = aprintf("http://user:s3cret-pw@127.0.0.1:%d", t.port);
  host = aprintf("127.0.0.1:%d", t.port);
  transmitter_refused(url, host, "s3cret-pw");
  free(url);
  free(host);
  url = aprintf("http://127.0.0.1:%d/m d", t.port);
  transmitter_refused(url, NULL, NULL);
  free(url);
  tripwire_close_untouched(&t);
}

void TestRefusesATransmitterWithoutPollDelivery(void) {
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  iya_wsfed_receiver *receiver = iya_wsfed_receiver_new("http://127.0.0.1:1", end_ok, NULL, 60000, NULL, NULL, &err);
  if (!receiver) die(err.message);
  memset(&err, 0, sizeof err);
  int rc = iya_wsfed_receiver_start(receiver, &err);
  expect_err(rc != 0, &err, "ssf", "");
  iya_wsfed_receiver_free(receiver);
  PlainHttpTransmitterChecks();
}

static void write_text(const char *path, const char *body) {
  FILE *f = fopen(path, "w");
  if (!f) die(path);
  fputs(body, f);
  fclose(f);
}

void TestConfigureSignalsBehavior(void) {
  char dir[] = "/tmp/wsfedcfgXXXXXX";
  if (!mkdtemp(dir)) die("mkdtemp");
  const char *base_body =
      "{\n"
      "  \"realm\": \"http://localhost:3000/\",\n"
      "  \"replyUrl\": \"http://localhost:3000/wsfed\",\n"
      "  \"privateKey\": \"generated/rp.key\",\n"
      "  \"certificate\": \"generated/rp.crt\",\n"
      "  \"idpMetadata\": \"generated/idp-metadata.xml\",\n"
      "  \"idpCa\": \"generated/idp-ca.pem\"\n"
      "}\n";
  char path[512];
  snprintf(path, sizeof path, "%s/wsfed.json", dir);
  write_text(path, base_body);
  char *with_ssf = aprintf("%s/wsfed-ssf.json", dir);
  char *off = aprintf("%s/off.json", dir);
  char *on = aprintf("%s/on.json", dir);
  char *bad = aprintf("%s/bad.json", dir);
  char *ssf_body = aprintf(
      "{\n  \"realm\": \"http://localhost:3000/\",\n  \"replyUrl\": \"http://localhost:3000/wsfed\",\n"
      "  \"privateKey\": \"generated/rp.key\",\n  \"certificate\": \"generated/rp.crt\",\n"
      "  \"idpMetadata\": \"generated/idp-metadata.xml\",\n  \"idpCa\": \"generated/idp-ca.pem\",\n"
      "  \"ssf\": {\"transmitter\": \"https://localhost:8081\"}\n}\n");
  char *off_body = aprintf(
      "{\n  \"realm\": \"http://localhost:3000/\",\n  \"replyUrl\": \"http://localhost:3000/wsfed\",\n"
      "  \"privateKey\": \"generated/rp.key\",\n  \"certificate\": \"generated/rp.crt\",\n"
      "  \"idpMetadata\": \"generated/idp-metadata.xml\",\n  \"idpCa\": \"generated/idp-ca.pem\",\n"
      "  \"signals\": false,\n  \"ssf\": {\"transmitter\": \"https://localhost:8081\"}\n}\n");
  char *on_body = aprintf(
      "{\n  \"realm\": \"http://localhost:3000/\",\n  \"replyUrl\": \"http://localhost:3000/wsfed\",\n"
      "  \"privateKey\": \"generated/rp.key\",\n  \"certificate\": \"generated/rp.crt\",\n"
      "  \"idpMetadata\": \"generated/idp-metadata.xml\",\n  \"idpCa\": \"generated/idp-ca.pem\",\n"
      "  \"signals\": true,\n  \"ssf\": {\"transmitter\": \"https://localhost:8081\"}\n}\n");
  char *bad_body = aprintf(
      "{\n  \"realm\": \"http://localhost:3000/\",\n  \"replyUrl\": \"http://localhost:3000/wsfed\",\n"
      "  \"privateKey\": \"generated/rp.key\",\n  \"certificate\": \"generated/rp.crt\",\n"
      "  \"idpMetadata\": \"generated/idp-metadata.xml\",\n  \"idpCa\": \"generated/idp-ca.pem\",\n"
      "  \"signals\": \"no\"\n}\n");
  write_text(with_ssf, ssf_body);
  write_text(off, off_body);
  write_text(on, on_body);
  write_text(bad, bad_body);
  char cwd[512];
  if (!getcwd(cwd, sizeof cwd)) die("cwd");
  char *check = aprintf("%s/check.py", dir);
  write_text(check,
             "import sys\n"
             "sys.path.insert(0, sys.argv[1])\n"
             "from configure_iya_sts import files_of, plan_for\n"
             "base, with_ssf, off, on, bad = sys.argv[2:]\n"
             "files = files_of(base)\n"
             "ssf = files_of(with_ssf)\n"
             "assert any(call[\"path\"].endswith(\"/applications/add-certificate\") for call in plan_for(ssf, \"https://localhost:8081\", \"\"))\n"
             "assert not any(call[\"path\"].endswith(\"/applications/add-certificate\") for call in plan_for(files, \"https://localhost:8081\", \"\"))\n"
             "off_files = files_of(off)\n"
             "assert off_files[\"signals\"] is False\n"
             "assert off_files[\"ssf_transmitter\"] == \"https://localhost:8081\"\n"
             "assert off_files[\"realm\"] == \"http://localhost:3000/\"\n"
             "assert off_files[\"reply_url\"] == \"http://localhost:3000/wsfed\"\n"
             "assert not any(call[\"path\"].endswith(\"/applications/add-certificate\") for call in plan_for(off_files, \"https://localhost:8081\", \"\"))\n"
             "assert not any(call[\"path\"].endswith(\"/roles/add-member\") for call in plan_for(off_files, \"https://localhost:8081\", \"\"))\n"
             "assert \"signals\" not in files_of(on)\n"
             "assert any(call[\"path\"].endswith(\"/applications/add-certificate\") for call in plan_for(files_of(on), \"https://localhost:8081\", \"\"))\n"
             "try:\n"
             "    files_of(bad)\n"
             "except ValueError as err:\n"
             "    assert str(err) == \"signals must be true or false\", str(err)\n"
             "else:\n"
             "    raise SystemExit(\"signals string was accepted\")\n"
             "print(\"ok\")\n");
  char *cmd = aprintf("python3 %s %s/scripts %s %s %s %s %s > %s/out.txt 2>&1", check, cwd, path, with_ssf, off, on, bad, dir);
  int rc = system(cmd);
  if (rc != 0) {
    FILE *out = fopen(aprintf("%s/out.txt", dir), "r");
    char buf[2048];
    buf[0] = 0;
    if (out) {
      size_t n = fread(buf, 1, sizeof buf - 1, out);
      buf[n] = 0;
      fclose(out);
    }
    dief("configure %d %s", rc, buf);
  }
  free(with_ssf);
  free(off);
  free(on);
  free(bad);
  free(ssf_body);
  free(off_body);
  free(on_body);
  free(bad_body);
  free(check);
  free(cmd);
}

static const unsigned char kSkiOid[] = {0x06, 0x03, 0x55, 0x1d, 0x0e};
static const unsigned char kAkiOid[] = {0x06, 0x03, 0x55, 0x1d, 0x23};

static int key_id_after(const unsigned char *der, int len, const unsigned char *oid, int oid_len, unsigned char out[20]) {
  for (int i = 0; i + oid_len < len; i++) {
    if (memcmp(der + i, oid, (size_t)oid_len) != 0) continue;
    const unsigned char *rest = der + i + oid_len;
    int rest_len = len - (i + oid_len);
    for (int j = 0; j + 21 <= rest_len; j++) {
      if (rest[j] == 0x14) {
        memcpy(out, rest + j + 1, 20);
        return 1;
      }
    }
    return 0;
  }
  return 0;
}

static X509 *cert_from_pem(const char *pem) {
  BIO *bio = BIO_new_mem_buf(pem, -1);
  X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  BIO_free(bio);
  if (!cert) die("cert");
  return cert;
}

static void sha1_public(const char *key_pem, unsigned char out[20]) {
  BIO *bio = BIO_new_mem_buf(key_pem, -1);
  EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  BIO_free(bio);
  if (!key) die("key");
  unsigned char *pkcs1 = NULL;
  int n = i2d_PublicKey(key, &pkcs1);
  EVP_PKEY_free(key);
  if (n <= 0 || !pkcs1) die("spki");
  SHA1(pkcs1, (size_t)n, out);
  OPENSSL_free(pkcs1);
}

static char *subject_rfc2253(X509 *cert) {
  BIO *bio = BIO_new(BIO_s_mem());
  X509_NAME_print_ex(bio, X509_get_subject_name(cert), 0, XN_FLAG_RFC2253);
  char *data = NULL;
  long len = BIO_get_mem_data(bio, &data);
  char *out = strndup(data && len > 0 ? data : "", len > 0 ? (size_t)len : 0);
  BIO_free(bio);
  return out;
}

static char *common_name_of(X509 *cert) {
  X509_NAME *name = X509_get_subject_name(cert);
  int idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
  if (idx < 0) return strdup("");
  ASN1_STRING *str = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, idx));
  unsigned char *utf = NULL;
  int n = ASN1_STRING_to_UTF8(&utf, str);
  char *out = n > 0 ? strndup((char *)utf, (size_t)n) : strdup("");
  if (utf) OPENSSL_free(utf);
  return out;
}

static void expect_key_ids(const char *key_pem, const char *cert_pem) {
  unsigned char want[20], ski[20], aki[20];
  sha1_public(key_pem, want);
  X509 *cert = cert_from_pem(cert_pem);
  unsigned char *der = NULL;
  int n = i2d_X509(cert, &der);
  X509_free(cert);
  if (n <= 0 || !der) die("der");
  if (!key_id_after(der, n, kSkiOid, (int)sizeof kSkiOid, ski) || !key_id_after(der, n, kAkiOid, (int)sizeof kAkiOid, aki) ||
      memcmp(ski, want, 20) != 0 || memcmp(aki, want, 20) != 0) {
    die("key id");
  }
  OPENSSL_free(der);
}

void TestSignsItselfAndNamesItsKey(void) {
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  iya_wsfed_keypair *pair = iya_wsfed_generate_keys("rp", 30, 2048, &err);
  if (!pair) die(err.message);
  X509 *cert = cert_from_pem(iya_wsfed_keypair_cert(pair));
  EVP_PKEY *pub = X509_get_pubkey(cert);
  if (X509_verify(cert, pub) != 1) die("signature");
  EVP_PKEY_free(pub);
  X509_free(cert);
  expect_key_ids(iya_wsfed_keypair_key(pair), iya_wsfed_keypair_cert(pair));
  iya_wsfed_keypair_free(pair);
}

void TestTwoCertificatesOfOneNameHaveDifferentKeyIdentifiers(void) {
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  iya_wsfed_keypair *one = iya_wsfed_generate_keys("localhost:3000", 30, 2048, &err);
  if (!one) die(err.message);
  memset(&err, 0, sizeof err);
  iya_wsfed_keypair *two = iya_wsfed_generate_keys("localhost:3000", 30, 2048, &err);
  if (!two) die(err.message);
  X509 *a = cert_from_pem(iya_wsfed_keypair_cert(one));
  X509 *b = cert_from_pem(iya_wsfed_keypair_cert(two));
  char *as = subject_rfc2253(a);
  char *bs = subject_rfc2253(b);
  char *ac = common_name_of(a);
  char *bc = common_name_of(b);
  if (strcmp(as, bs) != 0 || strcmp(ac, "localhost:3000") != 0 || strcmp(bc, "localhost:3000") != 0) dief("subject %s %s", as, bs);
  unsigned char *da = NULL;
  unsigned char *db = NULL;
  int na = i2d_X509(a, &da);
  int nb = i2d_X509(b, &db);
  unsigned char ska[20], skb[20];
  if (!key_id_after(da, na, kSkiOid, (int)sizeof kSkiOid, ska) || !key_id_after(db, nb, kSkiOid, (int)sizeof kSkiOid, skb) ||
      memcmp(ska, skb, 20) == 0) {
    die("same key id");
  }
  OPENSSL_free(da);
  OPENSSL_free(db);
  X509_free(a);
  X509_free(b);
  free(as);
  free(bs);
  free(ac);
  free(bc);
  iya_wsfed_keypair_free(one);
  iya_wsfed_keypair_free(two);
}

void TestGenerateKeysNamesTheCertificateAfterTheRealm(void) {
  char dir[] = "/tmp/wsfedkeyXXXXXX";
  if (!mkdtemp(dir)) die("mkdtemp");
  char *config = aprintf("%s/wsfed.json", dir);
  write_text(config,
             "{\"realm\":\"http://localhost:3000/\",\"replyUrl\":\"http://localhost:3000/wsfed\",\"idpMetadata\":\"x\","
             "\"privateKey\":\"k.pem\",\"certificate\":\"c.pem\"}");
  char *argv[] = {"generate-keys", "--config", config, "--bits", "2048"};
  if (iya_wsfed_cli(5, argv) != 0) die("generate-keys");
  char *cert_path = aprintf("%s/c.pem", dir);
  FILE *f = fopen(cert_path, "r");
  if (!f) die("c.pem");
  char pem[8192];
  size_t n = fread(pem, 1, sizeof pem - 1, f);
  pem[n] = 0;
  fclose(f);
  X509 *cert = cert_from_pem(pem);
  char *subject = subject_rfc2253(cert);
  char *cn = common_name_of(cert);
  const char *want = "CN=wsfed-caep-nodejs relying party http://localhost:3000/";
  const char *cn_want = "wsfed-caep-nodejs relying party http://localhost:3000/";
  if (strcmp(subject, want) != 0 || strcmp(cn, cn_want) != 0) dief("subject %s cn %s", subject, cn);
  X509_free(cert);
  free(subject);
  free(cn);
  free(cert_path);
  free(config);
}

static void cookie_of(const iya_http_response *response, const char *name, char *out, size_t n) {
  out[0] = 0;
  int count = iya_http_header_count(response, "set-cookie");
  for (int i = 0; i < count; i++) {
    const char *raw = iya_http_header_at(response, "set-cookie", i);
    if (!raw) continue;
    char buf[2048];
    snprintf(buf, sizeof buf, "%s", raw);
    char *semi = strchr(buf, ';');
    if (semi) *semi = 0;
    char *eq = strchr(buf, '=');
    if (!eq) continue;
    *eq = 0;
    if (strcmp(buf, name) == 0) {
      snprintf(out, n, "%s", eq + 1);
      return;
    }
  }
}

static iya_http_response *http_must(const char *method, const char *url, const char *type, const char *body, const char *cookie) {
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  iya_http_response *response = iya_http_call(method, url, type, body, cookie, &err);
  if (!response) die(err.message[0] ? err.message : "http");
  return response;
}

void TestSignInCleanupAndLogout(void) {
  char *json = cfg_json(default_meta_path(), 1, NULL);
  iya_wsfed_party *party = must_party(json);
  free(json);
  iya_wsfed_app *app = iya_wsfed_app_new(party);
  iya_wsfed_party_free(party);
  if (!app) die("app");
  int port = 0;
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  if (iya_wsfed_app_listen(app, &port, &err) != 0) die(err.message);
  char *base = aprintf("http://127.0.0.1:%d", port);
  char *health_url = aprintf("%s/healthz", base);
  iya_http_response *health = http_must("GET", health_url, "", "", "");
  if (iya_http_status(health) != 200 || strcmp(iya_http_body(health), "ok") != 0) die(iya_http_body(health));
  iya_http_response_free(health);
  char *login_url = aprintf("%s/login", base);
  iya_http_response *login = http_must("GET", login_url, "", "", "");
  if (iya_http_status(login) != 302) dief("login %d", iya_http_status(login));
  const char *location = iya_http_header_at(login, "location", 0);
  if (!location || strncmp(location, "https://idp.test/wsfed?", strlen("https://idp.test/wsfed?")) != 0) die(location ? location : "location");
  char *wa = query_get(location, "wa");
  char *wctx = query_get(location, "wctx");
  if (!wa || strcmp(wa, "wsignin1.0") != 0 || !wctx) die("query");
  char pending[512];
  cookie_of(login, "wsfed_pending", pending, sizeof pending);
  if (!pending[0]) die("pending");
  char cookie[640];
  snprintf(cookie, sizeof cookie, "wsfed_pending=%s", pending);
  char *made = signed_assertion(NULL, NULL, 0);
  char *result = wresult_xml(made, NULL, NULL, NULL, 0, 0);
  char *form = form_body(result, wctx);
  char *reply_url = aprintf("%s/wsfed", base);
  iya_http_response *reply = http_must("POST", reply_url, "application/x-www-form-urlencoded", form, cookie);
  if (iya_http_status(reply) != 303) dief("reply %d %s", iya_http_status(reply), iya_http_body(reply));
  char sid[512];
  cookie_of(reply, "sid", sid, sizeof sid);
  if (!sid[0]) die("sid");
  char sid_cookie[640];
  snprintf(sid_cookie, sizeof sid_cookie, "sid=%s", sid);
  char *home_url = aprintf("%s/", base);
  iya_http_response *home = http_must("GET", home_url, "", "", sid_cookie);
  if (!contains(iya_http_body(home), "Signed in as <strong>alice-1234</strong>") || !contains(iya_http_body(home), "https://idp.test"))
    die(iya_http_body(home));
  iya_http_response_free(home);
  char *clean_url = aprintf("%s/wsfed?wa=wsignoutcleanup1.0", base);
  iya_http_response *cleanup = http_must("GET", clean_url, "", "", sid_cookie);
  if (!contains(iya_http_header_at(cleanup, "content-type", 0), "image/gif")) die(iya_http_header_at(cleanup, "content-type", 0));
  iya_http_response_free(cleanup);
  home = http_must("GET", home_url, "", "", sid_cookie);
  if (!contains(iya_http_body(home), "Sign in with WS-Federation")) die(iya_http_body(home));
  iya_http_response_free(home);
  char *logout_url = aprintf("%s/logout", base);
  iya_http_response *out = http_must("POST", logout_url, "", "", "");
  const char *out_loc = iya_http_header_at(out, "location", 0);
  char *out_wa = out_loc ? query_get(out_loc, "wa") : NULL;
  if (!out_wa || strcmp(out_wa, "wsignout1.0") != 0) die(out_loc ? out_loc : "logout");
  iya_http_response_free(out);
  iya_http_response *refused = http_must("POST", reply_url, "application/x-www-form-urlencoded", "wa=wsignin1.0&wresult=x&wctx=id%3Dabc", "");
  if (iya_http_status(refused) != 400) dief("refused %d %s", iya_http_status(refused), iya_http_body(refused));
  iya_http_response_free(refused);
  iya_http_response_free(reply);
  iya_http_response_free(login);
  iya_wsfed_app_close(app);
  free(wa);
  free(wctx);
  free(made);
  free(result);
  free(form);
  free(out_wa);
  free(base);
  free(health_url);
  free(login_url);
  free(reply_url);
  free(home_url);
  free(clean_url);
  free(logout_url);
}

void TestLiveStatusReportsTheSignInWithoutTokens(void) {
  char *json = cfg_json(default_meta_path(), 1, NULL);
  iya_wsfed_party *party = must_party(json);
  free(json);
  iya_wsfed_app *app = iya_wsfed_app_new(party);
  iya_wsfed_party_free(party);
  if (!app) die("app");
  int port = 0;
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  if (iya_wsfed_app_listen(app, &port, &err) != 0) die(err.message);
  char *base = aprintf("http://127.0.0.1:%d", port);
  char *status_url = aprintf("%s/live-status", base);
  iya_http_response *before = http_must("GET", status_url, "", "", "");
  if (iya_http_status(before) != 200 || !contains(iya_http_header_at(before, "content-type", 0), "application/json")) die("status");
  if (strcmp(iya_http_body(before), "{\"signedIn\":false,\"subject\":null,\"receiver\":\"not configured\",\"events\":[]}") != 0)
    die(iya_http_body(before));
  iya_http_response_free(before);
  char *login_url = aprintf("%s/login", base);
  iya_http_response *login = http_must("GET", login_url, "", "", "");
  const char *location = iya_http_header_at(login, "location", 0);
  char *wctx = location ? query_get(location, "wctx") : NULL;
  if (!wctx) die("wctx");
  char pending[512];
  cookie_of(login, "wsfed_pending", pending, sizeof pending);
  char cookie[640];
  snprintf(cookie, sizeof cookie, "wsfed_pending=%s", pending);
  char *made = signed_assertion(NULL, NULL, 0);
  char *result = wresult_xml(made, NULL, NULL, NULL, 0, 0);
  char *form = form_body(result, wctx);
  char *reply_url = aprintf("%s/wsfed", base);
  iya_http_response *reply = http_must("POST", reply_url, "application/x-www-form-urlencoded", form, cookie);
  if (iya_http_status(reply) != 303) dief("reply %d %s", iya_http_status(reply), iya_http_body(reply));
  char sid[512];
  cookie_of(reply, "sid", sid, sizeof sid);
  char sid_cookie[640];
  snprintf(sid_cookie, sizeof sid_cookie, "sid=%s", sid);
  iya_http_response *after = http_must("GET", status_url, "", "", sid_cookie);
  const char *body = iya_http_body(after);
  if (!contains(body, "\"signedIn\":true") || !contains(body, "\"subject\":\"alice-1234\"")) die(body);
  if (contains(body, "Assertion") || contains(body, "wresult") || contains(body, "token")) die(body);
  iya_http_response_free(after);
  iya_http_response *other = http_must("GET", status_url, "", "", "");
  if (!contains(iya_http_body(other), "\"signedIn\":false")) die(iya_http_body(other));
  iya_http_response_free(other);
  iya_http_response_free(reply);
  iya_http_response_free(login);
  iya_wsfed_app_close(app);
  free(wctx);
  free(made);
  free(result);
  free(form);
  free(base);
  free(status_url);
  free(login_url);
  free(reply_url);
}
