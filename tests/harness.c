// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "harness.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static const char *g_test = "";
static iya_wsfed_keypair *g_rp;
static iya_wsfed_keypair *g_idp;
static char *g_meta;
static char *g_rp_key_path;
static char *g_rp_cert_path;
static char *g_idp_cert_path;

void harness_begin(const char *name) { g_test = name ? name : ""; }

void die(const char *msg) {
  fprintf(stderr, "%s: %s\n", g_test, msg ? msg : "");
  exit(1);
}

void dief(const char *fmt, ...) {
  fprintf(stderr, "%s: ", g_test);
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
  exit(1);
}

int msg_has(const char *msg, const char *pat) {
  if (!pat || !pat[0]) return 1;
  if (!msg) return 0;
  char *copy = strdup(pat);
  int ok = 0;
  char *save = NULL;
  for (char *part = strtok_r(copy, "|", &save); part; part = strtok_r(NULL, "|", &save)) {
    if (strstr(msg, part)) ok = 1;
  }
  free(copy);
  return ok;
}

void expect_err(int failed, const iya_wsfed_error *err, const char *code, const char *pat) {
  if (!failed) die("expected an error");
  if (!err || strcmp(err->code, code) != 0) dief("code %s, want %s: %s", err ? err->code : "", code, err ? err->message : "");
  if (!msg_has(err->message, pat)) dief("pattern %s not in %s", pat, err->message);
}

int contains(const char *hay, const char *needle) { return hay && needle && strstr(hay, needle) != NULL; }

long long wall_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void iso_at(char *out, size_t n, int offset_ms) {
  long long ms = wall_ms() + offset_ms;
  time_t sec = (time_t)(ms / 1000);
  int milli = (int)(ms % 1000);
  if (milli < 0) {
    milli += 1000;
    sec -= 1;
  }
  struct tm tm;
  gmtime_r(&sec, &tm);
  snprintf(out, n, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
           tm.tm_min, tm.tm_sec, milli);
}

static char *b64url(const unsigned char *data, size_t len) {
  size_t cap = ((len + 2) / 3) * 4 + 1;
  char *out = malloc(cap);
  int n = EVP_EncodeBlock((unsigned char *)out, data, (int)len);
  out[n] = 0;
  for (int i = 0; out[i]; i++) {
    if (out[i] == '+') out[i] = '-';
    else if (out[i] == '/') out[i] = '_';
  }
  while (n > 0 && out[n - 1] == '=') out[--n] = 0;
  return out;
}

static char *new_id(void) {
  unsigned char buf[16];
  if (RAND_bytes(buf, sizeof buf) != 1) die("rand");
  char *enc = b64url(buf, sizeof buf);
  size_t n = strlen(enc);
  char *id = malloc(n + 2);
  id[0] = '_';
  memcpy(id + 1, enc, n + 1);
  free(enc);
  return id;
}

char *pem_body(const char *pem) {
  char *out = calloc(strlen(pem) + 1, 1);
  const char *p = pem;
  while (*p) {
    const char *nl = strchr(p, '\n');
    size_t n = nl ? (size_t)(nl - p) : strlen(p);
    if (n < 10 || strstr(p, "-----") != p) {
      size_t at = strlen(out);
      memcpy(out + at, p, n);
      out[at + n] = 0;
    }
    if (!nl) break;
    p = nl + 1;
  }
  return out;
}

char *write_temp(const char *body) {
  char path[] = "/tmp/wsfedXXXXXX";
  int fd = mkstemp(path);
  if (fd < 0) die("mkstemp");
  size_t n = strlen(body);
  if (write(fd, body, n) != (ssize_t)n) die("write temp");
  close(fd);
  return strdup(path);
}

const char *rp_key_pem(void) { return iya_wsfed_keypair_key(g_rp); }
const char *rp_cert_pem(void) { return iya_wsfed_keypair_cert(g_rp); }
const char *idp_key_pem(void) { return iya_wsfed_keypair_key(g_idp); }
const char *idp_cert_pem(void) { return iya_wsfed_keypair_cert(g_idp); }
const char *default_meta_path(void) { return g_meta; }

static char *metadata_of(const char *fed, int no_sts, const char *key_in, const char *types) {
  if (!fed || !fed[0]) fed = "fed";
  if (!key_in) key_in = "sts";
  if (!types) types = "<fedtok/>";
  char *body = pem_body(idp_cert_pem());
  const char *key =
      "<md:KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>";
  char keyxml[8192];
  snprintf(keyxml, sizeof keyxml, key, body);
  char typexml[2048];
  if (strcmp(types, "<fedtok/>") == 0) {
    snprintf(typexml, sizeof typexml,
             "<%s:TokenType Uri=\"urn:oasis:names:tc:SAML:1.0:assertion\"/><%s:TokenType Uri=\"%s\"/>", fed, fed, SAML2);
  } else {
    snprintf(typexml, sizeof typexml, "%s", types);
  }
  const char *sts_key = strcmp(key_in, "idpsso") == 0 ? "" : keyxml;
  char sts[12000];
  sts[0] = 0;
  if (!no_sts) {
    snprintf(sts, sizeof sts,
             "<md:RoleDescriptor xsi:type=\"%s:SecurityTokenServiceType\" "
             "protocolSupportEnumeration=\"http://docs.oasis-open.org/wsfed/federation/200706\">%s<%s:TokenTypesOffered>%s</"
             "%s:TokenTypesOffered><%s:SecurityTokenServiceEndpoint><wsa:EndpointReference><wsa:Address>https://idp.test/"
             "sts</wsa:Address></wsa:EndpointReference></%s:SecurityTokenServiceEndpoint><%s:PassiveRequestorEndpoint><wsa:"
             "EndpointReference><wsa:Address>%s</wsa:Address></wsa:EndpointReference></%s:PassiveRequestorEndpoint></"
             "md:RoleDescriptor>",
             fed, sts_key, fed, typexml, fed, fed, fed, fed, PASSIVE, fed);
  }
  char *xml = malloc(strlen(sts) + strlen(keyxml) + 2048);
  sprintf(xml,
          "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/"
          "xmldsig#\" xmlns:%s=\"http://docs.oasis-open.org/wsfed/federation/200706\" "
          "xmlns:wsa=\"http://www.w3.org/2005/08/addressing\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
          "entityID=\"%s\">%s<md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">%s<md:"
          "SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" "
          "Location=\"https://idp.test/saml2/sso\"/></md:IDPSSODescriptor></md:EntityDescriptor>",
          fed, IDP_ENTITY, sts, keyxml);
  free(body);
  return xml;
}

void ensure_keys(void) {
  if (g_rp) return;
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  g_rp = iya_wsfed_generate_keys("rp", 30, 2048, &err);
  if (!g_rp) die(err.message);
  memset(&err, 0, sizeof err);
  g_idp = iya_wsfed_generate_keys("idp", 30, 2048, &err);
  if (!g_idp) die(err.message);
  char *xml = metadata_of("fed", 0, "sts", NULL);
  g_meta = write_temp(xml);
  free(xml);
  g_rp_key_path = write_temp(rp_key_pem());
  g_rp_cert_path = write_temp(rp_cert_pem());
  g_idp_cert_path = write_temp(idp_cert_pem());
}

char *cfg_json(const char *meta_path, int keys_mode, const char *extra) {
  ensure_keys();
  const char *meta = meta_path ? meta_path : g_meta;
  size_t n = 2048 + strlen(meta) + (extra ? strlen(extra) : 0);
  char *json = malloc(n);
  const char *comma = extra && extra[0] ? "," : "";
  const char *more = extra ? extra : "";
  if (keys_mode == 0) {
    snprintf(json, n, "{\"realm\":\"%s\",\"replyUrl\":\"%s\",\"idpMetadata\":\"%s\"%s%s}", REALM, REPLY, meta, comma, more);
  } else if (keys_mode == 2) {
    snprintf(json, n,
             "{\"realm\":\"%s\",\"replyUrl\":\"%s\",\"privateKey\":\"%s\",\"certificate\":\"%s\",\"idpMetadata\":\"%s\"%s%s}",
             REALM, REPLY, g_rp_key_path, g_idp_cert_path, meta, comma, more);
  } else if (keys_mode == 3) {
    snprintf(json, n, "{\"realm\":\"%s\",\"replyUrl\":\"%s\",\"privateKey\":\"%s\",\"idpMetadata\":\"%s\"%s%s}", REALM, REPLY,
             g_rp_key_path, meta, comma, more);
  } else {
    snprintf(json, n,
             "{\"realm\":\"%s\",\"replyUrl\":\"%s\",\"privateKey\":\"%s\",\"certificate\":\"%s\",\"idpMetadata\":\"%s\"%s%s}",
             REALM, REPLY, g_rp_key_path, g_rp_cert_path, meta, comma, more);
  }
  return json;
}

iya_wsfed_party *must_party(const char *json) {
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  iya_wsfed_party *party = iya_wsfed_party_create(json, "", &err);
  if (!party) die(err.message);
  return party;
}

void must_fail_party(const char *json, const char *code, const char *pat) {
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  iya_wsfed_party *party = iya_wsfed_party_create(json, "", &err);
  if (party) die("expected an error");
  expect_err(1, &err, code, pat);
}

char *assertion_xml(const AssertionOpt *opt, char *id_out, size_t id_len) {
  AssertionOpt none;
  memset(&none, 0, sizeof none);
  if (!opt) opt = &none;
  char *id = new_id();
  if (id_out && id_len) snprintf(id_out, id_len, "%s", id);
  char issued[40], not_before[40], not_after[40], authn[40];
  iso_at(issued, sizeof issued, 0);
  iso_at(not_before, sizeof not_before, -5000);
  int offset = opt->not_on_set ? opt->not_on_ms : 300000;
  iso_at(not_after, sizeof not_after, offset);
  iso_at(authn, sizeof authn, -1000);
  const char *recipient = REPLY;
  int omit_recipient = 0;
  if (opt->recipient_set) {
    recipient = opt->recipient ? opt->recipient : "";
    if (!recipient[0]) omit_recipient = 1;
  }
  char recipient_attr[512] = "";
  if (!omit_recipient) snprintf(recipient_attr, sizeof recipient_attr, " Recipient=\"%s\"", recipient);
  char irt[256] = "";
  if (opt->in_response_to && opt->in_response_to[0]) snprintf(irt, sizeof irt, " InResponseTo=\"%s\"", opt->in_response_to);
  char confirmation[1024];
  if (opt->bare) {
    snprintf(confirmation, sizeof confirmation, "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"/>");
  } else {
    snprintf(confirmation, sizeof confirmation,
             "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData%s "
             "NotOnOrAfter=\"%s\"%s/></saml:SubjectConfirmation>",
             recipient_attr, not_after, irt);
  }
  char expiry[80] = "";
  if (!opt->no_conditions_expiry) snprintf(expiry, sizeof expiry, " NotOnOrAfter=\"%s\"", not_after);
  const char *issuer = opt->issuer && opt->issuer[0] ? opt->issuer : IDP_ENTITY;
  const char *name = opt->name_id && opt->name_id[0] ? opt->name_id : "alice-1234";
  const char *session = opt->session && opt->session[0] ? opt->session : "_session1";
  const char *audience = opt->audience ? opt->audience : REALM;
  const char *extra = opt->extra ? opt->extra : "";
  const char *claims = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims";
  size_t cap = 4096 + strlen(extra) + strlen(id);
  char *xml = malloc(cap);
  snprintf(xml, cap,
           "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"%s\" Version=\"2.0\" "
           "IssueInstant=\"%s\"><saml:Issuer>%s</saml:Issuer><saml:Subject><saml:NameID "
           "Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">%s</saml:NameID>%s</saml:Subject><saml:"
           "Conditions NotBefore=\"%s\"%s><saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:"
           "AudienceRestriction></saml:Conditions><saml:AttributeStatement><saml:Attribute Name=\"%s/nameidentifier\"><saml:"
           "AttributeValue>urn:uuid:alice</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"%s/emailaddress\" "
           "FriendlyName=\"mail\"><saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute><saml:"
           "Attribute Name=\"http://schemas.microsoft.com/ws/2008/06/identity/claims/role\"><saml:AttributeValue>staff</"
           "saml:AttributeValue><saml:AttributeValue>admins</saml:AttributeValue></saml:Attribute>%s</saml:"
           "AttributeStatement><saml:AuthnStatement AuthnInstant=\"%s\" SessionIndex=\"%s\"><saml:AuthnContext><saml:"
           "AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:"
           "AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>",
           id, issued, issuer, name, confirmation, not_before, expiry, audience, claims, claims, extra, authn, session);
  free(id);
  return xml;
}

char *sign_xml(const char *xml, const char *id, const char *key_pem, const char *cert_pem) {
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  if (!key_pem) key_pem = idp_key_pem();
  if (!cert_pem) cert_pem = idp_cert_pem();
  char *signed_xml = iya_wsfed_sign(xml, id, key_pem, cert_pem, &err);
  if (!signed_xml) die(err.message);
  return signed_xml;
}

char *signed_assertion(const AssertionOpt *opt, char *id_out, size_t id_len) {
  char id[128];
  char *xml = assertion_xml(opt, id, sizeof id);
  if (id_out && id_len) snprintf(id_out, id_len, "%s", id);
  char *signed_xml = sign_xml(xml, id, NULL, NULL);
  free(xml);
  return signed_xml;
}

char *wresult_xml(const char *token, const char *trust, const char *applies, const char *token_type, int expires_ms,
                  int expires_set) {
  char *owned = NULL;
  if (!token) {
    owned = signed_assertion(NULL, NULL, 0);
    token = owned;
  }
  const char *ns = "http://schemas.xmlsoap.org/ws/2005/02/trust";
  int trust13 = trust && strcmp(trust, "1.3") == 0;
  if (trust13) ns = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
  const char *wsu = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
  if (!applies) applies = REALM;
  if (!token_type) token_type = SAML2;
  char created[40], expires[40];
  iso_at(created, sizeof created, 0);
  iso_at(expires, sizeof expires, expires_set ? expires_ms : 3600000);
  size_t cap = strlen(token) + 2048;
  char *rstr = malloc(cap);
  snprintf(rstr, cap,
           "<t:RequestSecurityTokenResponse xmlns:t=\"%s\"><t:Lifetime><wsu:Created xmlns:wsu=\"%s\">%s</wsu:Created><wsu:"
           "Expires xmlns:wsu=\"%s\">%s</wsu:Expires></t:Lifetime><wsp:AppliesTo "
           "xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\"><wsa:EndpointReference "
           "xmlns:wsa=\"http://www.w3.org/2005/08/addressing\"><wsa:Address>%s</wsa:Address></wsa:EndpointReference></"
           "wsp:AppliesTo><t:RequestedSecurityToken>%s</t:RequestedSecurityToken><t:TokenType>%s</t:TokenType><t:"
           "RequestType>%s/Issue</t:RequestType><t:KeyType>%s/Bearer</t:KeyType></t:RequestSecurityTokenResponse>",
           ns, wsu, created, wsu, expires, applies, token, token_type, ns, ns);
  free(owned);
  if (!trust13) return rstr;
  char *wrapped = malloc(strlen(rstr) + 256);
  sprintf(wrapped, "<t:RequestSecurityTokenResponseCollection xmlns:t=\"%s\">%s</t:RequestSecurityTokenResponseCollection>",
          ns, rstr);
  free(rstr);
  return wrapped;
}

static char *b64std(const unsigned char *data, size_t len) {
  size_t cap = ((len + 2) / 3) * 4 + 1;
  char *out = malloc(cap);
  int n = EVP_EncodeBlock((unsigned char *)out, data, (int)len);
  out[n] = 0;
  return out;
}

static EVP_PKEY *rp_public(void) {
  BIO *bio = BIO_new_mem_buf(rp_cert_pem(), -1);
  X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  BIO_free(bio);
  if (!cert) die("rp cert");
  EVP_PKEY *key = X509_get_pubkey(cert);
  X509_free(cert);
  if (!key) die("rp pubkey");
  return key;
}

static int rsa_wrap(EVP_PKEY *key, const EVP_MD *md, const unsigned char *in, size_t in_len, unsigned char *out,
                    size_t *out_len) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
  if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0) return 0;
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) return 0;
  if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0) return 0;
  if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0) return 0;
  if (EVP_PKEY_encrypt(ctx, NULL, out_len, in, in_len) <= 0) return 0;
  if (EVP_PKEY_encrypt(ctx, out, out_len, in, in_len) <= 0) return 0;
  EVP_PKEY_CTX_free(ctx);
  return 1;
}

char *encrypt_xml(const char *plain, const char *cipher, const char *transport, const char *wrapper) {
  if (!cipher || !cipher[0]) cipher = "aes-256-gcm";
  if (!transport || !transport[0]) transport = "mgf1p";
  if (!wrapper || !wrapper[0]) wrapper = "EncryptedAssertion";
  unsigned char key[32], iv[16], value[65536];
  size_t value_len = 0;
  const char *alg = NULL;
  int key_len = 32;
  if (strcmp(cipher, "aes-256-gcm") == 0) {
    key_len = 32;
    RAND_bytes(key, key_len);
    RAND_bytes(iv, 12);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outl = 0, fin = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    memcpy(value, iv, 12);
    EVP_EncryptUpdate(ctx, value + 12, &outl, (const unsigned char *)plain, (int)strlen(plain));
    EVP_EncryptFinal_ex(ctx, value + 12 + outl, &fin);
    unsigned char tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    memcpy(value + 12 + outl + fin, tag, 16);
    value_len = (size_t)(12 + outl + fin + 16);
    EVP_CIPHER_CTX_free(ctx);
    alg = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
  } else if (strcmp(cipher, "aes-128-cbc") == 0) {
    key_len = 16;
    RAND_bytes(key, key_len);
    RAND_bytes(iv, 16);
    size_t len = strlen(plain);
    int pad = 16 - (int)(len % 16);
    size_t padded = len + (size_t)pad;
    unsigned char *block = malloc(padded);
    memcpy(block, plain, len);
    memset(block + len, pad, (size_t)pad);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outl = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    memcpy(value, iv, 16);
    EVP_EncryptUpdate(ctx, value + 16, &outl, block, (int)padded);
    value_len = 16 + (size_t)outl;
    EVP_CIPHER_CTX_free(ctx);
    free(block);
    alg = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
  } else {
    die(cipher);
  }
  EVP_PKEY *pub = rp_public();
  unsigned char wrapped[512];
  size_t wrapped_len = sizeof wrapped;
  const EVP_MD *md = strcmp(transport, "oaep256") == 0 ? EVP_sha256() : EVP_sha1();
  if (!rsa_wrap(pub, md, key, (size_t)key_len, wrapped, &wrapped_len)) die("oaep");
  EVP_PKEY_free(pub);
  char *key_b64 = b64std(wrapped, wrapped_len);
  char *val_b64 = b64std(value, value_len);
  const char *key_method =
      "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"/>";
  char oaep[512];
  if (strcmp(transport, "oaep256") == 0) {
    snprintf(oaep, sizeof oaep,
             "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#rsa-oaep\"><ds:DigestMethod "
             "Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><xenc11:MGF "
             "xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\" "
             "Algorithm=\"http://www.w3.org/2009/xmlenc11#mgf1sha256\"/></xenc:EncryptionMethod>");
    key_method = oaep;
  }
  size_t cap = strlen(key_b64) + strlen(val_b64) + 1024;
  char *data = malloc(cap);
  snprintf(data, cap,
           "<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" "
           "Type=\"http://www.w3.org/2001/04/xmlenc#Element\"><xenc:EncryptionMethod Algorithm=\"%s\"/><ds:KeyInfo "
           "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><xenc:EncryptedKey>%s<xenc:CipherData><xenc:CipherValue>%s</"
           "xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>%s</"
           "xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>",
           alg, key_method, key_b64, val_b64);
  free(key_b64);
  free(val_b64);
  if (strcmp(wrapper, "none") == 0) return data;
  char *out = malloc(strlen(data) + 256);
  sprintf(out, "<saml:%s xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">%s</saml:%s>", wrapper, data, wrapper);
  free(data);
  return out;
}

static char *qesc(const char *s) {
  static const char *hex = "0123456789ABCDEF";
  size_t n = strlen(s);
  char *out = malloc(n * 3 + 1);
  size_t j = 0;
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') out[j++] = (char)c;
    else if (c == ' ') out[j++] = '+';
    else {
      out[j++] = '%';
      out[j++] = hex[c >> 4];
      out[j++] = hex[c & 15];
    }
  }
  out[j] = 0;
  return out;
}

char *query_unescape_dup(const char *in) {
  size_t n = strlen(in);
  char *out = malloc(n + 1);
  size_t j = 0;
  for (size_t i = 0; i < n; i++) {
    if (in[i] == '+') out[j++] = ' ';
    else if (in[i] == '%' && i + 2 < n) {
      char tmp[3] = {in[i + 1], in[i + 2], 0};
      out[j++] = (char)strtol(tmp, NULL, 16);
      i += 2;
    } else out[j++] = in[i];
  }
  out[j] = 0;
  return out;
}

char *form_body(const char *wresult, const char *wctx) {
  char *er = qesc(wresult);
  char *ew = wctx ? qesc(wctx) : NULL;
  char *body = malloc(strlen(er) + (ew ? strlen(ew) : 0) + 64);
  if (ew) sprintf(body, "wa=wsignin1.0&wresult=%s&wctx=%s", er, ew);
  else sprintf(body, "wa=wsignin1.0&wresult=%s", er);
  free(er);
  free(ew);
  return body;
}

iya_wsfed_login *submit(iya_wsfed_party *party, const char *result, const char *wctx, const char *const *ids, int n,
                        iya_wsfed_error *err) {
  char *body = form_body(result, wctx);
  iya_wsfed_login *login = iya_wsfed_handle_reply(party, "POST", "/wsfed", body, ids, n, err);
  free(body);
  return login;
}

void expect_submit(iya_wsfed_party *party, const char *result, const char *wctx, const char *const *ids, int n,
                   const char *code, const char *pat) {
  iya_wsfed_error err;
  memset(&err, 0, sizeof err);
  iya_wsfed_login *login = submit(party, result, wctx, ids, n, &err);
  if (login) die("expected an error");
  expect_err(1, &err, code, pat);
}

char *query_get(const char *url, const char *key) {
  const char *q = strchr(url, '?');
  if (!q) return NULL;
  q++;
  size_t klen = strlen(key);
  while (*q) {
    const char *amp = strchr(q, '&');
    size_t n = amp ? (size_t)(amp - q) : strlen(q);
    const char *eq = memchr(q, '=', n);
    if (eq && (size_t)(eq - q) == klen && memcmp(q, key, klen) == 0) {
      char *raw = strndup(eq + 1, n - (size_t)(eq + 1 - q));
      char *dec = query_unescape_dup(raw);
      free(raw);
      return dec;
    }
    if (!amp) break;
    q = amp + 1;
  }
  return NULL;
}

char *meta_custom(const char *fed, int no_sts, const char *key_in, const char *types) {
  ensure_keys();
  char *xml = metadata_of(fed, no_sts, key_in, types);
  char *path = write_temp(xml);
  free(xml);
  return path;
}
