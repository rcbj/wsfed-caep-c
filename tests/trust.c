// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// idpCa is iya-sts's listener CA trust chain. These tests serve HTTPS from a
// four-certificate chain shaped like iya-sts's (Root, Intermediate, TLS Issuing
// CA, leaf with DNS:localhost and IP:127.0.0.1), presented whole in the
// handshake and published at GET /tls/server-certificate.
//
// - The relying party fetches its metadata trusting the whole chain file. The
//   library used to read only the first PEM block (the leaf), so OpenSSL had no
//   self-signed anchor and refused the handshake.
// - The host name is verified: a leaf that chains to the trusted root but does
//   not name the host (DNS or IP SAN) is refused. The library used to set only
//   SNI, so any certificate under the root was accepted for any host.
// - scripts/trust_chain.py writes the whole chain to the file idpCa names, from
//   GET /tls/server-certificate and, when that is missing, from the handshake.

#include "harness.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static char *tprintf(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  va_list again;
  va_copy(again, ap);
  int n = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);
  char *out = malloc((size_t)n + 1);
  vsnprintf(out, (size_t)n + 1, fmt, again);
  va_end(again);
  return out;
}

static EVP_PKEY *rsa_key(void) {
  EVP_PKEY *key = EVP_RSA_gen(2048);
  if (!key) die("rsa");
  return key;
}

static void add_ext(X509 *cert, X509 *issuer, int nid, const char *value) {
  X509V3_CTX ctx;
  X509V3_set_ctx_nodb(&ctx);
  X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);
  X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
  if (!ext) dief("extension %d %s", nid, value);
  X509_add_ext(cert, ext, -1);
  X509_EXTENSION_free(ext);
}

// issuer NULL: self-signed. san NULL: a CA.
static X509 *make_cert(const char *cn, EVP_PKEY *key, X509 *issuer, EVP_PKEY *issuer_key, const char *san, long serial) {
  X509 *cert = X509_new();
  X509_set_version(cert, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);
  X509_gmtime_adj(X509_getm_notBefore(cert), -3600);
  X509_gmtime_adj(X509_getm_notAfter(cert), 86400);
  X509_set_pubkey(cert, key);
  X509_NAME *name = X509_get_subject_name(cert);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0);
  X509 *signer = issuer ? issuer : cert;
  X509_set_issuer_name(cert, X509_get_subject_name(signer));
  if (san) {
    add_ext(cert, signer, NID_basic_constraints, "critical,CA:FALSE");
    add_ext(cert, signer, NID_key_usage, "critical,digitalSignature,keyEncipherment");
    add_ext(cert, signer, NID_ext_key_usage, "serverAuth");
    add_ext(cert, signer, NID_subject_alt_name, san);
  } else {
    add_ext(cert, signer, NID_basic_constraints, "critical,CA:TRUE");
    add_ext(cert, signer, NID_key_usage, "critical,keyCertSign,cRLSign");
  }
  add_ext(cert, signer, NID_subject_key_identifier, "hash");
  if (!X509_sign(cert, issuer_key ? issuer_key : key, EVP_sha256())) die("sign");
  return cert;
}

static char *pem_of(X509 *cert) {
  BIO *bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(bio, cert);
  char *data = NULL;
  long n = BIO_get_mem_data(bio, &data);
  char *out = malloc((size_t)n + 1);
  memcpy(out, data, (size_t)n);
  out[n] = 0;
  BIO_free(bio);
  return out;
}

typedef struct Chain {
  EVP_PKEY *root_key, *mid_key, *issuing_key, *leaf_key;
  X509 *root, *mid, *issuing, *leaf;
  char *pem;  // leaf, TLS Issuing CA, Intermediate, Root: what iya-sts publishes
  char *root_pem;
  char *leaf_pem;
} Chain;

static Chain *make_chain(const char *san) {
  Chain *c = calloc(1, sizeof *c);
  c->root_key = rsa_key();
  c->mid_key = rsa_key();
  c->issuing_key = rsa_key();
  c->leaf_key = rsa_key();
  c->root = make_cert("sts Root CA", c->root_key, NULL, NULL, NULL, 1);
  c->mid = make_cert("sts Intermediate CA", c->mid_key, c->root, c->root_key, NULL, 2);
  c->issuing = make_cert("sts TLS Issuing CA", c->issuing_key, c->mid, c->mid_key, NULL, 3);
  c->leaf = make_cert("sts", c->leaf_key, c->issuing, c->issuing_key, san, 4);
  c->leaf_pem = pem_of(c->leaf);
  char *issuing = pem_of(c->issuing);
  char *mid = pem_of(c->mid);
  c->root_pem = pem_of(c->root);
  c->pem = tprintf("%s%s%s%s", c->leaf_pem, issuing, mid, c->root_pem);
  free(issuing);
  free(mid);
  return c;
}

typedef struct TlsServer {
  SSL_CTX *ctx;
  int fd;
  int port;
  int publish;  // answer GET /tls/server-certificate
  char *chain_pem;
  char *metadata;
  volatile int stop;
  pthread_t thread;
} TlsServer;

static void serve_one(TlsServer *s, int fd) {
  struct timeval tv = {5, 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
  SSL *ssl = SSL_new(s->ctx);
  SSL_set_fd(ssl, fd);
  if (SSL_accept(ssl) == 1) {
    char buf[8192];
    int got = 0;
    while (got < (int)sizeof buf - 1) {
      int n = SSL_read(ssl, buf + got, (int)sizeof buf - 1 - got);
      if (n <= 0) break;
      got += n;
      buf[got] = 0;
      if (strstr(buf, "\r\n\r\n")) break;
    }
    buf[got] = 0;
    int status = 404;
    const char *type = "text/plain";
    const char *body = "not found";
    if (strncmp(buf, "GET /tls/server-certificate ", 28) == 0 && s->publish) {
      status = 200;
      body = s->chain_pem;
    } else if (strncmp(buf, "GET /metadata ", 14) == 0) {
      status = 200;
      type = "application/samlmetadata+xml";
      body = s->metadata;
    }
    char *out = tprintf("HTTP/1.1 %d X\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s", status, type,
                        strlen(body), body);
    SSL_write(ssl, out, (int)strlen(out));
    free(out);
    SSL_shutdown(ssl);
  }
  SSL_free(ssl);
  ERR_clear_error();
  close(fd);
}

static void *serve_loop(void *arg) {
  TlsServer *s = arg;
  while (!s->stop) {
    struct pollfd pfd = {s->fd, POLLIN, 0};
    if (poll(&pfd, 1, 100) <= 0) continue;
    int fd = accept(s->fd, NULL, NULL);
    if (fd < 0) continue;
    serve_one(s, fd);
  }
  return NULL;
}

static TlsServer *tls_serve(Chain *c, int publish, const char *metadata) {
  TlsServer *s = calloc(1, sizeof *s);
  s->ctx = SSL_CTX_new(TLS_server_method());
  if (SSL_CTX_use_certificate(s->ctx, c->leaf) != 1 || SSL_CTX_use_PrivateKey(s->ctx, c->leaf_key) != 1) die("server cert");
  // The whole chain in the handshake, root included, as iya-sts presents it.
  SSL_CTX_add1_chain_cert(s->ctx, c->issuing);
  SSL_CTX_add1_chain_cert(s->ctx, c->mid);
  SSL_CTX_add1_chain_cert(s->ctx, c->root);
  s->publish = publish;
  s->chain_pem = c->pem;
  s->metadata = strdup(metadata ? metadata : "");
  s->fd = socket(AF_INET, SOCK_STREAM, 0);
  int yes = 1;
  setsockopt(s->fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(s->fd, (struct sockaddr *)&addr, sizeof addr) != 0 || listen(s->fd, 16) != 0) die("listen");
  socklen_t len = sizeof addr;
  getsockname(s->fd, (struct sockaddr *)&addr, &len);
  s->port = ntohs(addr.sin_port);
  pthread_create(&s->thread, NULL, serve_loop, s);
  return s;
}

static void tls_close(TlsServer *s) {
  s->stop = 1;
  pthread_join(s->thread, NULL);
  close(s->fd);
  SSL_CTX_free(s->ctx);
  free(s->metadata);
  free(s);
}

static char *read_all(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) dief("cannot read %s", path);
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *out = malloc((size_t)n + 1);
  size_t got = fread(out, 1, (size_t)n, f);
  out[got] = 0;
  fclose(f);
  return out;
}

static char *idp_metadata(void) {
  char *json = cfg_json(NULL, 0, NULL);  // makes the keys and the metadata file
  free(json);
  return read_all(default_meta_path());
}

// Create a party fetching https://<host>:<port>/metadata with idpCa = ca_path. Returns 1 on success.
static int party_over_tls(const char *host, int port, const char *ca_path, iya_wsfed_error *err) {
  char *url = tprintf("https://%s:%d/metadata", host, port);
  char *extra = tprintf("\"idpCa\":\"%s\"", ca_path);
  char *json = cfg_json(url, 0, extra);
  memset(err, 0, sizeof *err);
  iya_wsfed_party *party = iya_wsfed_party_create(json, "", err);
  free(url);
  free(extra);
  free(json);
  if (!party) return 0;
  iya_wsfed_party_free(party);
  return 1;
}

void TestIdpCaChainIsTheTrustStore(void) {
  char *metadata = idp_metadata();
  Chain *c = make_chain("DNS:localhost,DNS:sts,IP:127.0.0.1");
  TlsServer *s = tls_serve(c, 1, metadata);
  char *chain_path = write_temp(c->pem);
  char *root_path = write_temp(c->root_pem);
  char *leaf_path = write_temp(c->leaf_pem);
  iya_wsfed_error err;
  // The whole chain file: every block is an anchor, so the path ends at the Root.
  if (!party_over_tls("localhost", s->port, chain_path, &err)) dief("chain by name: %s", err.message);
  if (!party_over_tls("127.0.0.1", s->port, chain_path, &err)) dief("chain by IP SAN: %s", err.message);
  // The root alone is enough too.
  if (!party_over_tls("localhost", s->port, root_path, &err)) dief("root: %s", err.message);
  // The leaf alone is not a self-signed anchor: refused.
  if (party_over_tls("localhost", s->port, leaf_path, &err)) die("the leaf alone was accepted as a trust anchor");
  if (!msg_has(err.message, "tls handshake failed")) die(err.message);
  // A chain to some other root is refused.
  Chain *other = make_chain("DNS:localhost,IP:127.0.0.1");
  char *other_path = write_temp(other->pem);
  if (party_over_tls("localhost", s->port, other_path, &err)) die("another root's chain was accepted");
  tls_close(s);
  unlink(chain_path);
  unlink(root_path);
  unlink(leaf_path);
  unlink(other_path);
  free(metadata);
}

void TestHostNameIsChecked(void) {
  char *metadata = idp_metadata();
  // The Root alone as the trust file, so this checks the name and nothing else.
  // The right chain, the wrong name: the leaf names only sts.example.com.
  Chain *c = make_chain("DNS:sts.example.com");
  TlsServer *s = tls_serve(c, 1, metadata);
  char *chain_path = write_temp(c->root_pem);
  iya_wsfed_error err;
  if (party_over_tls("localhost", s->port, chain_path, &err)) die("localhost was accepted on a certificate for sts.example.com");
  if (!msg_has(err.message, "tls handshake failed")) die(err.message);
  if (party_over_tls("127.0.0.1", s->port, chain_path, &err)) die("127.0.0.1 was accepted without an IP SAN");
  if (!msg_has(err.message, "tls handshake failed")) die(err.message);
  tls_close(s);
  // A DNS SAN of 127.0.0.1 is not an IP SAN; an IP literal is matched against IP SANs only.
  Chain *dns_ip = make_chain("DNS:127.0.0.1,DNS:localhost");
  s = tls_serve(dns_ip, 1, metadata);
  char *dns_ip_path = write_temp(dns_ip->root_pem);
  if (party_over_tls("127.0.0.1", s->port, dns_ip_path, &err)) die("127.0.0.1 was accepted on a DNS SAN");
  if (!party_over_tls("localhost", s->port, dns_ip_path, &err)) dief("localhost: %s", err.message);
  tls_close(s);
  // The right name and the IP SAN are accepted.
  Chain *good = make_chain("DNS:localhost,DNS:sts,DNS:sts-mock,DNS:sts.example.com,IP:127.0.0.1");
  s = tls_serve(good, 1, metadata);
  char *good_path = write_temp(good->root_pem);
  if (!party_over_tls("localhost", s->port, good_path, &err)) dief("localhost: %s", err.message);
  if (!party_over_tls("127.0.0.1", s->port, good_path, &err)) dief("127.0.0.1: %s", err.message);
  tls_close(s);
  unlink(chain_path);
  unlink(dns_ip_path);
  unlink(good_path);
  free(metadata);
}

static void run_python(const char *script, const char *args) {
  char cwd[1024];
  if (!getcwd(cwd, sizeof cwd)) die("cwd");
  char *script_path = write_temp(script);
  char *out_path = write_temp("");
  char *cmd = tprintf("python3 %s %s/scripts %s > %s 2>&1", script_path, cwd, args, out_path);
  int rc = system(cmd);
  char *out = read_all(out_path);
  if (rc != 0) dief("python %d: %s", rc, out);
  free(out);
  unlink(script_path);
  unlink(out_path);
  free(script_path);
  free(out_path);
  free(cmd);
}

void TestConfigureWritesTheWholeChain(void) {
  char *metadata = idp_metadata();
  Chain *c = make_chain("DNS:localhost,DNS:sts,IP:127.0.0.1");
  TlsServer *published = tls_serve(c, 1, metadata);
  TlsServer *handshake = tls_serve(c, 0, metadata);
  char dir[] = "/tmp/wsfedtrustXXXXXX";
  if (!mkdtemp(dir)) die("mkdtemp");
  char *config = tprintf("%s/wsfed.json", dir);
  FILE *f = fopen(config, "w");
  fputs("{\"realm\":\"http://localhost:3000/\",\"replyUrl\":\"http://localhost:3000/wsfed\",\"idpCa\":\"file:generated/idp-ca.pem\"}\n",
        f);
  fclose(f);
  char *want = write_temp(c->pem);
  // Published chain, through the CLI the install script shares; then the handshake fallback.
  char *args = tprintf("%s %s https://127.0.0.1:%d https://localhost:%d", config, want, published->port, handshake->port);
  run_python(
      "import sys, os, subprocess\n"
      "sys.path.insert(0, sys.argv[1])\n"
      "import trust_chain\n"
      "config, want, published, handshake = sys.argv[2:]\n"
      "want = open(want).read()\n"
      "dest = os.path.join(os.path.dirname(config), 'generated', 'idp-ca.pem')\n"
      "assert trust_chain.trust_path('file:generated/idp-ca.pem', os.path.dirname(config)) == dest\n"
      "out = subprocess.run([sys.executable, os.path.join(sys.argv[1], 'trust_chain.py'), '--config', config, '--idp', published],\n"
      "                     capture_output=True, text=True, check=True).stdout\n"
      "assert 'sts Root CA' in out and 'sha256 ' in out and dest in out, out\n"
      "assert open(dest).read() == want, 'the published chain was not written whole'\n"
      "assert open(dest).read().count('BEGIN CERTIFICATE') == 4\n"
      "os.remove(dest)\n"
      "saved = trust_chain.save_trust_chain(handshake, dest)\n"
      "assert saved['count'] == 4, saved['count']\n"
      "assert open(dest).read() == want, 'the handshake chain was not written whole'\n"
      "assert 'CN=sts Root CA' in saved['anchor'].subject.rfc4514_string()\n"
      "print('ok')\n",
      args);
  // The file the script wrote is what the library trusts.
  char *dest = tprintf("%s/generated/idp-ca.pem", dir);
  iya_wsfed_error err;
  if (!party_over_tls("localhost", published->port, dest, &err)) dief("the saved chain: %s", err.message);
  tls_close(published);
  tls_close(handshake);
  unlink(dest);
  unlink(want);
  unlink(config);
  char *gen = tprintf("%s/generated", dir);
  rmdir(gen);
  rmdir(dir);
  free(gen);
  free(dest);
  free(args);
  free(config);
  free(metadata);
}
