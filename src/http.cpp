// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "detail.hpp"
#include "iya/wsfed.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <thread>

namespace iya::wsfed {
namespace {

constexpr int kMaxBytes = 2 * 1024 * 1024;
constexpr int kTimeoutMs = 15000;

struct Url {
  std::string scheme;
  std::string host;
  std::string port;
  std::string target;
};

Url parse_url(const std::string &url) {
  Url u;
  auto pos = url.find("://");
  if (pos == std::string::npos) return u;
  u.scheme = url.substr(0, pos);
  std::string rest = url.substr(pos + 3);
  auto slash = rest.find('/');
  std::string hostport = slash == std::string::npos ? rest : rest.substr(0, slash);
  u.target = slash == std::string::npos ? "/" : rest.substr(slash);
  if (!hostport.empty() && hostport[0] == '[') {
    auto end = hostport.find(']');
    u.host = end == std::string::npos ? hostport : hostport.substr(1, end - 1);
    if (end != std::string::npos && end + 1 < hostport.size() && hostport[end + 1] == ':') u.port = hostport.substr(end + 2);
  } else {
    auto colon = hostport.rfind(':');
    if (colon != std::string::npos && hostport.find(':') == colon) {
      u.host = hostport.substr(0, colon);
      u.port = hostport.substr(colon + 1);
    } else {
      u.host = hostport;
    }
  }
  if (u.port.empty()) u.port = u.scheme == "https" ? "443" : "80";
  return u;
}

void set_timeouts(int fd) {
  struct timeval tv;
  tv.tv_sec = kTimeoutMs / 1000;
  tv.tv_usec = (kTimeoutMs % 1000) * 1000;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}

int connect_host(const std::string &host, const std::string &port, const std::string &url, const std::string &code) {
  addrinfo hints{};
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  addrinfo *res = nullptr;
  if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0 || !res) {
    fail(code, url + ": name lookup failed");
  }
  int fd = -1;
  std::string why = "connection failed";
  for (addrinfo *ai = res; ai; ai = ai->ai_next) {
    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) continue;
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
    if (rc != 0 && errno != EINPROGRESS) {
      why = std::strerror(errno);
      close(fd);
      fd = -1;
      continue;
    }
    pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLOUT;
    int pr = poll(&pfd, 1, kTimeoutMs);
    if (pr == 0) {
      close(fd);
      freeaddrinfo(res);
      fail(code, url + " did not answer within 15 s");
    }
    if (pr < 0) {
      why = std::strerror(errno);
      close(fd);
      fd = -1;
      continue;
    }
    int err = 0;
    socklen_t len = sizeof err;
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
    if (err != 0) {
      why = err == ECONNREFUSED ? "connection refused" : std::strerror(err);
      close(fd);
      fd = -1;
      continue;
    }
    fcntl(fd, F_SETFL, flags);
    set_timeouts(fd);
    break;
  }
  freeaddrinfo(res);
  if (fd < 0) {
    std::string low = why;
    for (char &c : low) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (low.find("timeout") != std::string::npos || low.find("deadline") != std::string::npos) {
      fail(code, url + " did not answer within 15 s");
    }
    fail(code, url + ": " + why);
  }
  return fd;
}

bool write_all(int fd, SSL *ssl, const std::string &data, const std::string &url, const std::string &code) {
  size_t off = 0;
  while (off < data.size()) {
    int n = 0;
    if (ssl) n = SSL_write(ssl, data.data() + off, static_cast<int>(data.size() - off));
    else n = static_cast<int>(send(fd, data.data() + off, data.size() - off, 0));
    if (n <= 0) {
      int e = errno;
      if (e == EAGAIN || e == EWOULDBLOCK) fail(code, url + " did not answer within 15 s");
      fail(code, url + ": write failed");
    }
    off += static_cast<size_t>(n);
  }
  return true;
}

std::string read_some(int fd, SSL *ssl, bool &closed, bool &timed_out) {
  char buf[8192];
  int n = 0;
  closed = false;
  timed_out = false;
  if (ssl) {
    n = SSL_read(ssl, buf, sizeof buf);
    if (n == 0) closed = true;
    if (n < 0) {
      int err = SSL_get_error(ssl, n);
      if (err == SSL_ERROR_ZERO_RETURN) closed = true;
      else if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_SYSCALL) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) timed_out = true;
        else closed = n == 0;
      }
      n = 0;
    }
  } else {
    n = static_cast<int>(recv(fd, buf, sizeof buf, 0));
    if (n == 0) closed = true;
    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) timed_out = true;
      n = 0;
    }
  }
  if (n <= 0) return "";
  return std::string(buf, buf + n);
}

std::string reason_phrase(int status) {
  switch (status) {
    case 200: return "OK";
    case 201: return "Created";
    case 204: return "No Content";
    case 302: return "Found";
    case 303: return "See Other";
    case 400: return "Bad Request";
    case 404: return "Not Found";
    case 500: return "Internal Server Error";
    case 503: return "Service Unavailable";
    default: return "OK";
  }
}

struct ServerImpl {
  HttpServer::Handler handler;
  int listen_fd = -1;
  std::atomic<bool> stop{false};
  std::thread thread;
  std::mutex mu;
};

void serve_client(int fd, const HttpServer::Handler &handler) {
  set_timeouts(fd);
  std::string data;
  while (data.find("\r\n\r\n") == std::string::npos && data.size() < 1024 * 1024) {
    char buf[4096];
    int n = static_cast<int>(recv(fd, buf, sizeof buf, 0));
    if (n <= 0) {
      close(fd);
      return;
    }
    data.append(buf, buf + n);
  }
  auto hdr_end = data.find("\r\n\r\n");
  if (hdr_end == std::string::npos) {
    close(fd);
    return;
  }
  std::string head = data.substr(0, hdr_end);
  std::string body = data.substr(hdr_end + 4);
  std::string method, target;
  auto line_end = head.find("\r\n");
  std::string req = line_end == std::string::npos ? head : head.substr(0, line_end);
  auto sp1 = req.find(' ');
  auto sp2 = sp1 == std::string::npos ? std::string::npos : req.find(' ', sp1 + 1);
  if (sp1 != std::string::npos) {
    method = req.substr(0, sp1);
    target = sp2 == std::string::npos ? req.substr(sp1 + 1) : req.substr(sp1 + 1, sp2 - sp1 - 1);
  }
  size_t content_length = 0;
  std::vector<std::pair<std::string, std::string>> req_headers;
  std::string rest = line_end == std::string::npos ? "" : head.substr(line_end + 2);
  size_t i = 0;
  while (i < rest.size()) {
    auto nl = rest.find("\r\n", i);
    std::string line = rest.substr(i, nl == std::string::npos ? std::string::npos : nl - i);
    auto colon = line.find(':');
    if (colon != std::string::npos) {
      std::string name = line.substr(0, colon);
      for (char &c : name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      std::string value = trim_copy(line.substr(colon + 1));
      req_headers.emplace_back(name, value);
      if (name == "content-length") content_length = static_cast<size_t>(std::strtoul(value.c_str(), nullptr, 10));
    }
    if (nl == std::string::npos) break;
    i = nl + 2;
  }
  while (body.size() < content_length) {
    char buf[8192];
    int n = static_cast<int>(recv(fd, buf, sizeof buf, 0));
    if (n <= 0) break;
    body.append(buf, buf + n);
  }
  if (body.size() > content_length) body.resize(content_length);
  HttpResponse response;
  try {
    response = handler(method, target, req_headers, body);
  } catch (const std::exception &ex) {
    response.status = 500;
    response.body = ex.what();
    response.headers.push_back({"content-type", "text/plain"});
  }
  if (response.status == 0) response.status = 200;
  std::string out = "HTTP/1.1 " + itoa_i(response.status) + " " + reason_phrase(response.status) + "\r\n";
  bool has_len = false;
  bool has_conn = false;
  for (const auto &h : response.headers) {
    std::string name = h.first;
    std::string low = name;
    for (char &c : low) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (low == "content-length") has_len = true;
    if (low == "connection") has_conn = true;
    out += h.first + ": " + h.second + "\r\n";
  }
  if (!has_len) out += "Content-Length: " + itoa_i(static_cast<long long>(response.body.size())) + "\r\n";
  if (!has_conn) out += "Connection: close\r\n";
  out += "\r\n";
  out += response.body;
  size_t off = 0;
  while (off < out.size()) {
    int n = static_cast<int>(send(fd, out.data() + off, out.size() - off, 0));
    if (n <= 0) break;
    off += static_cast<size_t>(n);
  }
  close(fd);
}

}  // namespace

HttpResult http_send(const std::string &method_in, const std::string &url,
                     const std::vector<std::pair<std::string, std::string>> &headers, const std::string *body,
                     const TlsMaterial *tls, const std::string &code) {
  std::string method = method_in.empty() ? "GET" : method_in;
  if (url.compare(0, 8, "https://") != 0 && url.compare(0, 7, "http://") != 0) {
    fail(code, url + " is not an http(s) URL");
  }
  Url u = parse_url(url);
  if (u.host.empty()) fail(code, url + ": name lookup failed");
  int fd = connect_host(u.host, u.port, url, code);
  SSL_CTX *ctx = nullptr;
  SSL *ssl = nullptr;
  if (u.scheme == "https") {
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
      close(fd);
      fail(code, url + ": tls failed");
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (tls && !tls->ca.empty()) {
      BIO *bio = BIO_new_mem_buf(tls->ca.data(), static_cast<int>(tls->ca.size()));
      X509 *ca = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
      BIO_free(bio);
      if (!ca) {
        SSL_CTX_free(ctx);
        close(fd);
        fail(code, url + ": the CA certificate cannot be read");
      }
      X509_STORE *store = X509_STORE_new();
      X509_STORE_add_cert(store, ca);
      SSL_CTX_set_cert_store(ctx, store);
      X509_free(ca);
    } else {
      SSL_CTX_set_default_verify_paths(ctx);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    if (tls && !tls->cert.empty() && !tls->key.empty()) {
      BIO *cb = BIO_new_mem_buf(tls->cert.data(), static_cast<int>(tls->cert.size()));
      X509 *cert = PEM_read_bio_X509(cb, nullptr, nullptr, nullptr);
      BIO_free(cb);
      BIO *kb = BIO_new_mem_buf(tls->key.data(), static_cast<int>(tls->key.size()));
      EVP_PKEY *key = PEM_read_bio_PrivateKey(kb, nullptr, nullptr, nullptr);
      BIO_free(kb);
      if (!cert || !key || SSL_CTX_use_certificate(ctx, cert) != 1 || SSL_CTX_use_PrivateKey(ctx, key) != 1) {
        if (cert) X509_free(cert);
        if (key) EVP_PKEY_free(key);
        SSL_CTX_free(ctx);
        close(fd);
        fail(code, url + ": client certificate cannot be read");
      }
      X509_free(cert);
      EVP_PKEY_free(key);
    }
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, u.host.c_str());
    if (SSL_connect(ssl) != 1) {
      SSL_free(ssl);
      SSL_CTX_free(ctx);
      close(fd);
      fail(code, url + ": tls handshake failed");
    }
  }
  std::string req = method + " " + u.target + " HTTP/1.1\r\nHost: " + u.host;
  if (!((u.scheme == "https" && u.port == "443") || (u.scheme == "http" && u.port == "80"))) req += ":" + u.port;
  req += "\r\nConnection: close\r\n";
  bool has_len = false;
  for (const auto &h : headers) {
    std::string low = h.first;
    for (char &c : low) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (low == "content-length" || low == "host" || low == "connection") continue;
    req += h.first + ": " + h.second + "\r\n";
  }
  if (body) {
    req += "Content-Length: " + itoa_i(static_cast<long long>(body->size())) + "\r\n";
    has_len = true;
  }
  (void)has_len;
  req += "\r\n";
  if (body) req += *body;
  try {
    write_all(fd, ssl, req, url, code);
  } catch (...) {
    if (ssl) SSL_free(ssl);
    if (ctx) SSL_CTX_free(ctx);
    close(fd);
    throw;
  }
  std::string raw;
  bool closed = false;
  while (!closed && static_cast<int>(raw.size()) <= kMaxBytes + 1) {
    bool timed = false;
    std::string chunk = read_some(fd, ssl, closed, timed);
    if (timed && chunk.empty()) {
      if (ssl) SSL_free(ssl);
      if (ctx) SSL_CTX_free(ctx);
      close(fd);
      fail(code, url + " did not answer within 15 s");
    }
    raw += chunk;
    if (chunk.empty() && !closed && !timed) break;
  }
  if (ssl) SSL_free(ssl);
  if (ctx) SSL_CTX_free(ctx);
  close(fd);
  if (static_cast<int>(raw.size()) > kMaxBytes + 64 && raw.find("\r\n\r\n") == std::string::npos) {
    fail(code, url + " answered more than " + itoa_i(kMaxBytes) + " bytes");
  }
  auto hdr_end = raw.find("\r\n\r\n");
  if (hdr_end == std::string::npos) fail(code, url + ": empty response");
  std::string head = raw.substr(0, hdr_end);
  std::string payload = raw.substr(hdr_end + 4);
  auto line_end = head.find("\r\n");
  std::string status_line = line_end == std::string::npos ? head : head.substr(0, line_end);
  int status = 0;
  auto sp = status_line.find(' ');
  if (sp != std::string::npos) status = std::atoi(status_line.c_str() + sp + 1);
  HttpResult result;
  result.status = status;
  std::string rest = line_end == std::string::npos ? "" : head.substr(line_end + 2);
  size_t at = 0;
  bool chunked = false;
  long long declared = -1;
  while (at < rest.size()) {
    auto nl = rest.find("\r\n", at);
    std::string line = rest.substr(at, nl == std::string::npos ? std::string::npos : nl - at);
    auto colon = line.find(':');
    if (colon != std::string::npos) {
      std::string name = trim_copy(line.substr(0, colon));
      std::string value = trim_copy(line.substr(colon + 1));
      result.headers.emplace_back(name, value);
      std::string low = name;
      for (char &c : low) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      if (low == "content-type" && result.content_type.empty()) result.content_type = value;
      if (low == "content-length") declared = std::atoll(value.c_str());
      if (low == "transfer-encoding" && value.find("chunked") != std::string::npos) chunked = true;
    }
    if (nl == std::string::npos) break;
    at = nl + 2;
  }
  if (chunked) {
    std::string decoded;
    size_t p = 0;
    while (p < payload.size()) {
      auto nl = payload.find("\r\n", p);
      if (nl == std::string::npos) break;
      long long sz = std::strtoll(payload.substr(p, nl - p).c_str(), nullptr, 16);
      p = nl + 2;
      if (sz <= 0) break;
      if (p + static_cast<size_t>(sz) > payload.size()) break;
      decoded.append(payload, p, static_cast<size_t>(sz));
      p += static_cast<size_t>(sz);
      if (p + 2 <= payload.size() && payload[p] == '\r') p += 2;
    }
    payload.swap(decoded);
  } else if (declared >= 0 && static_cast<long long>(payload.size()) > declared) {
    payload.resize(static_cast<size_t>(declared));
  }
  if (static_cast<int>(payload.size()) > kMaxBytes) fail(code, url + " answered more than " + itoa_i(kMaxBytes) + " bytes");
  result.body = payload;
  return result;
}

HttpResponse HttpRequest(const std::string &method, const std::string &url, const std::string &content_type,
                         const std::string &body, const std::string &cookie) {
  std::vector<std::pair<std::string, std::string>> headers;
  if (!content_type.empty()) headers.emplace_back("content-type", content_type);
  if (!cookie.empty()) headers.emplace_back("cookie", cookie);
  headers.emplace_back("accept", "*/*");
  const std::string *payload = body.empty() && method != "POST" && method != "PUT" ? nullptr : &body;
  if (method == "GET" || method == "HEAD") payload = nullptr;
  HttpResult got = http_send(method, url, headers, payload, nullptr, "ssf");
  HttpResponse out;
  out.status = got.status;
  out.body = got.body;
  out.headers = got.headers;
  return out;
}

struct HttpServer::Impl {
  Handler handler;
  int listen_fd = -1;
  std::atomic<bool> stop{false};
  std::thread thread;
};

HttpServer::HttpServer(Handler handler, int *port_out) : impl_(std::make_unique<Impl>()) {
  impl_->handler = std::move(handler);
  impl_->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (impl_->listen_fd < 0) fail("ssf", "the test server could not listen");
  int yes = 1;
  setsockopt(impl_->listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  int requested = port_out && *port_out > 0 ? *port_out : 0;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(static_cast<uint16_t>(requested));
  if (bind(impl_->listen_fd, reinterpret_cast<sockaddr *>(&addr), sizeof addr) != 0) {
    close(impl_->listen_fd);
    fail("ssf", "the test server could not listen");
  }
  socklen_t len = sizeof addr;
  getsockname(impl_->listen_fd, reinterpret_cast<sockaddr *>(&addr), &len);
  if (port_out) *port_out = ntohs(addr.sin_port);
  if (listen(impl_->listen_fd, 64) != 0) fail("ssf", "the test server could not listen");
  int lfd = impl_->listen_fd;
  impl_->thread = std::thread([this, lfd] {
    while (!impl_->stop.load()) {
      pollfd pfd{};
      pfd.fd = lfd;
      pfd.events = POLLIN;
      int pr = poll(&pfd, 1, 200);
      if (pr <= 0) continue;
      int fd = accept(lfd, nullptr, nullptr);
      if (fd < 0) continue;
      serve_client(fd, impl_->handler);
    }
  });
}

HttpServer::~HttpServer() { Close(); }

void HttpServer::Close() {
  if (!impl_) return;
  impl_->stop.store(true);
  if (impl_->listen_fd >= 0) {
    shutdown(impl_->listen_fd, SHUT_RDWR);
    close(impl_->listen_fd);
    impl_->listen_fd = -1;
  }
  if (impl_->thread.joinable()) impl_->thread.join();
}

}  // namespace iya::wsfed
