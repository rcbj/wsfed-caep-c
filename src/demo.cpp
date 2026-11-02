// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "b64.hpp"
#include "detail.hpp"
#include "iya/wsfed.hpp"

#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <map>
#include <mutex>
#include <thread>

namespace iya::wsfed {
namespace {

const char *kStyles =
    "body { font-family: sans-serif; margin: 2rem; } a.button, button { padding: 0.4rem 0.8rem; }";
const char *kGifB64 = "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";

std::string gif_bytes() {
  auto raw = b64_decode(kGifB64, false);
  return std::string(reinterpret_cast<char *>(raw.data()), raw.size());
}

std::string hmac_sign(const std::string &secret, const std::string &value) {
  unsigned char mac[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()),
       reinterpret_cast<const unsigned char *>(value.data()), value.size(), mac, &len);
  return value + "." + b64url_encode(mac, len);
}

bool hmac_equal(const std::string &a, const std::string &b) {
  if (a.size() != b.size()) return false;
  return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

std::string hmac_unsign(const std::string &secret, const std::string &signed_value) {
  auto dot = signed_value.rfind('.');
  if (signed_value.empty() || dot == std::string::npos) return "";
  std::string value = signed_value.substr(0, dot);
  std::string again = hmac_sign(secret, value);
  if (hmac_equal(again, signed_value)) return value;
  return "";
}

std::map<std::string, std::string> cookie_jar(const std::string &header) {
  std::map<std::string, std::string> out;
  size_t i = 0;
  while (i < header.size()) {
    auto semi = header.find(';', i);
    std::string part = header.substr(i, semi == std::string::npos ? std::string::npos : semi - i);
    auto eq = part.find('=');
    if (eq != std::string::npos) {
      std::string name = trim_copy(part.substr(0, eq));
      std::string value = part.substr(eq + 1);
      if (!name.empty() && !value.empty() && !out.count(name)) out[name] = value;
    }
    if (semi == std::string::npos) break;
    i = semi + 1;
  }
  return out;
}

std::string html_escape(const std::string &value) {
  std::string out;
  for (char c : value) {
    if (c == '&') out += "&amp;";
    else if (c == '<') out += "&lt;";
    else if (c == '>') out += "&gt;";
    else if (c == '"') out += "&quot;";
    else out.push_back(c);
  }
  return out;
}

std::string header_get(const std::vector<std::pair<std::string, std::string>> &headers, const std::string &name) {
  for (const auto &h : headers) {
    if (h.first == name) return h.second;
  }
  return "";
}

std::string path_of(const std::string &target) {
  auto q = target.find('?');
  std::string path = q == std::string::npos ? target : target.substr(0, q);
  if (path.empty()) return "/";
  return path;
}

std::string token_url(size_t n) {
  std::vector<unsigned char> buf(n);
  if (RAND_bytes(buf.data(), static_cast<int>(buf.size())) != 1) fail("config", "a session id could not be chosen");
  return b64url_encode(buf.data(), buf.size());
}

bool loopback_host(const std::string &host) { return host == "localhost" || host == "127.0.0.1" || host == "::1"; }

struct UrlParts {
  std::string scheme;
  std::string host;
  std::string port;
  std::string path;
  std::string query;
};

UrlParts split_url(const std::string &raw) {
  UrlParts u;
  auto scheme = raw.find("://");
  if (scheme == std::string::npos) return u;
  u.scheme = raw.substr(0, scheme);
  size_t host_at = scheme + 3;
  auto path_at = raw.find('/', host_at);
  std::string hostport = path_at == std::string::npos ? raw.substr(host_at) : raw.substr(host_at, path_at - host_at);
  std::string rest = path_at == std::string::npos ? "" : raw.substr(path_at);
  auto q = rest.find('?');
  if (q == std::string::npos) {
    u.path = rest;
  } else {
    u.path = rest.substr(0, q);
    u.query = rest.substr(q + 1);
  }
  if (!hostport.empty() && hostport[0] == '[') {
    auto end = hostport.find(']');
    if (end != std::string::npos) {
      u.host = hostport.substr(1, end - 1);
      if (end + 1 < hostport.size() && hostport[end + 1] == ':') u.port = hostport.substr(end + 2);
    }
  } else {
    auto colon = hostport.rfind(':');
    if (colon != std::string::npos) {
      u.host = hostport.substr(0, colon);
      u.port = hostport.substr(colon + 1);
    } else {
      u.host = hostport;
    }
  }
  return u;
}

std::string join_url(const UrlParts &u) {
  std::string host = u.host.find(':') != std::string::npos ? "[" + u.host + "]" : u.host;
  std::string out = u.scheme + "://" + host;
  if (!u.port.empty()) out += ":" + u.port;
  out += u.path;
  if (!u.query.empty()) out += "?" + u.query;
  return out;
}

std::string on_port(const std::string &raw, int port) {
  UrlParts u = split_url(raw);
  if (u.host.empty() || !loopback_host(u.host)) return raw;
  u.port = itoa_i(port);
  return join_url(u);
}

std::string move_origin(const std::string &value, const std::string &public_url) {
  std::string base_raw = public_url;
  if (base_raw.empty() || base_raw.back() != '/') base_raw.push_back('/');
  UrlParts base = split_url(base_raw);
  UrlParts next = split_url(value);
  if (base.scheme.empty() || next.scheme.empty()) return value;
  next.scheme = base.scheme;
  next.host = base.host;
  next.port = base.port;
  return join_url(next);
}

std::string material_of(const std::string &value, const std::string &base) {
  if (value.find("-----BEGIN ") != std::string::npos) return value;
  std::string path = value;
  if (path.compare(0, 5, "file:") == 0) path = path.substr(5);
  if (path.compare(0, 4, "env:") == 0) {
    const char *env = std::getenv(path.c_str() + 4);
    return env ? env : "";
  }
  if (path.empty() || path[0] != '/') path = join_path(base, path);
  return read_file(path);
}

std::string attr_first(const RelyingParty::LoginResult &who, const std::string &name) {
  for (const auto &attr : who.attributes) {
    if (attr.name == name && !attr.values.empty()) return attr.values[0];
  }
  return "";
}

const char *kMailNames[] = {
    "urn:oid:0.9.2342.19200300.100.1.3",
    "mail",
    "email",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
};

}  // namespace

struct DemoApp::Impl {
  RelyingParty party;
  std::unique_ptr<SignalsReceiver> receiver;
  std::unique_ptr<HttpServer> server;
  std::mutex sessions_mu;
  std::map<std::string, RelyingParty::LoginResult> sessions;
  std::string secret;
  std::string reply_path = "/wsfed";
  std::string secure;
  std::string gif;
  int bound_port = 0;

  explicit Impl(RelyingParty party_in) : party(std::move(party_in)), gif(gif_bytes()) {
    unsigned char raw[32];
    if (RAND_bytes(raw, sizeof raw) != 1) fail("config", "a session secret could not be chosen");
    secret.assign(reinterpret_cast<char *>(raw), sizeof raw);
    UrlParts reply = split_url(party.config().reply_url);
    if (!reply.path.empty()) reply_path = reply.path;
    if (reply.scheme == "https") secure = "; Secure";
  }

  void drop(const std::string &id) {
    std::lock_guard<std::mutex> lock(sessions_mu);
    sessions.erase(id);
  }

  std::string pending(const std::string &value, int age) const {
    std::string mark = secure.empty() ? "; Secure" : secure;
    return "wsfed_pending=" + value + "; Path=" + reply_path + "; HttpOnly; SameSite=None" + mark + "; Max-Age=" + itoa_i(age);
  }
};

DemoApp::DemoApp(RelyingParty party) : impl_(std::make_unique<Impl>(std::move(party))) {}

DemoApp::~DemoApp() {
  if (!impl_) return;
  if (impl_->receiver) impl_->receiver->Stop();
  if (impl_->server) impl_->server->Close();
}

DemoApp::DemoApp(DemoApp &&) noexcept = default;
DemoApp &DemoApp::operator=(DemoApp &&) noexcept = default;

void DemoApp::StartSignals(const std::string &transmitter, int poll_interval_ms, const std::string &ca_pem,
                           const std::string &cert_pem, const std::string &key_pem) {
  Impl *self = impl_.get();
  SignalsReceiver::Options options;
  options.poll_interval_ms = poll_interval_ms;
  options.tls_ca = ca_pem;
  options.tls_cert = cert_pem;
  options.tls_key = key_pem;
  auto receiver = std::make_unique<SignalsReceiver>(
      transmitter,
      [self](const std::vector<std::string> &ids, const SignalEvent &) {
        for (const auto &id : ids) self->drop(id);
      },
      options);
  receiver->Start();
  impl_->receiver = std::move(receiver);
}

DemoApp::Handled DemoApp::Handle(const std::string &method_in, const std::string &target,
                                 const std::vector<std::pair<std::string, std::string>> &headers, const std::string &body) {
  std::string method = method_in;
  for (char &c : method) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  std::string path = path_of(target);
  auto jar = cookie_jar(header_get(headers, "cookie"));
  std::string sid = hmac_unsign(impl_->secret, jar.count("sid") ? jar["sid"] : "");
  Handled out;
  if (path == "/healthz" && method == "GET") {
    out.headers.push_back({"content-type", "text/plain"});
    out.body = "ok";
    return out;
  }
  if (path == "/login" && method == "GET") {
    RelyingParty::LoginOptions opts;
    opts.relay_state = std::string("/");
    auto request = impl_->party.Login(opts);
    out.status = 302;
    out.headers.push_back({"location", request.url});
    out.headers.push_back({"set-cookie", impl_->pending(hmac_sign(impl_->secret, request.id), 600)});
    return out;
  }
  if (path == impl_->reply_path && impl_->party.IsSignOutCleanup(method, target, body)) {
    if (!sid.empty()) {
      impl_->drop(sid);
      if (impl_->receiver) impl_->receiver->Untrack(sid);
    }
    out.headers.push_back({"content-type", "image/gif"});
    out.headers.push_back({"set-cookie", "sid=; Path=/; HttpOnly; Max-Age=0" + impl_->secure});
    out.body = impl_->gif;
    return out;
  }
  if (path == impl_->reply_path && method == "POST") {
    try {
    std::string pending = hmac_unsign(impl_->secret, jar.count("wsfed_pending") ? jar["wsfed_pending"] : "");
    std::vector<std::string> ids;
    if (!pending.empty()) ids.push_back(pending);
    RelyingParty::LoginResult who = impl_->party.HandleReply("POST", target, body, ids);
    std::string session_id = token_url(24);
    {
      std::lock_guard<std::mutex> lock(impl_->sessions_mu);
      impl_->sessions[session_id] = who;
    }
    if (impl_->receiver) {
      std::string person = attr_first(who, kDefaultSubjectAttribute);
      std::string email;
      for (const char *name : kMailNames) {
        email = attr_first(who, name);
        if (!email.empty()) break;
      }
      impl_->receiver->Track(session_id, who.name_id, who.name_id_format ? *who.name_id_format : "",
                             who.session_index ? *who.session_index : "", person, email);
    }
    std::string next = "/";
    if (who.relay_state && who.relay_state->compare(0, 1, "/") == 0 && who.relay_state->compare(0, 2, "//") != 0) {
      next = *who.relay_state;
    }
    out.status = 303;
    out.headers.push_back({"location", next});
    out.headers.push_back({"set-cookie", impl_->pending("", 0)});
    out.headers.push_back({"set-cookie", "sid=" + hmac_sign(impl_->secret, session_id) + "; Path=/; HttpOnly; SameSite=Lax" +
                                              impl_->secure});
    return out;
    } catch (const std::exception &) {
      Handled failed;
      failed.status = 400;
      failed.headers.push_back({"content-type", "text/plain"});
      failed.body = "Sign-in failed.";
      return failed;
    }
  }
  if (path == "/logout" && method == "POST") {
    if (!sid.empty()) {
      impl_->drop(sid);
      if (impl_->receiver) impl_->receiver->Untrack(sid);
    }
    UrlParts reply = split_url(impl_->party.config().reply_url);
    std::string origin = "/";
    if (!reply.scheme.empty()) {
      UrlParts home = reply;
      home.path = "/";
      home.query.clear();
      origin = join_url(home);
    }
    std::string location = impl_->party.Logout(origin);
    out.status = 303;
    out.headers.push_back({"location", location});
    out.headers.push_back({"set-cookie", "sid=; Path=/; HttpOnly; Max-Age=0" + impl_->secure});
    return out;
  }
  if (path == "/FederationMetadata/2007-06/FederationMetadata.xml" && method == "GET") {
    out.headers.push_back({"content-type", "application/samlmetadata+xml"});
    out.body = impl_->party.Metadata();
    return out;
  }
  if (path == "/" && method == "GET") {
    const RelyingParty::LoginResult *who = nullptr;
    std::lock_guard<std::mutex> lock(impl_->sessions_mu);
    if (!sid.empty() && impl_->sessions.count(sid)) who = &impl_->sessions[sid];
    std::string page = "<p><a href=\"/login\">Sign in with WS-Federation</a></p>";
    if (who) {
      page = "<p>Signed in as <strong>" + html_escape(who->name_id) + "</strong> by " + html_escape(who->issuer) +
             ".</p><form method=\"post\" action=\"/logout\"><button>Sign out</button></form>";
    }
    out.headers.push_back({"content-type", "text/html; charset=utf-8"});
    out.body = "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>WS-Federation</title><link rel=\"stylesheet\" href=\"/styles.css\"></head><body><main>" +
               page + "</main></body></html>";
    return out;
  }
  if (path == "/styles.css" && method == "GET") {
    out.headers.push_back({"content-type", "text/css"});
    out.body = kStyles;
    if (out.body.empty()) out.body = "body{font-family:sans-serif}\n";
    return out;
  }
  out.status = 404;
  out.headers.push_back({"content-type", "text/plain"});
  out.body = "Not found";
  return out;
}

void DemoApp::Listen(int port) {
  int bound = port;
  impl_->server = std::make_unique<HttpServer>(
      [this](const std::string &method, const std::string &target,
             const std::vector<std::pair<std::string, std::string>> &headers, const std::string &body) {
        Handled handled = Handle(method, target, headers, body);
        HttpResponse response;
        response.status = handled.status;
        response.headers = std::move(handled.headers);
        response.body = std::move(handled.body);
        return response;
      },
      &bound);
  impl_->bound_port = bound;
}

int DemoApp::ListenEphemeral() {
  Listen(0);
  return impl_->bound_port;
}

void DemoApp::Close() {
  if (impl_ && impl_->server) impl_->server->Close();
}

namespace {

std::string public_url_of(int argc, char **argv, bool &given, std::string &error) {
  const char *env = std::getenv("PUBLIC_URL");
  given = env && *env;
  std::string public_url = env ? env : "";
  while (!public_url.empty() && public_url.back() == '/') public_url.pop_back();
  for (int i = 0; i < argc; i++) {
    if (std::strcmp(argv[i], "--public-url") == 0) {
      if (i + 1 >= argc || !argv[i + 1] || !argv[i + 1][0]) {
        error = "--public-url is empty";
        return "";
      }
      public_url = argv[i + 1];
      while (!public_url.empty() && public_url.back() == '/') public_url.pop_back();
      given = true;
    }
  }
  return public_url;
}

std::string config_path_of(int argc, char **argv) {
  const char *env = std::getenv("WSFED_CONFIG");
  std::string configured = env ? env : "";
  for (int i = 0; i < argc; i++) {
    if (std::strcmp(argv[i], "--config") == 0 && i + 1 < argc) configured = argv[i + 1];
  }
  if (configured.empty()) return "demo/wsfed.json";
  return configured;
}

int port_of(int argc, char **argv) {
  int port = 3000;
  const char *env = std::getenv("PORT");
  if (env && *env) port = std::atoi(env);
  for (int i = 0; i < argc; i++) {
    if (std::strcmp(argv[i], "--port") == 0 && i + 1 < argc) port = std::atoi(argv[i + 1]);
  }
  return port;
}

}  // namespace

int DemoMain(int argc, char **argv) {
  int port = port_of(argc, argv);
  bool given = false;
  std::string error;
  std::string public_url = public_url_of(argc, argv, given, error);
  if (!error.empty()) {
    std::fprintf(stderr, "%s\n", error.c_str());
    return 1;
  }
  std::string path = config_path_of(argc, argv);
  struct Holder {
    std::unique_ptr<DemoApp> app;
    std::string error;
    bool tried = false;
  } holder;
  int bound = port;
  try {
    HttpServer server(
        [&](const std::string &method, const std::string &target,
            const std::vector<std::pair<std::string, std::string>> &headers, const std::string &body) {
          HttpResponse response;
          std::string upper = method;
          for (char &c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
          if (path_of(target) == "/healthz" && upper == "GET") {
            response.status = 200;
            response.headers.push_back({"content-type", "text/plain"});
            response.body = "ok";
            return response;
          }
          if (!holder.tried) {
            holder.tried = true;
            try {
              std::string raw_text = read_file(path);
              if (raw_text.empty() && !file_exists(path)) throw std::runtime_error(path + " cannot be read");
              Json raw = parse_json(raw_text);
              std::string realm = string_of(raw.get("realm"));
              std::string reply = string_of(raw.get("replyUrl"));
              if (given && !public_url.empty()) {
                realm = move_origin(realm, public_url);
                reply = move_origin(reply, public_url);
              } else if (port > 0) {
                realm = on_port(realm, port);
                reply = on_port(reply, port);
              }
              Json overrides;
              overrides.type = Json::Object;
              if (!realm.empty()) overrides.obj.emplace_back("realm", obj_string(realm));
              if (!reply.empty()) overrides.obj.emplace_back("replyUrl", obj_string(reply));
              RelyingParty party = RelyingParty::FromFile(path, json_dump(overrides));
              bool has_key = party.config().has_private_key;
              auto app = std::make_unique<DemoApp>(std::move(party));
              bool signals_off = raw.get("signals") && raw.get("signals")->type == Json::Bool && !raw.get("signals")->b;
              const Json *ssf = raw.get("ssf");
              std::string transmitter = ssf ? string_of(ssf->get("transmitter")) : "";
              if (!signals_off && !transmitter.empty() && has_key) {
                int interval = 5000;
                if (ssf && ssf->get("pollIntervalMs") && ssf->get("pollIntervalMs")->type == Json::Number) {
                  double n = 0;
                  if (json_as_float(*ssf->get("pollIntervalMs"), n) && n > 0) interval = static_cast<int>(n);
                }
                std::string base = abs_path(path);
                auto slash = base.find_last_of('/');
                base = slash == std::string::npos ? cwd_path() : base.substr(0, slash);
                std::string key = material_of(string_of(raw.get("privateKey")), base);
                std::string cert = material_of(string_of(raw.get("certificate")), base);
                std::string ca = raw.get("idpCa") ? material_of(string_of(raw.get("idpCa")), base) : "";
                try {
                  app->StartSignals(transmitter, interval, ca, cert, key);
                } catch (const std::exception &ex) {
                  std::printf("ssf: not started: %s\n", ex.what());
                }
              }
              holder.app = std::move(app);
            } catch (const std::exception &ex) {
              holder.error = ex.what();
            }
          }
          if (!holder.app) {
            response.status = 503;
            response.headers.push_back({"content-type", "text/plain"});
            response.body = "not ready: " + holder.error + "\n";
            return response;
          }
          DemoApp::Handled handled = holder.app->Handle(method, target, headers, body);
          response.status = handled.status;
          response.headers = handled.headers;
          response.body = std::move(handled.body);
          return response;
        },
        &bound);
    std::printf("wsfed-caep demo on port %d\n", bound);
    std::fflush(stdout);
    for (;;) std::this_thread::sleep_for(std::chrono::hours(24));
  } catch (const std::exception &ex) {
    std::fprintf(stderr, "%s\n", ex.what());
    return 1;
  }
  return 0;
}

}  // namespace iya::wsfed
