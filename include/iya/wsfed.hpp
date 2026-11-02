// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace iya::wsfed {

class failure : public std::runtime_error {
 public:
  std::string code;
  failure(std::string code_in, std::string message)
      : std::runtime_error(std::move(message)), code(std::move(code_in)) {}
};

[[noreturn]] inline void fail(const std::string &code, const std::string &message) {
  throw failure(code, message);
}

struct Resolved {
  std::string realm;
  std::string reply_url;
  std::string idp_metadata;
  int clock_skew_ms = 60000;
  bool want_assertions_encrypted = false;
  bool allow_unsolicited = false;
  bool request_token_type = true;
  bool signals_set = false;
  bool signals = false;
  bool has_private_key = false;
  std::string idp_ca;
  std::string idp_entity_id;
};

Resolved ResolveConfig(const std::string &json, const std::string &base_dir);

struct KeyPairPem {
  std::string private_key_pem;
  std::string certificate_pem;
  std::string common_name;
};

KeyPairPem CreateSelfSignedKeyPair(const std::string &common_name, int days, int bits);

std::string SignEnveloped(const std::string &xml, const std::string &element_id,
                          const std::string &key_pem, const std::string &cert_pem);

inline constexpr const char *kStatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success";
inline constexpr const char *kRsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
inline constexpr const char *kDefaultSubjectAttribute =
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";
inline constexpr const char *kSaml2Token = "urn:oasis:names:tc:SAML:2.0:assertion";

const std::map<std::string, std::string> &EventCatalog();
const std::vector<std::string> &CaepEvents();
const std::vector<std::string> &RiscEvents();

struct SubjectView {
  std::optional<std::string> person;
  std::optional<std::string> email;
  std::optional<std::string> idp_session;
};

SubjectView SubjectOf(const std::string &sub_json, const std::string &issuer);

struct JwsVerified {
  std::string header_json;
  std::string payload_json;
};

JwsVerified VerifyCompactJws(const std::string &token, const std::string &keys_json);

class RelyingParty {
 public:
  struct LoginRequest {
    std::string id;
    std::string url;
    std::string wctx;
  };
  struct LoginOptions {
    std::optional<std::string> relay_state;
    bool force_authn = false;
    std::optional<int> freshness;
    std::string authentication_method;
    std::string home_realm;
    std::vector<std::pair<std::string, std::string>> params;
  };
  struct Attribute {
    std::string name;
    std::vector<std::string> values;
    std::string friendly_name;
  };
  struct LoginResult {
    std::string name_id;
    std::optional<std::string> name_id_format;
    std::optional<std::string> name_qualifier;
    std::optional<std::string> sp_name_qualifier;
    std::optional<std::string> session_index;
    std::optional<std::string> relay_state;
    std::optional<std::string> request_id;
    std::optional<std::string> authn_context_class_ref;
    std::string trust_version;
    std::string realm;
    std::string issuer;
    bool encrypted = false;
    std::string assertion_id;
    std::int64_t not_on_or_after_ms = 0;
    std::int64_t authn_instant_ms = 0;
    std::vector<Attribute> attributes;
  };

  static RelyingParty Create(const std::string &json, const std::string &base_dir);
  static RelyingParty FromFile(const std::string &path, const std::string &overrides_json);

  RelyingParty(RelyingParty &&) noexcept;
  RelyingParty &operator=(RelyingParty &&) noexcept;
  ~RelyingParty();
  RelyingParty(const RelyingParty &) = delete;
  RelyingParty &operator=(const RelyingParty &) = delete;

  LoginRequest Login(const LoginOptions &options);
  LoginResult HandleReply(const std::string &method, const std::string &url, const std::string &body,
                          const std::vector<std::string> &request_ids);
  std::string Logout(const std::string &reply);
  bool IsSignOutCleanup(const std::string &method, const std::string &url, const std::string &body) const;
  std::string Metadata() const;
  const Resolved &config() const;
  std::string IdpEntityId() const;
  std::string PassiveEndpoint() const;
  std::vector<std::string> TokenTypesOffered() const;
  int SigningCertificateCount() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
  explicit RelyingParty(std::unique_ptr<Impl> impl);
};

struct SignalEvent {
  std::string type;
  std::string payload_json;
  SubjectView subject;
  std::string jti;
  std::vector<std::string> sessions;
  bool ended = false;
  std::optional<double> iat;
  std::optional<std::string> txn;
};

class SignalsReceiver {
 public:
  struct Options {
    int poll_interval_ms = 0;
    int max_events = 0;
    std::string subject_attribute;
    std::string description;
    std::string tls_ca;
    std::string tls_cert;
    std::string tls_key;
    std::function<void(const std::string &level, const std::string &message)> log;
  };
  using EndFn = std::function<void(const std::vector<std::string> &ids, const SignalEvent &event)>;
  using HandlerFn = std::function<void(const SignalEvent &event)>;

  SignalsReceiver(std::string transmitter, EndFn on_end, Options options);
  ~SignalsReceiver();
  SignalsReceiver(SignalsReceiver &&) noexcept;
  SignalsReceiver &operator=(SignalsReceiver &&) noexcept;
  SignalsReceiver(const SignalsReceiver &) = delete;
  SignalsReceiver &operator=(const SignalsReceiver &) = delete;

  void Start();
  void Stop();
  bool PollOnce();
  void On(const std::string &event_type, HandlerFn handler);
  void Track(const std::string &local_id, const std::string &name_id, const std::string &name_id_format,
             const std::string &session_index, const std::string &subject_value, const std::string &email);
  void Untrack(const std::string &local_id);
  std::vector<std::string> SessionsByPerson(const std::string &person) const;
  std::string StreamId() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};


int CliMain(int argc, char **argv);

struct HttpResponse {
  int status = 0;
  std::string body;
  std::vector<std::pair<std::string, std::string>> headers;
};

HttpResponse HttpRequest(const std::string &method, const std::string &url, const std::string &content_type,
                         const std::string &body, const std::string &cookie);

class HttpServer {
 public:
  using Handler = std::function<HttpResponse(const std::string &method, const std::string &target,
                                             const std::vector<std::pair<std::string, std::string>> &headers,
                                             const std::string &body)>;
  HttpServer(Handler handler, int *port_out);
  ~HttpServer();
  void Close();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace iya::wsfed
