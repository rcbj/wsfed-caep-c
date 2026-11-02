// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "detail.hpp"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <functional>
#include <thread>

namespace iya::wsfed {
namespace {

const char *kCaep = "https://schemas.openid.net/secevent/caep/event-type/";
const char *kRisc = "https://schemas.openid.net/secevent/risc/event-type/";
const char *kSsf = "https://schemas.openid.net/secevent/ssf/event-type/";
const char *kPoll = "urn:ietf:rfc:8936";

const char *kMail[] = {
    "urn:oid:0.9.2342.19200300.100.1.3",
    "mail",
    "email",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
};

std::string ev(const char *prefix, const char *name) { return std::string(prefix) + name; }

const std::map<std::string, std::string> &event_map() {
  static const std::map<std::string, std::string> events = {
      {"session_revoked", ev(kCaep, "session-revoked")},
      {"token_claims_change", ev(kCaep, "token-claims-change")},
      {"credential_change", ev(kCaep, "credential-change")},
      {"assurance_level_change", ev(kCaep, "assurance-level-change")},
      {"device_compliance_change", ev(kCaep, "device-compliance-change")},
      {"session_established", ev(kCaep, "session-established")},
      {"session_presented", ev(kCaep, "session-presented")},
      {"risk_level_change", ev(kCaep, "risk-level-change")},
      {"account_credential_change_required", ev(kRisc, "account-credential-change-required")},
      {"account_purged", ev(kRisc, "account-purged")},
      {"account_disabled", ev(kRisc, "account-disabled")},
      {"account_enabled", ev(kRisc, "account-enabled")},
      {"identifier_changed", ev(kRisc, "identifier-changed")},
      {"identifier_recycled", ev(kRisc, "identifier-recycled")},
      {"credential_compromise", ev(kRisc, "credential-compromise")},
      {"opt_in", ev(kRisc, "opt-in")},
      {"opt_out_initiated", ev(kRisc, "opt-out-initiated")},
      {"opt_out_cancelled", ev(kRisc, "opt-out-cancelled")},
      {"opt_out_effective", ev(kRisc, "opt-out-effective")},
      {"recovery_activated", ev(kRisc, "recovery-activated")},
      {"recovery_information_changed", ev(kRisc, "recovery-information-changed")},
      {"sessions_revoked", ev(kRisc, "sessions-revoked")},
      {"verification", ev(kSsf, "verification")},
      {"stream_updated", ev(kSsf, "stream-updated")},
  };
  return events;
}

Json j_string(const std::string &s) { return obj_string(s); }
Json j_bool(bool v) { return obj_bool(v); }
Json j_num(long long n) { return obj_number(n); }
Json j_obj() {
  Json j;
  j.type = Json::Object;
  return j;
}
Json j_arr() {
  Json j;
  j.type = Json::Array;
  return j;
}
void j_put(Json &obj, const std::string &key, Json value) { obj.obj.emplace_back(key, std::move(value)); }

std::string lower_copy(std::string s) {
  for (char &c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

bool contains_str(const std::vector<std::string> &list, const std::string &value) {
  return std::find(list.begin(), list.end(), value) != list.end();
}

std::map<std::string, std::string> simple_subject(const Json *identifier, const std::string &issuer) {
  std::map<std::string, std::string> out;
  if (!identifier || identifier->type != Json::Object) return out;
  std::string fmt = string_of(identifier->get("format"));
  if (fmt.empty()) fmt = string_of(identifier->get("subject_type"));
  if (fmt == "iss_sub") {
    const Json *iss = identifier->get("iss");
    bool iss_ok = !iss || iss->type == Json::Null || (iss->type == Json::String && iss->text == issuer);
    if (iss_ok && identifier->get("sub") && identifier->get("sub")->type == Json::String) out["sub"] = identifier->get("sub")->text;
  } else if (fmt == "email") {
    if (identifier->get("email") && identifier->get("email")->type == Json::String) out["email"] = identifier->get("email")->text;
  } else if (fmt == "opaque") {
    if (identifier->get("id") && identifier->get("id")->type == Json::String) out["opaque"] = identifier->get("id")->text;
  } else if (fmt == "aliases") {
    const Json *list = identifier->get("identifiers");
    if (list && list->type == Json::Array) {
      for (const auto &child : list->arr) {
        auto part = simple_subject(&child, issuer);
        for (const auto &kv : part) out[kv.first] = kv.second;
      }
    }
  }
  return out;
}

std::vector<std::string> string_list(const Json *value) {
  std::vector<std::string> out;
  if (!value || value->type == Json::Null) return out;
  if (value->type == Json::Array) {
    for (const auto &item : value->arr) {
      if (item.type == Json::String) out.push_back(item.text);
      else if (item.type == Json::Number) out.push_back(item.text);
      else if (item.type == Json::Bool) out.push_back(item.b ? "true" : "false");
    }
    return out;
  }
  if (value->type == Json::String && !value->text.empty()) out.push_back(value->text);
  else if (value->type != Json::String) {
    std::string dumped = json_dump(*value);
    if (!dumped.empty() && dumped != "null") out.push_back(dumped);
  }
  return out;
}

struct Session {
  std::string local_id;
  std::string person;
  std::string email;
  std::string idp_session;
};

class SessionIndex {
 public:
  void add(Session session) {
    std::lock_guard<std::mutex> lock(mu_);
    if (static_cast<int>(sessions_.size()) >= max_ && !sessions_.count(session.local_id)) {
      if (!sessions_.empty()) sessions_.erase(sessions_.begin());
    }
    if (!session.email.empty()) session.email = lower_copy(session.email);
    sessions_[session.local_id] = std::move(session);
  }
  void remove(const std::string &id) {
    std::lock_guard<std::mutex> lock(mu_);
    sessions_.erase(id);
  }
  std::vector<std::string> find(const std::function<bool(const Session &)> &match) {
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<std::string> out;
    for (const auto &kv : sessions_) {
      if (match(kv.second)) out.push_back(kv.first);
    }
    return out;
  }
  std::vector<std::string> by_person(const std::string &person) {
    return find([&](const Session &s) { return s.person == person; });
  }
  std::vector<std::string> by_email(const std::string &email) {
    std::string wanted = lower_copy(email);
    return find([&](const Session &s) { return s.email == wanted; });
  }
  std::vector<std::string> by_idp(const std::string &idp) {
    return find([&](const Session &s) { return s.idp_session == idp; });
  }

 private:
  std::mutex mu_;
  std::map<std::string, Session> sessions_;
  int max_ = 100000;
};

struct Flight {
  std::mutex mu;
  std::condition_variable cv;
  bool done = false;
  bool result = false;
  std::exception_ptr error;
};

const std::vector<std::string> &default_requested() {
  static const std::vector<std::string> values = {
      event_map().at("session_revoked"),
      event_map().at("credential_change"),
      event_map().at("assurance_level_change"),
      event_map().at("token_claims_change"),
      event_map().at("account_disabled"),
      event_map().at("account_enabled"),
      event_map().at("account_purged"),
      event_map().at("credential_compromise"),
      event_map().at("sessions_revoked"),
      event_map().at("account_credential_change_required"),
  };
  return values;
}

const std::vector<std::string> &default_ending() {
  static const std::vector<std::string> values = {
      event_map().at("session_revoked"), event_map().at("account_disabled"), event_map().at("account_purged"),
      event_map().at("credential_compromise"), event_map().at("sessions_revoked"),
  };
  return values;
}

}  // namespace

const std::map<std::string, std::string> &EventCatalog() { return event_map(); }

const std::vector<std::string> &CaepEvents() {
  static const std::vector<std::string> values = {
      ev(kCaep, "session-revoked"),
      ev(kCaep, "token-claims-change"),
      ev(kCaep, "credential-change"),
      ev(kCaep, "assurance-level-change"),
      ev(kCaep, "device-compliance-change"),
      ev(kCaep, "session-established"),
      ev(kCaep, "session-presented"),
      ev(kCaep, "risk-level-change"),
  };
  return values;
}

const std::vector<std::string> &RiscEvents() {
  static const std::vector<std::string> values = {
      ev(kRisc, "account-credential-change-required"),
      ev(kRisc, "account-purged"),
      ev(kRisc, "account-disabled"),
      ev(kRisc, "account-enabled"),
      ev(kRisc, "identifier-changed"),
      ev(kRisc, "identifier-recycled"),
      ev(kRisc, "credential-compromise"),
      ev(kRisc, "opt-in"),
      ev(kRisc, "opt-out-initiated"),
      ev(kRisc, "opt-out-cancelled"),
      ev(kRisc, "opt-out-effective"),
      ev(kRisc, "recovery-activated"),
      ev(kRisc, "recovery-information-changed"),
      ev(kRisc, "sessions-revoked"),
  };
  return values;
}

SubjectView SubjectOf(const std::string &sub_json, const std::string &issuer) {
  SubjectView view;
  if (sub_json.empty()) return view;
  Json item = parse_json(sub_json);
  if (item.type != Json::Object) return view;
  std::string fmt = string_of(item.get("format"));
  if (fmt.empty()) fmt = string_of(item.get("subject_type"));
  auto fill = [](SubjectView &view, const std::map<std::string, std::string> &one) {
    if (one.count("sub")) view.person = one.at("sub");
    if (one.count("email")) view.email = one.at("email");
  };
  if (fmt == "complex" || (fmt.empty() && (item.get("user") || item.get("session")))) {
    auto user = simple_subject(item.get("user"), issuer);
    auto session = simple_subject(item.get("session"), issuer);
    if (user.count("sub")) view.person = user["sub"];
    if (user.count("email")) view.email = user["email"];
    std::string session_id = session.count("opaque") ? session["opaque"] : "";
    if (session_id.empty() && session.count("sub")) session_id = session["sub"];
    if (!session_id.empty()) view.idp_session = session_id;
    return view;
  }
  fill(view, simple_subject(&item, issuer));
  return view;
}

JwsVerified VerifyCompactJws(const std::string &token, const std::string &keys_json) {
  auto parts_split = [](const std::string &s) {
    std::vector<std::string> out;
    size_t i = 0;
    while (i <= s.size()) {
      auto dot = s.find('.', i);
      if (dot == std::string::npos) {
        out.push_back(s.substr(i));
        break;
      }
      out.push_back(s.substr(i, dot - i));
      i = dot + 1;
    }
    return out;
  };
  auto parts = parts_split(token);
  if (parts.size() != 3) fail("signature", "the SET is not a compact JWS");
  auto decode_part = [](const std::string &value, const std::string &what) {
    for (char c : value) {
      bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
      if (!ok) fail("signature", "the SET's " + what + " is not base64url");
    }
    auto raw = b64_decode(value, true);
    return std::string(reinterpret_cast<char *>(raw.data()), raw.size());
  };
  std::string header_raw = decode_part(parts[0], "header");
  std::string payload_raw = decode_part(parts[1], "payload");
  Json header;
  Json payload;
  try {
    header = parse_json(header_raw);
    payload = parse_json(payload_raw);
  } catch (const failure &) {
    fail("signature", "the SET's header or payload is not JSON");
  }
  if (header.type != Json::Object || payload.type != Json::Object) fail("signature", "the SET's header or payload is not JSON");
  std::string alg = string_of(header.get("alg"));
  static const char *supported =
      "RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA, Ed25519";
  auto known = event_map();
  (void)known;
  bool supported_alg = alg == "RS256" || alg == "RS384" || alg == "RS512" || alg == "PS256" || alg == "PS384" ||
                       alg == "PS512" || alg == "ES256" || alg == "ES384" || alg == "ES512" || alg == "EdDSA" ||
                       alg == "Ed25519";
  if (!supported_alg) {
    std::string shown = alg.empty() ? "(no alg)" : alg;
    fail("signature", "the SET is signed with " + shown + ", which this receiver does not verify (" + supported + ")");
  }
  if (header.has("crit") && header.get("crit") && header.get("crit")->type != Json::Null) {
    fail("signature", "the SET's header has a crit member this receiver does not understand");
  }
  std::string kid = string_of(header.get("kid"));
  std::string kty = (alg[0] == 'R' || alg[0] == 'P') ? "RSA" : (alg[0] == 'E' && alg != "EdDSA" && alg != "Ed25519") ? "EC" : "OKP";
  if (alg == "EdDSA" || alg == "Ed25519") kty = "OKP";
  Json keys = parse_json(keys_json.empty() ? "{\"keys\":[]}" : keys_json);
  const Json *list = keys.type == Json::Array ? &keys : keys.get("keys");
  if (keys.type == Json::Object && !list) list = nullptr;
  std::vector<const Json *> candidates;
  if (list && list->type == Json::Array) {
    for (const auto &key : list->arr) {
      if (key.type != Json::Object) continue;
      if (!kid.empty() && string_of(key.get("kid")) != kid) continue;
      if (string_of(key.get("kty")) != kty) continue;
      std::string use = string_of(key.get("use"));
      if (!use.empty() && use != "sig") continue;
      std::string key_alg = string_of(key.get("alg"));
      if (!key_alg.empty() && key_alg != alg) continue;
      candidates.push_back(&key);
    }
  }
  if (candidates.empty()) {
    std::string suffix = kid.empty() ? "" : " with kid " + kid;
    fail("signature", "the transmitter publishes no " + kty + " signing key" + suffix);
  }
  std::string data = parts[0] + "." + parts[1];
  auto signature = b64_decode(parts[2], true);
  bool ok = false;
  for (const Json *jwk : candidates) {
    EVP_PKEY *key = nullptr;
    try {
      key = jwk_public(*jwk);
    } catch (const failure &) {
      continue;
    }
    if (!key) continue;
    ok = jws_verify_key(key, alg, data, signature);
    EVP_PKEY_free(key);
    if (ok) break;
  }
  if (!ok) fail("signature", "the SET's signature does not verify against the transmitter's keys");
  JwsVerified verified;
  verified.header_json = header_raw;
  verified.payload_json = payload_raw;
  return verified;
}

struct SignalsReceiver::Impl {
  std::string transmitter;
  EndFn on_end;
  TlsMaterial tls;
  bool has_tls = false;
  std::vector<std::string> events_requested;
  std::vector<std::string> end_on;
  SessionIndex index;
  std::string subject_attribute;
  std::string description;
  int poll_interval_ms = 5000;
  int max_events = 50;
  std::function<void(const std::string &, const std::string &)> log;
  std::mutex mu;
  Json config;
  Json stream;
  Json keys;
  int64_t keys_at = 0;
  bool running = false;
  std::vector<std::string> ack;
  std::map<std::string, std::pair<std::string, std::string>> errs;
  std::map<std::string, std::vector<HandlerFn>> handlers;
  std::shared_ptr<Flight> inflight;
  std::mutex poll_mu;
  std::thread thread;
  std::mutex stop_mu;
  std::condition_variable stop_cv;
  bool stop = false;
  bool thread_done = true;

  void note(const std::string &level, const std::string &message) {
    if (log) log(level, message);
    else if (level == "info") std::fprintf(stdout, "%s\n", message.c_str());
    else std::fprintf(stderr, "%s\n", message.c_str());
  }

  HttpResult call(const std::string &method, const std::string &url, const Json *body) {
    std::vector<std::pair<std::string, std::string>> headers = {{"accept", "application/json"}};
    std::string payload;
    const std::string *sent = nullptr;
    if (body) {
      payload = json_dump(*body);
      sent = &payload;
      headers.emplace_back("content-type", "application/json");
    }
    return http_send(method, url, headers, sent, has_tls ? &tls : nullptr, "ssf");
  }

  Json parse_body(const std::string &body) {
    if (body.empty()) return Json();
    try {
      return parse_json(body);
    } catch (const failure &) {
      Json text;
      text.type = Json::String;
      text.text = body;
      return text;
    }
  }

  Json discover() {
    std::string url = transmitter + "/.well-known/ssf-configuration";
    HttpResult answer = call("GET", url, nullptr);
    Json config = parse_body(answer.body);
    if (answer.status != 200 || config.type != Json::Object || string_of(config.get("configuration_endpoint")).empty() ||
        string_of(config.get("jwks_uri")).empty()) {
      fail("ssf", url + " answered " + itoa_i(answer.status) + " without a usable transmitter configuration");
    }
    const Json *supported = config.get("delivery_methods_supported");
    if (supported && supported->type == Json::Array) {
      bool found = false;
      for (const auto &item : supported->arr) {
        if (item.type == Json::String && item.text == kPoll) found = true;
      }
      if (!found) fail("ssf", "the transmitter does not offer poll delivery (RFC 8936)");
    }
    return config;
  }

  Json jwks(bool force) {
    std::unique_lock<std::mutex> lock(mu);
    if (!force && keys.type == Json::Object && keys.get("keys") && now_ms() - keys_at < 3600LL * 1000) {
      return keys;
    }
    std::string uri = string_of(config.get("jwks_uri"));
    lock.unlock();
    HttpResult answer = call("GET", uri, nullptr);
    Json body = parse_body(answer.body);
    bool has_keys = body.type == Json::Object && body.get("keys");
    if (answer.status != 200 || !has_keys) fail("ssf", "the transmitter's JWKS answered " + itoa_i(answer.status));
    lock.lock();
    keys = body;
    keys_at = now_ms();
    return keys;
  }

  Json ensure_stream() {
    std::string endpoint;
    {
      std::lock_guard<std::mutex> lock(mu);
      endpoint = string_of(config.get("configuration_endpoint"));
    }
    HttpResult answer = call("GET", endpoint, nullptr);
    Json parsed = parse_body(answer.body);
    if (answer.status == 200) {
      std::vector<const Json *> all;
      if (parsed.type == Json::Array) {
        for (const auto &item : parsed.arr) all.push_back(&item);
      } else if (parsed.type == Json::Object) {
        all.push_back(&parsed);
      }
      for (const Json *item : all) {
        if (!item || item->type != Json::Object || string_of(item->get("stream_id")).empty()) continue;
        const Json *delivery = item->get("delivery");
        if (delivery && string_of(delivery->get("method")) == kPoll) return *item;
      }
    } else if (answer.status != 404) {
      std::string text = json_dump(parsed);
      if (text.size() > 300) text.resize(300);
      fail("ssf", "listing the streams at " + endpoint + " answered " + itoa_i(answer.status) + ": " + text);
    }
    Json body = j_obj();
    Json delivery = j_obj();
    j_put(delivery, "method", j_string(kPoll));
    j_put(body, "delivery", std::move(delivery));
    Json events = j_arr();
    for (const auto &event : events_requested) events.arr.push_back(j_string(event));
    j_put(body, "events_requested", std::move(events));
    if (!description.empty()) j_put(body, "description", j_string(description));
    answer = call("POST", endpoint, &body);
    parsed = parse_body(answer.body);
    if ((answer.status != 200 && answer.status != 201) || parsed.type != Json::Object || string_of(parsed.get("stream_id")).empty()) {
      std::string text = answer.body.size() > 300 ? answer.body.substr(0, 300) : answer.body;
      fail("ssf", "creating a stream at " + endpoint + " answered " + itoa_i(answer.status) + ": " + text);
    }
    return parsed;
  }

  std::vector<std::string> sessions_for(const std::string &event_type, const SubjectView &subject) {
    if (event_type == event_map().at("verification") || event_type == event_map().at("stream_updated")) return {};
    if (subject.idp_session) {
      auto found = index.by_idp(*subject.idp_session);
      if (!found.empty() || event_type == event_map().at("session_revoked")) return found;
    }
    if (subject.person) return index.by_person(*subject.person);
    if (subject.email) return index.by_email(*subject.email);
    return {};
  }

  void handle(const std::string &jti, const std::string &token) {
    Json keyset = jwks(false);
    JwsVerified verified;
    try {
      verified = VerifyCompactJws(token, json_dump(keyset));
    } catch (const failure &ex) {
      std::string message = ex.what();
      if (message.find("publishes no") != std::string::npos || message.find("does not verify") != std::string::npos) {
        try {
          keyset = jwks(true);
          verified = VerifyCompactJws(token, json_dump(keyset));
        } catch (const failure &) {
          throw ex;
        }
      } else {
        throw;
      }
    }
    Json header = parse_json(verified.header_json);
    Json payload = parse_json(verified.payload_json);
    const Json *typ = header.get("typ");
    if (typ && typ->type != Json::Null) {
      std::string shown = typ->type == Json::String ? typ->text : json_dump(*typ);
      if (lower_copy(shown) != "secevent+jwt") fail("validation", "the SET's typ is " + shown);
    }
    std::string issuer;
    Json stream_copy;
    {
      std::lock_guard<std::mutex> lock(mu);
      issuer = string_of(config.get("issuer"));
      stream_copy = stream;
    }
    std::string got_iss = payload.get("iss") ? (payload.get("iss")->type == Json::String ? payload.get("iss")->text : json_dump(*payload.get("iss"))) : "";
    if (string_of(payload.get("iss")) != issuer) fail("validation", "the SET was issued by " + got_iss + ", not " + issuer);
    auto want_list = string_list(stream_copy.get("aud"));
    auto aud_list = string_list(payload.get("aud"));
    if (!want_list.empty()) {
      bool hit = false;
      for (const auto &item : aud_list) {
        if (contains_str(want_list, item)) hit = true;
      }
      if (!hit) {
        std::string joined;
        for (size_t i = 0; i < aud_list.size(); i++) {
          if (i) joined += ", ";
          joined += aud_list[i];
        }
        fail("validation", "the SET is for " + joined + ", not this stream");
      }
    }
    if (payload.get("jti") && payload.get("jti")->type != Json::Null && string_of(payload.get("jti")) != jti) {
      fail("validation", "the SET's jti is not the one it was delivered under");
    }
    const Json *events = payload.get("events");
    if (!events || events->type != Json::Object || events->obj.empty()) fail("validation", "the SET carries no events");
    for (const auto &event_kv : events->obj) {
      const Json *sub = payload.get("sub_id");
      if (!sub || sub->type == Json::Null) {
        if (event_kv.second.type == Json::Object) sub = event_kv.second.get("subject");
      }
      SubjectView subject;
      if (sub && sub->type == Json::Object) subject = SubjectOf(json_dump(*sub), issuer);
      auto sessions = sessions_for(event_kv.first, subject);
      bool ends = contains_str(end_on, event_kv.first) && !sessions.empty();
      SignalEvent event;
      event.type = event_kv.first;
      event.payload_json = json_dump(event_kv.second);
      event.subject = subject;
      event.jti = jti;
      event.sessions = sessions;
      event.ended = ends;
      if (payload.get("iat") && payload.get("iat")->type == Json::Number) {
        double n = 0;
        if (json_as_float(*payload.get("iat"), n)) event.iat = n;
      }
      if (payload.get("txn") && payload.get("txn")->type == Json::String) event.txn = payload.get("txn")->text;
      if (ends) {
        try {
          on_end(sessions, event);
        } catch (const std::exception &ex) {
          note("error", "ssf: onEndSessions threw for " + event_type_name(event.type) + " (SET " + jti +
                            " is still acknowledged): " + ex.what());
          event.ended = false;
        }
        if (event.ended) {
          for (const auto &local : sessions) index.remove(local);
        }
      }
      std::vector<HandlerFn> handlers_now;
      {
        std::lock_guard<std::mutex> lock(mu);
        if (handlers.count(event.type)) handlers_now.insert(handlers_now.end(), handlers[event.type].begin(), handlers[event.type].end());
        if (handlers.count("*")) handlers_now.insert(handlers_now.end(), handlers["*"].begin(), handlers["*"].end());
      }
      for (const auto &handler : handlers_now) {
        try {
          handler(event);
        } catch (const std::exception &ex) {
          note("error", "ssf: a handler for " + event.type + " threw (SET " + jti + " is still acknowledged): " + ex.what());
        }
      }
    }
  }

  static std::string event_type_name(const std::string &type) { return type; }

  bool poll_now() {
    std::string url;
    std::vector<std::string> ack_now;
    std::map<std::string, std::pair<std::string, std::string>> errs_now;
    {
      std::lock_guard<std::mutex> lock(mu);
      const Json *delivery = stream.get("delivery");
      url = delivery ? string_of(delivery->get("endpoint_url")) : "";
      ack_now.swap(ack);
      errs_now.swap(errs);
    }
    Json body = j_obj();
    j_put(body, "maxEvents", j_num(max_events));
    j_put(body, "returnImmediately", j_bool(true));
    if (!ack_now.empty()) {
      Json arr = j_arr();
      for (const auto &item : ack_now) arr.arr.push_back(j_string(item));
      j_put(body, "ack", std::move(arr));
    }
    if (!errs_now.empty()) {
      Json obj = j_obj();
      for (const auto &kv : errs_now) {
        Json err = j_obj();
        j_put(err, "err", j_string(kv.second.first));
        j_put(err, "description", j_string(kv.second.second));
        j_put(obj, kv.first, std::move(err));
      }
      j_put(body, "setErrs", std::move(obj));
    }
    HttpResult answer;
    try {
      answer = call("POST", url, &body);
    } catch (...) {
      restore(ack_now, errs_now);
      throw;
    }
    if (answer.status != 200) {
      restore(ack_now, errs_now);
      std::string text = answer.body.size() > 300 ? answer.body.substr(0, 300) : answer.body;
      fail("ssf", "the poll answered " + itoa_i(answer.status) + ": " + text);
    }
    Json payload = parse_body(answer.body);
    const Json *sets = payload.type == Json::Object ? payload.get("sets") : nullptr;
    if (sets && sets->type == Json::Object) {
      for (const auto &kv : sets->obj) {
        std::string text = kv.second.type == Json::String ? kv.second.text : "";
        try {
          handle(kv.first, text);
          std::lock_guard<std::mutex> lock(mu);
          ack.push_back(kv.first);
        } catch (const failure &ex) {
          note("warn", "ssf: SET " + kv.first + " refused: " + ex.what());
          std::string code = ex.code == "signature" ? "invalid_key" : "invalid_request";
          std::lock_guard<std::mutex> lock(mu);
          errs[kv.first] = {code, ex.what()};
        }
      }
    }
    const Json *more = payload.type == Json::Object ? payload.get("moreAvailable") : nullptr;
    return more && more->type == Json::Bool && more->b;
  }

  void restore(const std::vector<std::string> &ack_now, const std::map<std::string, std::pair<std::string, std::string>> &errs_now) {
    std::lock_guard<std::mutex> lock(mu);
    std::vector<std::string> merged = ack_now;
    merged.insert(merged.end(), ack.begin(), ack.end());
    ack.swap(merged);
    auto kept = errs;
    errs = errs_now;
    for (const auto &kv : kept) errs[kv.first] = kv.second;
  }

  void loop() {
    while (true) {
      {
        std::lock_guard<std::mutex> lock(mu);
        if (!running) break;
      }
      int delay = poll_interval_ms;
      try {
        bool more = poll_shared();
        if (more) delay = 0;
      } catch (const std::exception &ex) {
        note("warn", std::string("ssf: poll failed: ") + ex.what());
        delay = poll_interval_ms * 4;
        if (delay > 60000) delay = 60000;
      }
      std::unique_lock<std::mutex> lock(stop_mu);
      if (stop_cv.wait_for(lock, std::chrono::milliseconds(delay), [&] { return stop || !running_relaxed(); })) break;
    }
    std::lock_guard<std::mutex> lock(stop_mu);
    thread_done = true;
    stop_cv.notify_all();
  }

  bool running_relaxed() {
    std::lock_guard<std::mutex> lock(mu);
    return running;
  }

  bool poll_shared() {
    std::shared_ptr<Flight> mine;
    {
      std::unique_lock<std::mutex> lock(poll_mu);
      if (inflight) {
        auto current = inflight;
        lock.unlock();
        std::unique_lock<std::mutex> fl(current->mu);
        current->cv.wait(fl, [&] { return current->done; });
        if (current->error) std::rethrow_exception(current->error);
        return current->result;
      }
      mine = std::make_shared<Flight>();
      inflight = mine;
    }
    bool result = false;
    std::exception_ptr err;
    try {
      result = poll_now();
    } catch (...) {
      err = std::current_exception();
    }
    {
      std::lock_guard<std::mutex> lock(poll_mu);
      if (inflight == mine) inflight.reset();
    }
    {
      std::lock_guard<std::mutex> fl(mine->mu);
      mine->result = result;
      mine->error = err;
      mine->done = true;
    }
    mine->cv.notify_all();
    if (err) std::rethrow_exception(err);
    return result;
  }
};

SignalsReceiver::SignalsReceiver(std::string transmitter, EndFn on_end, Options options) : impl_(std::make_unique<Impl>()) {
  if (!on_end) fail("config", "onEndSessions is required");
  if (transmitter.compare(0, 7, "http://") != 0 && transmitter.compare(0, 8, "https://") != 0) {
    fail("config", "transmitter must be an http(s) URL");
  }
  while (!transmitter.empty() && transmitter.back() == '/') transmitter.pop_back();
  impl_->transmitter = std::move(transmitter);
  impl_->on_end = std::move(on_end);
  impl_->events_requested = default_requested();
  impl_->end_on = default_ending();
  if (options.poll_interval_ms > 0) impl_->poll_interval_ms = options.poll_interval_ms;
  if (options.max_events > 0) impl_->max_events = options.max_events;
  if (!options.subject_attribute.empty()) impl_->subject_attribute = options.subject_attribute;
  impl_->description = options.description;
  impl_->log = std::move(options.log);
  if (!options.tls_ca.empty() || !options.tls_cert.empty() || !options.tls_key.empty()) {
    impl_->has_tls = true;
    impl_->tls.ca = options.tls_ca;
    impl_->tls.cert = options.tls_cert;
    impl_->tls.key = options.tls_key;
  }
}

SignalsReceiver::~SignalsReceiver() { Stop(); }
SignalsReceiver::SignalsReceiver(SignalsReceiver &&) noexcept = default;
SignalsReceiver &SignalsReceiver::operator=(SignalsReceiver &&) noexcept = default;

void SignalsReceiver::Start() {
  {
    std::lock_guard<std::mutex> lock(impl_->mu);
    if (impl_->running) return;
  }
  Json config = impl_->discover();
  {
    std::lock_guard<std::mutex> lock(impl_->mu);
    impl_->config = config;
  }
  impl_->jwks(true);
  Json stream = impl_->ensure_stream();
  const Json *delivery = stream.get("delivery");
  if (!delivery || string_of(delivery->get("endpoint_url")).empty()) fail("ssf", "the stream has no poll endpoint_url");
  std::lock_guard<std::mutex> lock(impl_->mu);
  if (impl_->running) {
    impl_->stream = stream;
    return;
  }
  impl_->stream = stream;
  impl_->running = true;
  {
    std::lock_guard<std::mutex> stop_lock(impl_->stop_mu);
    impl_->stop = false;
    impl_->thread_done = false;
  }
  const Json *delivered = stream.get("events_delivered");
  int count = delivered && delivered->type == Json::Array ? static_cast<int>(delivered->arr.size()) : 0;
  impl_->note("info", "ssf: polling stream " + string_of(stream.get("stream_id")) + " at " + string_of(delivery->get("endpoint_url")) +
                          ", delivering " + itoa_i(count) + " event type(s)");
  impl_->thread = std::thread([this] { impl_->loop(); });
}

void SignalsReceiver::Stop() {
  if (!impl_) return;
  {
    std::lock_guard<std::mutex> lock(impl_->mu);
    impl_->running = false;
  }
  {
    std::lock_guard<std::mutex> lock(impl_->stop_mu);
    impl_->stop = true;
  }
  impl_->stop_cv.notify_all();
  if (impl_->thread.joinable()) {
    auto start = std::chrono::steady_clock::now();
    while (impl_->thread.joinable()) {
      {
        std::lock_guard<std::mutex> lock(impl_->stop_mu);
        if (impl_->thread_done) break;
      }
      if (std::chrono::steady_clock::now() - start > std::chrono::seconds(20)) break;
      impl_->stop_cv.notify_all();
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (impl_->thread.joinable()) {
      std::lock_guard<std::mutex> lock(impl_->stop_mu);
      if (impl_->thread_done) impl_->thread.join();
      else impl_->thread.detach();
    }
  }
}

bool SignalsReceiver::PollOnce() { return impl_->poll_shared(); }

void SignalsReceiver::On(const std::string &event_type, HandlerFn handler) {
  std::lock_guard<std::mutex> lock(impl_->mu);
  impl_->handlers[event_type].push_back(std::move(handler));
}

void SignalsReceiver::Track(const std::string &local_id, const std::string &name_id, const std::string &name_id_format,
                            const std::string &session_index, const std::string &subject_value, const std::string &email) {
  Session session;
  session.local_id = local_id;
  session.person = subject_value;
  session.email = email;
  if (session.email.empty() && name_id_format == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress") session.email = name_id;
  session.idp_session = session_index;
  (void)impl_->subject_attribute;
  impl_->index.add(std::move(session));
}

void SignalsReceiver::Untrack(const std::string &local_id) {
  if (impl_) impl_->index.remove(local_id);
}

std::vector<std::string> SignalsReceiver::SessionsByPerson(const std::string &person) const { return impl_->index.by_person(person); }

std::string SignalsReceiver::StreamId() const {
  std::lock_guard<std::mutex> lock(impl_->mu);
  return string_of(impl_->stream.get("stream_id"));
}

}  // namespace iya::wsfed
