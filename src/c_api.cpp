// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "iya/wsfed.hpp"
#include "iya_wsfed.h"
#include "c_api_internal.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <new>
#include <string>
#include <vector>

namespace {

int report(iya_wsfed_error *err, const iya::wsfed::failure &ex) {
  std::fprintf(stderr, "%s\n", ex.what());
  if (err) {
    std::snprintf(err->code, sizeof err->code, "%s", ex.code.c_str());
    std::snprintf(err->message, sizeof err->message, "%s", ex.what());
  }
  return 1;
}

char *dup_str(const std::string &value) {
  char *out = static_cast<char *>(std::malloc(value.size() + 1));
  if (!out) return nullptr;
  std::memcpy(out, value.data(), value.size());
  out[value.size()] = '\0';
  return out;
}

bool ieq(const std::string &a, const char *b) {
  if (!b) return false;
  size_t n = std::strlen(b);
  if (a.size() != n) return false;
  for (size_t i = 0; i < n; i++) {
    char c = a[i];
    char d = b[i];
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    if (d >= 'A' && d <= 'Z') d = static_cast<char>(d - 'A' + 'a');
    if (c != d) return false;
  }
  return true;
}


struct LoginRequestBox {
  iya::wsfed::RelyingParty::LoginRequest request;
};

struct LoginBox {
  iya::wsfed::RelyingParty::LoginResult login;
};

struct KeyBox {
  iya::wsfed::KeyPairPem pair;
};

struct ReceiverBox {
  iya::wsfed::SignalsReceiver receiver;
  std::vector<std::string> people;
  std::string person;
  std::string stream_id;
  ReceiverBox(std::string transmitter, iya::wsfed::SignalsReceiver::EndFn on_end, iya::wsfed::SignalsReceiver::Options options)
      : receiver(std::move(transmitter), std::move(on_end), std::move(options)) {}
};

struct ServerBox {
  iya::wsfed::HttpServer server;
  ServerBox(iya::wsfed::HttpServer::Handler handler, int *port) : server(std::move(handler), port) {}
};

struct ResponseBox {
  iya::wsfed::HttpResponse response;
};

const iya::wsfed::RelyingParty::Attribute *attr_of(const LoginBox *login, const char *name) {
  if (!login || !name) return nullptr;
  for (const auto &attr : login->login.attributes) {
    if (attr.name == name) return &attr;
  }
  return nullptr;
}

void fill_event(const iya::wsfed::SignalEvent &event, iya_wsfed_event *out, std::vector<const char *> &sessions) {
  sessions.clear();
  for (const auto &id : event.sessions) sessions.push_back(id.c_str());
  out->type = event.type.c_str();
  out->jti = event.jti.c_str();
  out->payload_json = event.payload_json.c_str();
  out->ended = event.ended ? 1 : 0;
  out->session_count = static_cast<int>(sessions.size());
  out->sessions = sessions.empty() ? nullptr : sessions.data();
  out->has_person = event.subject.person ? 1 : 0;
  out->person = event.subject.person ? event.subject.person->c_str() : nullptr;
  out->has_email = event.subject.email ? 1 : 0;
  out->email = event.subject.email ? event.subject.email->c_str() : nullptr;
  out->has_idp_session = event.subject.idp_session ? 1 : 0;
  out->idp_session = event.subject.idp_session ? event.subject.idp_session->c_str() : nullptr;
}

}  // namespace

namespace iya::wsfed::capi {

int report_std(iya_wsfed_error *err, const std::exception &ex) {
  const auto *fail = dynamic_cast<const iya::wsfed::failure *>(&ex);
  if (fail) return report(err, *fail);
  return report(err, iya::wsfed::failure("error", ex.what()));
}

}  // namespace iya::wsfed::capi

using iya::wsfed::capi::PartyBox;
using iya::wsfed::capi::ResolvedBox;
using iya::wsfed::capi::report_std;

extern "C" {

const char *iya_wsfed_status_success(void) { return iya::wsfed::kStatusSuccess; }
const char *iya_wsfed_rsa_sha256(void) { return iya::wsfed::kRsaSha256; }
const char *iya_wsfed_default_subject(void) { return iya::wsfed::kDefaultSubjectAttribute; }

const char *iya_wsfed_event_uri(const char *name) {
  if (!name) return nullptr;
  const auto &catalog = iya::wsfed::EventCatalog();
  auto found = catalog.find(name);
  if (found == catalog.end()) return nullptr;
  return found->second.c_str();
}

int iya_wsfed_caep_count(void) { return static_cast<int>(iya::wsfed::CaepEvents().size()); }
int iya_wsfed_risc_count(void) { return static_cast<int>(iya::wsfed::RiscEvents().size()); }

int iya_wsfed_caep_has(const char *uri) {
  if (!uri) return 0;
  for (const auto &item : iya::wsfed::CaepEvents()) {
    if (item == uri) return 1;
  }
  return 0;
}

int iya_wsfed_risc_has(const char *uri) {
  if (!uri) return 0;
  for (const auto &item : iya::wsfed::RiscEvents()) {
    if (item == uri) return 1;
  }
  return 0;
}

iya_wsfed_resolved *iya_wsfed_resolve(const char *json, const char *base_dir, iya_wsfed_error *err) {
  try {
    auto *box = new ResolvedBox();
    box->resolved = iya::wsfed::ResolveConfig(json ? json : "", base_dir ? base_dir : "");
    return reinterpret_cast<iya_wsfed_resolved *>(box);
  } catch (const std::exception &ex) {
    report_std(err, ex);
    return nullptr;
  }
}

const char *iya_wsfed_resolved_realm(const iya_wsfed_resolved *cfg) {
  return cfg ? reinterpret_cast<const ResolvedBox *>(cfg)->resolved.realm.c_str() : "";
}
const char *iya_wsfed_resolved_reply(const iya_wsfed_resolved *cfg) {
  return cfg ? reinterpret_cast<const ResolvedBox *>(cfg)->resolved.reply_url.c_str() : "";
}
const char *iya_wsfed_resolved_idp_metadata(const iya_wsfed_resolved *cfg) {
  return cfg ? reinterpret_cast<const ResolvedBox *>(cfg)->resolved.idp_metadata.c_str() : "";
}
int iya_wsfed_resolved_clock_skew_ms(const iya_wsfed_resolved *cfg) {
  return cfg ? reinterpret_cast<const ResolvedBox *>(cfg)->resolved.clock_skew_ms : 0;
}
int iya_wsfed_resolved_want_encrypted(const iya_wsfed_resolved *cfg) {
  return cfg && reinterpret_cast<const ResolvedBox *>(cfg)->resolved.want_assertions_encrypted ? 1 : 0;
}
int iya_wsfed_resolved_allow_unsolicited(const iya_wsfed_resolved *cfg) {
  return cfg && reinterpret_cast<const ResolvedBox *>(cfg)->resolved.allow_unsolicited ? 1 : 0;
}
int iya_wsfed_resolved_request_token_type(const iya_wsfed_resolved *cfg) {
  return cfg && reinterpret_cast<const ResolvedBox *>(cfg)->resolved.request_token_type ? 1 : 0;
}
int iya_wsfed_resolved_signals_set(const iya_wsfed_resolved *cfg) {
  return cfg && reinterpret_cast<const ResolvedBox *>(cfg)->resolved.signals_set ? 1 : 0;
}
int iya_wsfed_resolved_signals(const iya_wsfed_resolved *cfg) {
  return cfg && reinterpret_cast<const ResolvedBox *>(cfg)->resolved.signals ? 1 : 0;
}
int iya_wsfed_resolved_has_key(const iya_wsfed_resolved *cfg) {
  return cfg && reinterpret_cast<const ResolvedBox *>(cfg)->resolved.has_private_key ? 1 : 0;
}
const char *iya_wsfed_resolved_idp_ca(const iya_wsfed_resolved *cfg) {
  return cfg ? reinterpret_cast<const ResolvedBox *>(cfg)->resolved.idp_ca.c_str() : "";
}
const char *iya_wsfed_resolved_idp_entity(const iya_wsfed_resolved *cfg) {
  return cfg ? reinterpret_cast<const ResolvedBox *>(cfg)->resolved.idp_entity_id.c_str() : "";
}
void iya_wsfed_resolved_free(iya_wsfed_resolved *cfg) { delete reinterpret_cast<ResolvedBox *>(cfg); }

iya_wsfed_party *iya_wsfed_party_create(const char *json, const char *base_dir, iya_wsfed_error *err) {
  try {
    auto party = iya::wsfed::RelyingParty::Create(json ? json : "", base_dir ? base_dir : "");
    return reinterpret_cast<iya_wsfed_party *>(new PartyBox(std::move(party)));
  } catch (const std::exception &ex) {
    report_std(err, ex);
    return nullptr;
  }
}

const iya_wsfed_resolved *iya_wsfed_party_config(const iya_wsfed_party *party) {
  return party ? reinterpret_cast<const iya_wsfed_resolved *>(&reinterpret_cast<const PartyBox *>(party)->resolved) : nullptr;
}

const char *iya_wsfed_party_idp_entity(const iya_wsfed_party *party) {
  return party ? reinterpret_cast<const PartyBox *>(party)->entity.c_str() : "";
}

const char *iya_wsfed_party_passive(const iya_wsfed_party *party) {
  return party ? reinterpret_cast<const PartyBox *>(party)->passive.c_str() : "";
}

int iya_wsfed_party_offers(const iya_wsfed_party *party, const char *token) {
  if (!party || !token) return 0;
  for (const auto &item : reinterpret_cast<const PartyBox *>(party)->tokens) {
    if (item == token) return 1;
  }
  return 0;
}

int iya_wsfed_party_signing_certs(const iya_wsfed_party *party) {
  return party ? reinterpret_cast<const PartyBox *>(party)->party.SigningCertificateCount() : 0;
}

char *iya_wsfed_party_metadata(const iya_wsfed_party *party) {
  if (!party) return dup_str("");
  return dup_str(reinterpret_cast<const PartyBox *>(party)->party.Metadata());
}

void iya_wsfed_party_free(iya_wsfed_party *party) { delete reinterpret_cast<PartyBox *>(party); }

iya_wsfed_login_request *iya_wsfed_begin_login(iya_wsfed_party *party, const iya_wsfed_login_opts *opts, iya_wsfed_error *err) {
  try {
    iya::wsfed::RelyingParty::LoginOptions options;
    if (opts) {
      if (opts->has_relay && opts->relay) options.relay_state = opts->relay;
      options.force_authn = opts->force_authn != 0;
      if (opts->has_freshness) options.freshness = opts->freshness;
      if (opts->authentication_method) options.authentication_method = opts->authentication_method;
      if (opts->home_realm) options.home_realm = opts->home_realm;
      for (int i = 0; i < opts->param_count; i++) {
        const char *key = opts->param_keys && opts->param_keys[i] ? opts->param_keys[i] : "";
        const char *value = opts->param_values && opts->param_values[i] ? opts->param_values[i] : "";
        options.params.emplace_back(key, value);
      }
    }
    auto *box = new LoginRequestBox();
    box->request = reinterpret_cast<PartyBox *>(party)->party.Login(options);
    return reinterpret_cast<iya_wsfed_login_request *>(box);
  } catch (const std::exception &ex) {
    report_std(err, ex);
    return nullptr;
  }
}

const char *iya_wsfed_login_request_id(const iya_wsfed_login_request *req) {
  return req ? reinterpret_cast<const LoginRequestBox *>(req)->request.id.c_str() : "";
}
const char *iya_wsfed_login_request_url(const iya_wsfed_login_request *req) {
  return req ? reinterpret_cast<const LoginRequestBox *>(req)->request.url.c_str() : "";
}
const char *iya_wsfed_login_request_wctx(const iya_wsfed_login_request *req) {
  return req ? reinterpret_cast<const LoginRequestBox *>(req)->request.wctx.c_str() : "";
}
void iya_wsfed_login_request_free(iya_wsfed_login_request *req) { delete reinterpret_cast<LoginRequestBox *>(req); }

iya_wsfed_login *iya_wsfed_handle_reply(iya_wsfed_party *party, const char *method, const char *url, const char *body,
                                        const char *const *request_ids, int request_id_count, iya_wsfed_error *err) {
  try {
    std::vector<std::string> ids;
    for (int i = 0; i < request_id_count; i++) ids.emplace_back(request_ids && request_ids[i] ? request_ids[i] : "");
    auto *box = new LoginBox();
    box->login = reinterpret_cast<PartyBox *>(party)->party.HandleReply(method ? method : "", url ? url : "", body ? body : "", ids);
    return reinterpret_cast<iya_wsfed_login *>(box);
  } catch (const std::exception &ex) {
    report_std(err, ex);
    return nullptr;
  }
}

const char *iya_wsfed_login_name_id(const iya_wsfed_login *login) {
  return login ? reinterpret_cast<const LoginBox *>(login)->login.name_id.c_str() : "";
}
int iya_wsfed_login_has_format(const iya_wsfed_login *login) {
  return login && reinterpret_cast<const LoginBox *>(login)->login.name_id_format ? 1 : 0;
}
const char *iya_wsfed_login_format(const iya_wsfed_login *login) {
  auto *box = reinterpret_cast<const LoginBox *>(login);
  return box && box->login.name_id_format ? box->login.name_id_format->c_str() : "";
}
int iya_wsfed_login_has_session(const iya_wsfed_login *login) {
  return login && reinterpret_cast<const LoginBox *>(login)->login.session_index ? 1 : 0;
}
const char *iya_wsfed_login_session(const iya_wsfed_login *login) {
  auto *box = reinterpret_cast<const LoginBox *>(login);
  return box && box->login.session_index ? box->login.session_index->c_str() : "";
}
int iya_wsfed_login_has_relay(const iya_wsfed_login *login) {
  return login && reinterpret_cast<const LoginBox *>(login)->login.relay_state ? 1 : 0;
}
const char *iya_wsfed_login_relay(const iya_wsfed_login *login) {
  auto *box = reinterpret_cast<const LoginBox *>(login);
  return box && box->login.relay_state ? box->login.relay_state->c_str() : "";
}
int iya_wsfed_login_has_request(const iya_wsfed_login *login) {
  return login && reinterpret_cast<const LoginBox *>(login)->login.request_id ? 1 : 0;
}
const char *iya_wsfed_login_request_id_of(const iya_wsfed_login *login) {
  auto *box = reinterpret_cast<const LoginBox *>(login);
  return box && box->login.request_id ? box->login.request_id->c_str() : "";
}
const char *iya_wsfed_login_trust(const iya_wsfed_login *login) {
  return login ? reinterpret_cast<const LoginBox *>(login)->login.trust_version.c_str() : "";
}
const char *iya_wsfed_login_realm(const iya_wsfed_login *login) {
  return login ? reinterpret_cast<const LoginBox *>(login)->login.realm.c_str() : "";
}
int iya_wsfed_login_encrypted(const iya_wsfed_login *login) {
  return login && reinterpret_cast<const LoginBox *>(login)->login.encrypted ? 1 : 0;
}
long long iya_wsfed_login_not_on_or_after_ms(const iya_wsfed_login *login) {
  return login ? reinterpret_cast<const LoginBox *>(login)->login.not_on_or_after_ms : 0;
}
int iya_wsfed_login_has_class(const iya_wsfed_login *login) {
  return login && reinterpret_cast<const LoginBox *>(login)->login.authn_context_class_ref ? 1 : 0;
}
const char *iya_wsfed_login_class(const iya_wsfed_login *login) {
  auto *box = reinterpret_cast<const LoginBox *>(login);
  return box && box->login.authn_context_class_ref ? box->login.authn_context_class_ref->c_str() : "";
}
int iya_wsfed_login_attr_count(const iya_wsfed_login *login, const char *name) {
  const auto *attr = attr_of(reinterpret_cast<const LoginBox *>(login), name);
  return attr ? static_cast<int>(attr->values.size()) : 0;
}
const char *iya_wsfed_login_attr_at(const iya_wsfed_login *login, const char *name, int index) {
  const auto *attr = attr_of(reinterpret_cast<const LoginBox *>(login), name);
  if (!attr || index < 0 || index >= static_cast<int>(attr->values.size())) return "";
  return attr->values[static_cast<size_t>(index)].c_str();
}
const char *iya_wsfed_login_friendly(const iya_wsfed_login *login, const char *name) {
  const auto *attr = attr_of(reinterpret_cast<const LoginBox *>(login), name);
  return attr ? attr->friendly_name.c_str() : "";
}
void iya_wsfed_login_free(iya_wsfed_login *login) { delete reinterpret_cast<LoginBox *>(login); }

char *iya_wsfed_logout(iya_wsfed_party *party, const char *reply, iya_wsfed_error *err) {
  try {
    return dup_str(reinterpret_cast<PartyBox *>(party)->party.Logout(reply ? reply : ""));
  } catch (const std::exception &ex) {
    report_std(err, ex);
    return nullptr;
  }
}

int iya_wsfed_is_signout(iya_wsfed_party *party, const char *method, const char *url, const char *body) {
  if (!party) return 0;
  return reinterpret_cast<PartyBox *>(party)->party.IsSignOutCleanup(method ? method : "", url ? url : "", body ? body : "") ? 1 : 0;
}

iya_wsfed_keypair *iya_wsfed_generate_keys(const char *common_name, int days, int bits, iya_wsfed_error *err) {
  try {
    auto *box = new KeyBox();
    box->pair = iya::wsfed::CreateSelfSignedKeyPair(common_name ? common_name : "", days, bits);
    return reinterpret_cast<iya_wsfed_keypair *>(box);
  } catch (const std::exception &ex) {
    report_std(err, ex);
    return nullptr;
  }
}
const char *iya_wsfed_keypair_key(const iya_wsfed_keypair *pair) {
  return pair ? reinterpret_cast<const KeyBox *>(pair)->pair.private_key_pem.c_str() : "";
}
const char *iya_wsfed_keypair_cert(const iya_wsfed_keypair *pair) {
  return pair ? reinterpret_cast<const KeyBox *>(pair)->pair.certificate_pem.c_str() : "";
}
const char *iya_wsfed_keypair_cn(const iya_wsfed_keypair *pair) {
  return pair ? reinterpret_cast<const KeyBox *>(pair)->pair.common_name.c_str() : "";
}
void iya_wsfed_keypair_free(iya_wsfed_keypair *pair) { delete reinterpret_cast<KeyBox *>(pair); }

char *iya_wsfed_sign(const char *xml, const char *element_id, const char *key_pem, const char *cert_pem, iya_wsfed_error *err) {
  try {
    return dup_str(iya::wsfed::SignEnveloped(xml ? xml : "", element_id ? element_id : "", key_pem ? key_pem : "",
                                             cert_pem ? cert_pem : ""));
  } catch (const std::exception &ex) {
    report_std(err, ex);
    return nullptr;
  }
}

int iya_wsfed_cli(int argc, char **argv) { return iya::wsfed::CliMain(argc, argv); }

int iya_wsfed_subject_of(const char *sub_json, const char *issuer, iya_wsfed_subject *out, iya_wsfed_error *err) {
  if (!out) return 1;
  std::memset(out, 0, sizeof *out);
  try {
    auto view = iya::wsfed::SubjectOf(sub_json ? sub_json : "", issuer ? issuer : "");
    if (view.person) {
      out->has_person = 1;
      std::snprintf(out->person, sizeof out->person, "%s", view.person->c_str());
    }
    if (view.email) {
      out->has_email = 1;
      std::snprintf(out->email, sizeof out->email, "%s", view.email->c_str());
    }
    if (view.idp_session) {
      out->has_idp_session = 1;
      std::snprintf(out->idp_session, sizeof out->idp_session, "%s", view.idp_session->c_str());
    }
    return 0;
  } catch (const std::exception &ex) {
    return report_std(err, ex);
  }
}

char *iya_wsfed_jws_verify(const char *token, const char *keys_json, iya_wsfed_error *err) {
  try {
    auto verified = iya::wsfed::VerifyCompactJws(token ? token : "", keys_json ? keys_json : "");
    return dup_str(verified.payload_json);
  } catch (const std::exception &ex) {
    report_std(err, ex);
    return nullptr;
  }
}

iya_wsfed_receiver *iya_wsfed_receiver_new(const char *transmitter, iya_wsfed_end_fn on_end, void *user, int poll_interval_ms,
                                           iya_wsfed_log_fn log, void *log_user, iya_wsfed_error *err) {
  try {
    iya::wsfed::SignalsReceiver::Options options;
    options.poll_interval_ms = poll_interval_ms;
    if (log) {
      options.log = [log, log_user](const std::string &level, const std::string &message) {
        log(level.c_str(), message.c_str(), log_user);
      };
    }
    auto end = [on_end, user](const std::vector<std::string> &ids, const iya::wsfed::SignalEvent &event) {
      (void)ids;
      iya_wsfed_event view;
      std::vector<const char *> sessions;
      fill_event(event, &view, sessions);
      char message[1024];
      message[0] = '\0';
      if (on_end && on_end(&view, user, message, sizeof message) != 0) {
        throw std::runtime_error(message[0] ? message : "onEndSessions failed");
      }
    };
    auto *box = new ReceiverBox(transmitter ? transmitter : "", end, options);
    return reinterpret_cast<iya_wsfed_receiver *>(box);
  } catch (const std::exception &ex) {
    report_std(err, ex);
    return nullptr;
  }
}

int iya_wsfed_receiver_start(iya_wsfed_receiver *receiver, iya_wsfed_error *err) {
  try {
    reinterpret_cast<ReceiverBox *>(receiver)->receiver.Start();
    return 0;
  } catch (const std::exception &ex) {
    return report_std(err, ex);
  }
}

void iya_wsfed_receiver_stop(iya_wsfed_receiver *receiver) {
  if (receiver) reinterpret_cast<ReceiverBox *>(receiver)->receiver.Stop();
}

int iya_wsfed_receiver_poll(iya_wsfed_receiver *receiver, int *more, iya_wsfed_error *err) {
  try {
    bool again = reinterpret_cast<ReceiverBox *>(receiver)->receiver.PollOnce();
    if (more) *more = again ? 1 : 0;
    return 0;
  } catch (const std::exception &ex) {
    return report_std(err, ex);
  }
}

void iya_wsfed_receiver_on(iya_wsfed_receiver *receiver, const char *event_type, iya_wsfed_handler_fn handler, void *user) {
  if (!receiver || !handler) return;
  std::string type = event_type ? event_type : "";
  reinterpret_cast<ReceiverBox *>(receiver)->receiver.On(
      type, [handler, user](const iya::wsfed::SignalEvent &event) {
        iya_wsfed_event view;
        std::vector<const char *> sessions;
        fill_event(event, &view, sessions);
        char message[1024];
        message[0] = '\0';
        if (handler(&view, user, message, sizeof message) != 0) {
          throw std::runtime_error(message[0] ? message : "handler failed");
        }
      });
}

void iya_wsfed_receiver_track(iya_wsfed_receiver *receiver, const char *local_id, const char *name_id,
                              const char *name_id_format, const char *session_index, const char *subject_value,
                              const char *email) {
  if (!receiver) return;
  reinterpret_cast<ReceiverBox *>(receiver)->receiver.Track(local_id ? local_id : "", name_id ? name_id : "",
                                                            name_id_format ? name_id_format : "",
                                                            session_index ? session_index : "",
                                                            subject_value ? subject_value : "", email ? email : "");
}

int iya_wsfed_receiver_person_count(iya_wsfed_receiver *receiver, const char *person) {
  if (!receiver) return 0;
  auto *box = reinterpret_cast<ReceiverBox *>(receiver);
  box->person = person ? person : "";
  box->people = box->receiver.SessionsByPerson(box->person);
  return static_cast<int>(box->people.size());
}

const char *iya_wsfed_receiver_person_id(iya_wsfed_receiver *receiver, const char *person, int index) {
  if (!receiver) return "";
  auto *box = reinterpret_cast<ReceiverBox *>(receiver);
  std::string wanted = person ? person : "";
  if (box->person != wanted) {
    box->person = wanted;
    box->people = box->receiver.SessionsByPerson(wanted);
  }
  if (index < 0 || index >= static_cast<int>(box->people.size())) return "";
  return box->people[static_cast<size_t>(index)].c_str();
}

const char *iya_wsfed_receiver_stream_id(iya_wsfed_receiver *receiver) {
  if (!receiver) return "";
  auto *box = reinterpret_cast<ReceiverBox *>(receiver);
  box->stream_id = box->receiver.StreamId();
  return box->stream_id.c_str();
}

void iya_wsfed_receiver_free(iya_wsfed_receiver *receiver) { delete reinterpret_cast<ReceiverBox *>(receiver); }

iya_http_server *iya_http_serve(iya_http_handler_fn handler, void *user, int *port) {
  try {
    auto *box = new ServerBox(
        [handler, user](const std::string &method, const std::string &target,
                        const std::vector<std::pair<std::string, std::string>> &, const std::string &body) {
          int status = 200;
          char *owned = nullptr;
          if (handler) handler(method.c_str(), target.c_str(), body.c_str(), user, &status, &owned);
          iya::wsfed::HttpResponse response;
          response.status = status;
          if (owned) {
            response.body = owned;
            std::free(owned);
          }
          response.headers.push_back({"content-type", "application/json"});
          return response;
        },
        port);
    return reinterpret_cast<iya_http_server *>(box);
  } catch (const std::exception &ex) {
    report_std(nullptr, ex);
    return nullptr;
  }
}

void iya_http_server_close(iya_http_server *server) {
  if (!server) return;
  reinterpret_cast<ServerBox *>(server)->server.Close();
  delete reinterpret_cast<ServerBox *>(server);
}

iya_http_response *iya_http_call(const char *method, const char *url, const char *content_type, const char *body,
                                 const char *cookie, iya_wsfed_error *err) {
  try {
    auto *box = new ResponseBox();
    box->response = iya::wsfed::HttpRequest(method ? method : "GET", url ? url : "", content_type ? content_type : "",
                                            body ? body : "", cookie ? cookie : "");
    return reinterpret_cast<iya_http_response *>(box);
  } catch (const std::exception &ex) {
    report_std(err, ex);
    return nullptr;
  }
}

int iya_http_status(const iya_http_response *response) {
  return response ? reinterpret_cast<const ResponseBox *>(response)->response.status : 0;
}
const char *iya_http_body(const iya_http_response *response) {
  return response ? reinterpret_cast<const ResponseBox *>(response)->response.body.c_str() : "";
}
int iya_http_header_count(const iya_http_response *response, const char *name) {
  if (!response) return 0;
  int count = 0;
  for (const auto &header : reinterpret_cast<const ResponseBox *>(response)->response.headers) {
    if (ieq(header.first, name)) count++;
  }
  return count;
}
const char *iya_http_header_at(const iya_http_response *response, const char *name, int index) {
  if (!response || index < 0) return "";
  int seen = 0;
  for (const auto &header : reinterpret_cast<const ResponseBox *>(response)->response.headers) {
    if (!ieq(header.first, name)) continue;
    if (seen == index) return header.second.c_str();
    seen++;
  }
  return "";
}
void iya_http_response_free(iya_http_response *response) { delete reinterpret_cast<ResponseBox *>(response); }

void iya_wsfed_string_free(char *value) { std::free(value); }

}  // extern "C"
