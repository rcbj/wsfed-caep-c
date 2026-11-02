// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "detail.hpp"

namespace iya::wsfed {
namespace {

std::string ns_of(xmlNodePtr el) {
  std::string uri = node_ns(el);
  if (uri.empty()) return "no namespace";
  return uri;
}

struct ResponseOf {
  xmlNodePtr rstr = nullptr;
  std::string trust;
  std::string version;
};

ResponseOf response_of(xmlNodePtr root) {
  ResponseOf out;
  if (is_el(root, NS_TRUST13, "RequestSecurityTokenResponseCollection")) {
    auto all = children(root, NS_TRUST13, "RequestSecurityTokenResponse");
    if (all.size() != 1) {
      fail("message", "the RequestSecurityTokenResponseCollection holds " + itoa_i(static_cast<long long>(all.size())) +
                          " responses; exactly one is accepted");
    }
    out.rstr = all[0];
    out.trust = NS_TRUST13;
    out.version = "1.3";
    return out;
  }
  if (is_el(root, NS_TRUST2005, "RequestSecurityTokenResponse")) {
    out.rstr = root;
    out.trust = NS_TRUST2005;
    out.version = "2005/02";
    return out;
  }
  if (is_el(root, NS_TRUST13, "RequestSecurityTokenResponse")) {
    out.rstr = root;
    out.trust = NS_TRUST13;
    out.version = "1.3";
    return out;
  }
  std::string tag = root && root->name ? reinterpret_cast<const char *>(root->name) : "";
  fail("message", "wresult is a <" + tag + "> in " + ns_of(root) + ", not a WS-Trust RequestSecurityTokenResponse");
}

bool attr_instant(xmlNodePtr el, const char *name, const std::string &what, bool &present, int64_t &ms) {
  present = false;
  if (!el) return false;
  std::string value;
  if (!attr(el, name, value)) return false;
  present = true;
  return parse_instant(value, what, ms);
}

void add_values(RelyingParty::LoginResult &login, const std::string &name, const std::vector<std::string> &values,
                const std::string &friendly) {
  for (auto &attr : login.attributes) {
    if (attr.name == name) {
      attr.values.insert(attr.values.end(), values.begin(), values.end());
      if (!friendly.empty()) attr.friendly_name = friendly;
      return;
    }
  }
  RelyingParty::Attribute item;
  item.name = name;
  item.values = values;
  item.friendly_name = friendly;
  login.attributes.push_back(std::move(item));
}

}  // namespace

RelyingParty::LoginResult validate_token(const std::string &wresult, TokenIn ctx) {
  int64_t now = now_ms();
  int64_t skew = ctx.clock_skew_ms;
  Xml doc = parse_xml(wresult, "wresult");
  assert_unique_ids(doc.root());
  ResponseOf response = response_of(doc.root());
  xmlNodePtr token_type_el = one_child(response.rstr, response.trust.c_str(), "TokenType");
  std::string token_type = text_of(token_type_el);
  if (!token_type.empty() && token_type != NS_SAML &&
      token_type != "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0") {
    fail("message", "the response carries a token of type " + token_type + "; this relying party accepts SAML 2.0 assertions only");
  }
  auto applies = children(response.rstr, NS_WSP, "AppliesTo");
  auto applies15 = children(response.rstr, NS_WSP15, "AppliesTo");
  applies.insert(applies.end(), applies15.begin(), applies15.end());
  if (applies.size() > 1) fail("message", "the response has more than one AppliesTo");
  if (applies.size() == 1) {
    auto scopes = wsa_addresses(applies[0]);
    if (!scopes.empty()) {
      bool found = false;
      for (const auto &scope : scopes) {
        if (scope == ctx.realm) found = true;
      }
      if (!found) {
        std::string joined;
        for (size_t i = 0; i < scopes.size(); i++) {
          if (i) joined += ", ";
          joined += scopes[i];
        }
        fail("validation", "the response applies to " + joined + ", not to " + ctx.realm);
      }
    }
  }
  xmlNodePtr lifetime = one_child(response.rstr, response.trust.c_str(), "Lifetime");
  bool has_expires = false;
  int64_t expires_ms = 0;
  if (lifetime) {
    auto expires_nodes = children(lifetime, NS_WSU, "Expires");
    std::string raw = expires_nodes.empty() ? "" : text_of(expires_nodes[0]);
    if (!raw.empty()) {
      has_expires = parse_instant(raw, "the response's Lifetime Expires", expires_ms);
    }
  }
  if (has_expires && expires_ms <= now - skew) fail("validation", "the response expired at " + iso_time(expires_ms));
  auto requested = children(response.rstr, response.trust.c_str(), "RequestedSecurityToken");
  if (requested.size() != 1) {
    fail("message", "the response holds " + itoa_i(static_cast<long long>(requested.size())) +
                        " RequestedSecurityToken elements; exactly one is accepted");
  }
  auto tokens = element_children(requested[0]);
  if (tokens.size() != 1) {
    fail("message", "the RequestedSecurityToken holds " + itoa_i(static_cast<long long>(tokens.size())) +
                        " tokens; exactly one is accepted");
  }
  xmlNodePtr token = tokens[0];
  bool encrypted = false;
  std::string assertion_xml;
  xmlNodePtr assertion = nullptr;
  Xml decrypted_doc;
  if (is_el(token, NS_SAML, "Assertion")) {
    if (ctx.want_encrypted) fail("validation", "the assertion is not encrypted, and wantAssertionsEncrypted is on");
    assertion = token;
  } else if (is_el(token, NS_SAML, "EncryptedAssertion") || is_el(token, NS_XENC, "EncryptedData")) {
    if (!ctx.decryption_key) {
      fail("decryption", "the assertion is encrypted, and this relying party has no privateKey to decrypt it with");
    }
    encrypted = true;
    std::string plain = decrypt_element(token, ctx.decryption_key->key);
    decrypted_doc = parse_xml(plain, "the decrypted assertion");
    assert_unique_ids(decrypted_doc.root());
    assertion = decrypted_doc.root();
    if (is_el(assertion, NS_SAML1, "Assertion")) {
      fail("message", "the encrypted token is a SAML 1.1 assertion; this relying party accepts SAML 2.0 assertions only");
    }
    if (!is_el(assertion, NS_SAML, "Assertion")) fail("validation", "the encrypted token does not hold a SAML 2.0 Assertion");
  } else if (is_el(token, NS_SAML1, "Assertion")) {
    fail("message",
         "the token is a SAML 1.1 assertion; this relying party accepts SAML 2.0 assertions only. Ask for SAML 2.0 "
         "(requestTokenType, the default), or configure the identity provider to issue it to this realm");
  } else {
    std::string tag = token && token->name ? reinterpret_cast<const char *>(token->name) : "";
    fail("message", "the RequestedSecurityToken holds a <" + tag + ">, not a SAML 2.0 assertion");
  }
  std::string signed_xml = verify_signed(assertion, ctx.certs, "the assertion");
  if (signed_xml.empty()) {
    fail("validation", "the assertion is not signed; in WS-Federation its signature is the only one, so it is required");
  }
  Xml signed_doc = parse_xml(signed_xml, "the signed assertion");
  assertion = signed_doc.root();
  if (attr_or(assertion, "Version") != "2.0") fail("validation", "the assertion is not version 2.0");
  std::string assertion_id = attr_or(assertion, "ID");
  if (assertion_id.empty()) fail("validation", "the assertion has no ID");
  xmlNodePtr issuer = one_child(assertion, NS_SAML, "Issuer");
  if (!issuer) fail("validation", "the assertion has no Issuer");
  std::string format = attr_or(issuer, "Format");
  if (!format.empty() && format != "urn:oasis:names:tc:SAML:2.0:nameid-format:entity") {
    fail("validation", "the assertion's Issuer has the Format " + format);
  }
  if (text_of(issuer) != ctx.idp_entity) {
    fail("validation", "the assertion was issued by " + text_of(issuer) + ", not by " + ctx.idp_entity);
  }
  xmlNodePtr subject = one_child(assertion, NS_SAML, "Subject");
  if (!subject) fail("validation", "the assertion has no Subject");
  xmlNodePtr name_id = one_child(subject, NS_SAML, "NameID");
  xmlNodePtr encrypted_id = one_child(subject, NS_SAML, "EncryptedID");
  Xml name_doc;
  if (!name_id && encrypted_id) {
    if (!ctx.decryption_key) {
      fail("decryption", "the NameID is encrypted, and this relying party has no privateKey to decrypt it with");
    }
    std::string plain = decrypt_element(encrypted_id, ctx.decryption_key->key);
    name_doc = parse_xml(plain, "the decrypted NameID");
    name_id = name_doc.root();
    if (!is_el(name_id, NS_SAML, "NameID")) fail("validation", "the EncryptedID does not hold a NameID");
  }
  if (!name_id || text_of(name_id).empty()) fail("validation", "the assertion's Subject has no NameID");
  xmlNodePtr conditions = one_child(assertion, NS_SAML, "Conditions");
  if (!conditions) fail("validation", "the assertion has no Conditions, so it names no audience");
  bool has_not_before = false, has_not_on = false;
  int64_t not_before_ms = 0, not_on_ms = 0;
  if (attr(conditions, "NotBefore", format)) {
    has_not_before = true;
    parse_instant(attr_or(conditions, "NotBefore"), "Conditions NotBefore", not_before_ms);
  }
  if (attr(conditions, "NotOnOrAfter", format)) {
    has_not_on = true;
    parse_instant(attr_or(conditions, "NotOnOrAfter"), "Conditions NotOnOrAfter", not_on_ms);
  }
  (void)format;
  std::vector<std::string> reasons;
  bool confirmed = false;
  int64_t confirmed_until = 0;
  for (xmlNodePtr confirmation : children(subject, NS_SAML, "SubjectConfirmation")) {
    std::string method = attr_or(confirmation, "Method");
    if (method != "urn:oasis:names:tc:SAML:2.0:cm:bearer") {
      reasons.push_back("method " + method);
      continue;
    }
    xmlNodePtr data = one_child(confirmation, NS_SAML, "SubjectConfirmationData");
    if (!data) {
      if (!has_not_on) {
        reasons.push_back("no SubjectConfirmationData, and no Conditions NotOnOrAfter to bound it");
        continue;
      }
      confirmed = true;
      confirmed_until = not_on_ms;
      break;
    }
    std::string recipient;
    bool has_recipient = attr(data, "Recipient", recipient);
    bool has_until = false;
    int64_t until_ms = 0;
    std::string until_raw;
    if (attr(data, "NotOnOrAfter", until_raw)) {
      has_until = true;
      parse_instant(until_raw, "SubjectConfirmationData NotOnOrAfter", until_ms);
    }
    if (!has_until) {
      if (has_not_on) {
        has_until = true;
        until_ms = not_on_ms;
      }
    }
    std::string not_before_attr;
    bool has_nb = attr(data, "NotBefore", not_before_attr);
    std::string irt;
    bool has_irt = attr(data, "InResponseTo", irt);
    if (has_recipient && recipient != ctx.reply_url) {
      reasons.push_back("Recipient " + recipient);
    } else if (!has_until) {
      reasons.push_back("no NotOnOrAfter, on the confirmation or the Conditions");
    } else if (until_ms <= now - skew) {
      reasons.push_back("expired at " + iso_time(until_ms));
    } else if (has_nb) {
      reasons.push_back("a NotBefore, which a bearer confirmation must not have");
    } else if (has_irt) {
      reasons.push_back("InResponseTo " + irt + ", which answers a SAML request, not a WS-Federation sign-in");
    } else {
      confirmed = true;
      confirmed_until = until_ms;
      break;
    }
  }
  if (!confirmed) {
    std::string why;
    for (size_t i = 0; i < reasons.size(); i++) {
      if (i) why += "; ";
      why += reasons[i];
    }
    if (why.empty()) why = "there is none";
    fail("validation", "no bearer SubjectConfirmation of the assertion fits: " + why);
  }
  if (has_not_before && not_before_ms > now + skew) {
    fail("validation", "the assertion is not valid before " + iso_time(not_before_ms));
  }
  if (has_not_on && not_on_ms <= now - skew) fail("validation", "the assertion expired at " + iso_time(not_on_ms));
  auto restrictions = children(conditions, NS_SAML, "AudienceRestriction");
  if (restrictions.empty()) fail("validation", "the assertion has no AudienceRestriction");
  for (xmlNodePtr restriction : restrictions) {
    bool ok = false;
    for (xmlNodePtr audience : children(restriction, NS_SAML, "Audience")) {
      if (text_of(audience) == ctx.realm) ok = true;
    }
    if (!ok) fail("validation", "the assertion is not for " + ctx.realm);
  }
  auto authn_all = children(assertion, NS_SAML, "AuthnStatement");
  if (authn_all.empty()) fail("validation", "the assertion has no AuthnStatement");
  xmlNodePtr authn = authn_all[0];
  std::string instant_raw;
  if (!attr(authn, "AuthnInstant", instant_raw) || instant_raw.empty()) fail("validation", "the AuthnStatement has no AuthnInstant");
  int64_t authn_ms = 0;
  parse_instant(instant_raw, "AuthnInstant", authn_ms);
  std::string session_not_raw;
  bool has_session_not = attr(authn, "SessionNotOnOrAfter", session_not_raw) && !session_not_raw.empty();
  int64_t session_not_ms = 0;
  if (has_session_not) {
    parse_instant(session_not_raw, "SessionNotOnOrAfter", session_not_ms);
    if (session_not_ms <= now - skew) fail("validation", "the identity provider's session has already ended");
  }
  xmlNodePtr context_el = one_child(authn, NS_SAML, "AuthnContext");
  std::string class_ref;
  if (context_el) {
    auto refs = children(context_el, NS_SAML, "AuthnContextClassRef");
    if (!refs.empty()) class_ref = text_of(refs[0]);
  }
  RelyingParty::LoginResult login;
  for (xmlNodePtr statement : children(assertion, NS_SAML, "AttributeStatement")) {
    std::vector<xmlNodePtr> decrypted;
    std::vector<Xml> held;
    for (xmlNodePtr encrypted_attr : children(statement, NS_SAML, "EncryptedAttribute")) {
      if (!ctx.decryption_key) {
        fail("decryption", "an attribute is encrypted, and this relying party has no privateKey to decrypt it with");
      }
      std::string plain = decrypt_element(encrypted_attr, ctx.decryption_key->key);
      held.push_back(parse_xml(plain, "the decrypted attribute"));
      xmlNodePtr element = held.back().root();
      if (!is_el(element, NS_SAML, "Attribute")) fail("validation", "an EncryptedAttribute does not hold an Attribute");
      decrypted.push_back(element);
    }
    auto attrs = children(statement, NS_SAML, "Attribute");
    attrs.insert(attrs.end(), decrypted.begin(), decrypted.end());
    for (xmlNodePtr attribute : attrs) {
      std::string name = attr_or(attribute, "Name");
      if (name.empty()) continue;
      std::vector<std::string> values;
      for (xmlNodePtr value : children(attribute, NS_SAML, "AttributeValue")) values.push_back(text_content(value));
      add_values(login, name, values, attr_or(attribute, "FriendlyName"));
    }
  }
  int64_t keep = confirmed_until;
  if (has_not_on && not_on_ms > keep) keep = not_on_ms;
  keep += skew;
  std::string replay_id = ctx.idp_entity + " " + assertion_id;
  ReplayCache local(0);
  ReplayCache *cache = ctx.replay ? ctx.replay : &local;
  bool recorded = false;
  try {
    recorded = cache->check_and_record(replay_id, keep);
  } catch (const failure &ex) {
    if (ex.code == "replay") throw;
    fail("replay", ex.what());
  }
  if (recorded) fail("replay", "the assertion " + assertion_id + " has been accepted before");
  login.name_id = text_of(name_id);
  login.authn_instant_ms = authn_ms;
  login.issuer = ctx.idp_entity;
  login.realm = ctx.realm;
  login.trust_version = response.version;
  login.encrypted = encrypted;
  login.assertion_id = assertion_id;
  login.not_on_or_after_ms = confirmed_until;
  std::string name_format = attr_or(name_id, "Format");
  if (!name_format.empty()) login.name_id_format = name_format;
  std::string nq = attr_or(name_id, "NameQualifier");
  if (!nq.empty()) login.name_qualifier = nq;
  std::string spq = attr_or(name_id, "SPNameQualifier");
  if (!spq.empty()) login.sp_name_qualifier = spq;
  std::string session = attr_or(authn, "SessionIndex");
  if (!session.empty()) login.session_index = session;
  if (!class_ref.empty()) login.authn_context_class_ref = class_ref;
  return login;
}

}  // namespace iya::wsfed
