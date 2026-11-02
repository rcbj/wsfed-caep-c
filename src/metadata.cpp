// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "detail.hpp"

namespace iya::wsfed {
namespace {

bool is_saml2_token(const std::string &value) { return value == NS_SAML || value == "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0"; }

bool is_sts_role(xmlNodePtr el) {
  if (!is_el(el, NS_MD, "RoleDescriptor")) return false;
  std::string ns, local;
  bool ok = false;
  xsi_type(el, ns, local, ok);
  return ok && ns == NS_FED && local == "SecurityTokenServiceType";
}

std::vector<std::shared_ptr<Cert>> certificates_of(xmlNodePtr role, const std::string &use) {
  std::vector<std::shared_ptr<Cert>> out;
  for (xmlNodePtr descriptor : children(role, NS_MD, "KeyDescriptor")) {
    std::string declared;
    bool has = attr(descriptor, "use", declared);
    if (has && !declared.empty() && declared != use) continue;
    std::vector<xmlNodePtr> datas;
    descendants(descriptor, NS_DS, "X509Data", datas);
    for (xmlNodePtr data : datas) {
      auto first = children(data, NS_DS, "X509Certificate");
      if (first.empty()) continue;
      try {
        out.push_back(load_certificate(to_pem(text_of(first[0]))));
      } catch (const failure &ex) {
        fail("metadata", "a " + use + " certificate in the identity provider's metadata cannot be read");
      }
    }
  }
  return out;
}

std::vector<std::string> fed_addresses(xmlNodePtr role, const char *local) {
  std::vector<std::string> out;
  for (xmlNodePtr endpoint : children(role, NS_FED, local)) {
    for (const auto &addr : wsa_addresses(endpoint)) out.push_back(addr);
  }
  return out;
}

bool has_sts(xmlNodePtr element) {
  for (xmlNodePtr role : children(element, NS_MD, "RoleDescriptor")) {
    if (is_sts_role(role)) return true;
  }
  return false;
}

bool http_endpoint(const std::string &endpoint) {
  if (endpoint.compare(0, 8, "https://") != 0 && endpoint.compare(0, 7, "http://") != 0) return false;
  std::string rest = endpoint.compare(0, 8, "https://") == 0 ? endpoint.substr(8) : endpoint.substr(7);
  if (rest.empty() || rest[0] == '/') return false;
  auto slash = rest.find('/');
  std::string host = slash == std::string::npos ? rest : rest.substr(0, slash);
  return !host.empty();
}

}  // namespace

IdpInfo read_idp_metadata(const std::string &xml, const std::string &entity_id) {
  Xml doc = parse_xml(xml, "the identity provider metadata");
  xmlNodePtr root = doc.root();
  xmlNodePtr entity = nullptr;
  if (is_el(root, NS_MD, "EntityDescriptor")) {
    entity = root;
  } else if (is_el(root, NS_MD, "EntitiesDescriptor")) {
    std::vector<xmlNodePtr> all_nodes;
    descendants(root, NS_MD, "EntityDescriptor", all_nodes);
    std::vector<xmlNodePtr> all;
    for (xmlNodePtr item : all_nodes) {
      if (has_sts(item)) all.push_back(item);
    }
    if (!entity_id.empty()) {
      for (xmlNodePtr item : all) {
        if (attr_or(item, "entityID") == entity_id) {
          entity = item;
          break;
        }
      }
    } else if (all.size() == 1) {
      entity = all[0];
    }
    if (!entity) {
      if (!entity_id.empty()) fail("metadata", "the metadata aggregate has no WS-Federation identity provider " + entity_id);
      fail("metadata", "the metadata aggregate holds " + itoa_i(static_cast<long long>(all.size())) +
                           " WS-Federation identity providers; name one with idpEntityId");
    }
  } else {
    fail("metadata", "the identity provider metadata is not an EntityDescriptor");
  }
  std::string identifier = attr_or(entity, "entityID");
  if (identifier.empty()) fail("metadata", "the identity provider metadata has no entityID");
  if (!entity_id.empty() && identifier != entity_id) {
    fail("metadata", "the metadata describes " + identifier + ", not " + entity_id);
  }
  xmlNodePtr role = nullptr;
  for (xmlNodePtr item : children(entity, NS_MD, "RoleDescriptor")) {
    if (is_sts_role(item)) {
      role = item;
      break;
    }
  }
  if (!role) {
    fail("metadata", identifier + "'s metadata has no fed:SecurityTokenServiceType RoleDescriptor, so it is not a WS-Federation identity provider");
  }
  auto passive = fed_addresses(role, "PassiveRequestorEndpoint");
  if (passive.empty()) fail("metadata", identifier + "'s metadata names no PassiveRequestorEndpoint");
  if (!http_endpoint(passive[0])) {
    fail("metadata", identifier + "'s PassiveRequestorEndpoint " + passive[0] + " is not an http(s) URL");
  }
  std::vector<std::string> offered;
  for (xmlNodePtr types : children(role, NS_FED, "TokenTypesOffered")) {
    for (xmlNodePtr token : children(types, NS_FED, "TokenType")) {
      std::string uri = attr_or(token, "Uri");
      if (!uri.empty()) offered.push_back(uri);
    }
  }
  if (!offered.empty()) {
    bool ok = false;
    for (const auto &token : offered) {
      if (is_saml2_token(token)) ok = true;
    }
    if (!ok) {
      std::string joined;
      for (size_t i = 0; i < offered.size(); i++) {
        if (i) joined += ", ";
        joined += offered[i];
      }
      fail("metadata", identifier + " offers no SAML 2.0 token (it offers " + joined + ")");
    }
  }
  auto signing = certificates_of(role, "signing");
  if (signing.empty()) {
    auto idp = children(entity, NS_MD, "IDPSSODescriptor");
    if (!idp.empty()) signing = certificates_of(idp[0], "signing");
  }
  if (signing.empty()) fail("metadata", identifier + "'s metadata names no signing certificate");
  IdpInfo info;
  info.entity_id = identifier;
  info.passive = passive[0];
  info.token_types = offered;
  info.certs = std::move(signing);
  return info;
}

std::string write_rp_metadata(const std::string &realm, const std::string &reply, const std::string &cert_pem) {
  static const char *methods[] = {
      "http://www.w3.org/2009/xmlenc11#aes256-gcm",
      "http://www.w3.org/2009/xmlenc11#aes128-gcm",
      "http://www.w3.org/2009/xmlenc11#rsa-oaep",
      "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
  };
  std::string key;
  if (!cert_pem.empty()) {
    std::string method_xml;
    for (const char *method : methods) method_xml += "\n      <md:EncryptionMethod Algorithm=\"" + std::string(method) + "\"/>";
    key = "    <md:KeyDescriptor use=\"encryption\">\n      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>" + pem_body(cert_pem) +
          "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>" + method_xml + "\n    </md:KeyDescriptor>\n";
  }
  auto endpoint = [](const std::string &local, const std::string &address) {
    return "    <fed:" + local + "><wsa:EndpointReference><wsa:Address>" + escape_xml(address) +
           "</wsa:Address></wsa:EndpointReference></fed:" + local + ">";
  };
  return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
         "<md:EntityDescriptor xmlns:md=\"" +
         std::string(NS_MD) + "\" xmlns:ds=\"" + NS_DS + "\" xmlns:fed=\"" + NS_FED + "\" xmlns:wsa=\"" + NS_WSA +
         "\" xmlns:xsi=\"" + NS_XSI + "\" entityID=\"" + escape_xml(realm) + "\">\n"
         "  <md:RoleDescriptor xsi:type=\"fed:ApplicationServiceType\" protocolSupportEnumeration=\"" +
         std::string(NS_FED) + "\">\n" + key +
         "    <fed:TokenTypesOffered><fed:TokenType Uri=\"" + std::string(NS_SAML) + "\"/></fed:TokenTypesOffered>\n"
         "    <fed:TargetScopes><wsa:EndpointReference><wsa:Address>" +
         escape_xml(realm) + "</wsa:Address></wsa:EndpointReference></fed:TargetScopes>\n" +
         endpoint("ApplicationServiceEndpoint", reply) + "\n" + endpoint("SingleSignOutNotificationEndpoint", reply) + "\n" +
         endpoint("PassiveRequestorEndpoint", reply) + "\n"
         "  </md:RoleDescriptor>\n"
         "</md:EntityDescriptor>\n";
}

}  // namespace iya::wsfed
