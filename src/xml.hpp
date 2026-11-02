// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#pragma once

#include "b64.hpp"

#include <libxml/c14n.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include <cctype>
#include <cstring>
#include <functional>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace iya::wsfed {

inline constexpr const char *NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
inline constexpr const char *NS_SAML1 = "urn:oasis:names:tc:SAML:1.0:assertion";
inline constexpr const char *NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata";
inline constexpr const char *NS_DS = "http://www.w3.org/2000/09/xmldsig#";
inline constexpr const char *NS_XENC = "http://www.w3.org/2001/04/xmlenc#";
inline constexpr const char *NS_XENC11 = "http://www.w3.org/2009/xmlenc11#";
inline constexpr const char *NS_XSI = "http://www.w3.org/2001/XMLSchema-instance";
inline constexpr const char *NS_FED = "http://docs.oasis-open.org/wsfed/federation/200706";
inline constexpr const char *NS_TRUST2005 = "http://schemas.xmlsoap.org/ws/2005/02/trust";
inline constexpr const char *NS_TRUST13 = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
inline constexpr const char *NS_WSA = "http://www.w3.org/2005/08/addressing";
inline constexpr const char *NS_WSA2004 = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
inline constexpr const char *NS_WSP = "http://schemas.xmlsoap.org/ws/2004/09/policy";
inline constexpr const char *NS_WSP15 = "http://www.w3.org/ns/ws-policy";
inline constexpr const char *NS_WSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
inline constexpr const char *EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
inline constexpr const char *EXC_C14N_COMMENTS = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
inline constexpr const char *C14N10 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
inline constexpr const char *C14N10_COMMENTS = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
inline constexpr const char *ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

inline void xml_ignore_error(void *, const char *, ...) {}

inline void xml_init() {
  static std::once_flag once;
  std::call_once(once, [] {
    xmlInitParser();
    xmlSetGenericErrorFunc(nullptr, xml_ignore_error);
  });
}

inline bool contains_doctype(const std::string &text) {
  std::string lower;
  lower.reserve(text.size());
  for (unsigned char c : text) lower.push_back(static_cast<char>(std::tolower(c)));
  return lower.find("<!doctype") != std::string::npos || lower.find("<!entity") != std::string::npos;
}

struct Xml {
  xmlDocPtr doc = nullptr;
  explicit Xml(xmlDocPtr d = nullptr) : doc(d) {}
  ~Xml() {
    if (doc) xmlFreeDoc(doc);
  }
  Xml(const Xml &) = delete;
  Xml &operator=(const Xml &) = delete;
  Xml(Xml &&o) noexcept : doc(o.doc) { o.doc = nullptr; }
  Xml &operator=(Xml &&o) noexcept {
    if (this != &o) {
      if (doc) xmlFreeDoc(doc);
      doc = o.doc;
      o.doc = nullptr;
    }
    return *this;
  }
  xmlNodePtr root() const { return doc ? xmlDocGetRootElement(doc) : nullptr; }
};

inline Xml parse_xml(const std::string &text, const std::string &what) {
  xml_init();
  if (contains_doctype(text)) {
    fail("xml", what + " carries a DOCTYPE or an entity declaration, which WS-Federation never needs");
  }
  xmlDocPtr doc = xmlReadMemory(text.data(), static_cast<int>(text.size()), "wsfed.xml", "UTF-8",
                                XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING | XML_PARSE_NOCDATA);
  if (!doc || !xmlDocGetRootElement(doc)) {
    xmlErrorPtr err = xmlGetLastError();
    std::string detail = err && err->message ? err->message : "no document element";
    while (!detail.empty() && (detail.back() == '\n' || detail.back() == '\r')) detail.pop_back();
    if (doc) xmlFreeDoc(doc);
    fail("xml", what + " is not well-formed XML: " + detail);
  }
  return Xml(doc);
}

inline std::string node_ns(xmlNodePtr el) {
  if (!el || !el->ns || !el->ns->href) return "";
  return reinterpret_cast<const char *>(el->ns->href);
}

inline bool is_el(xmlNodePtr el, const char *ns, const char *local) {
  if (!el || el->type != XML_ELEMENT_NODE || !el->name) return false;
  if (std::strcmp(reinterpret_cast<const char *>(el->name), local) != 0) return false;
  return node_ns(el) == ns;
}

inline std::string attr_value(xmlAttrPtr a) {
  if (!a) return "";
  xmlChar *v = xmlNodeListGetString(a->doc, a->children, 1);
  if (!v) return "";
  std::string out(reinterpret_cast<char *>(v));
  xmlFree(v);
  return out;
}

inline bool attr(xmlNodePtr el, const char *name, std::string &out) {
  out.clear();
  if (!el) return false;
  for (xmlAttrPtr a = el->properties; a; a = a->next) {
    if (a->ns) continue;
    if (a->name && std::strcmp(reinterpret_cast<const char *>(a->name), name) == 0) {
      out = attr_value(a);
      return true;
    }
  }
  return false;
}

inline std::string attr_or(xmlNodePtr el, const char *name) {
  std::string v;
  attr(el, name, v);
  return v;
}

inline std::string lookup_prefix(xmlNodePtr el, const std::string &prefix) {
  for (xmlNodePtr cur = el; cur; cur = cur->parent) {
    if (cur->type != XML_ELEMENT_NODE) continue;
    for (xmlNsPtr ns = cur->nsDef; ns; ns = ns->next) {
      std::string p = ns->prefix ? reinterpret_cast<const char *>(ns->prefix) : "";
      if (p == prefix && ns->href) return reinterpret_cast<const char *>(ns->href);
    }
  }
  return "";
}

inline bool attr_ns(xmlNodePtr el, const char *ns, const char *local, std::string &out) {
  out.clear();
  if (!el) return false;
  for (xmlAttrPtr a = el->properties; a; a = a->next) {
    if (!a->name || std::strcmp(reinterpret_cast<const char *>(a->name), local) != 0) continue;
    std::string href = (a->ns && a->ns->href) ? reinterpret_cast<const char *>(a->ns->href) : "";
    if (href == ns) {
      out = attr_value(a);
      return true;
    }
  }
  return false;
}

inline std::vector<xmlNodePtr> children(xmlNodePtr el, const char *ns, const char *local) {
  std::vector<xmlNodePtr> out;
  if (!el) return out;
  for (xmlNodePtr c = el->children; c; c = c->next) {
    if (is_el(c, ns, local)) out.push_back(c);
  }
  return out;
}

inline xmlNodePtr one_child(xmlNodePtr el, const char *ns, const char *local) {
  auto found = children(el, ns, local);
  if (found.size() > 1) {
    std::string tag = el && el->name ? reinterpret_cast<const char *>(el->name) : "";
    fail("validation", "<" + tag + "> has more than one <" + local + ">");
  }
  if (found.empty()) return nullptr;
  return found[0];
}

inline void descendants(xmlNodePtr el, const char *ns, const char *local, std::vector<xmlNodePtr> &out) {
  if (!el) return;
  for (xmlNodePtr c = el->children; c; c = c->next) {
    if (c->type != XML_ELEMENT_NODE) continue;
    if (is_el(c, ns, local)) out.push_back(c);
    descendants(c, ns, local, out);
  }
}

inline std::vector<xmlNodePtr> element_children(xmlNodePtr el) {
  std::vector<xmlNodePtr> out;
  if (!el) return out;
  for (xmlNodePtr c = el->children; c; c = c->next) {
    if (c->type == XML_ELEMENT_NODE) out.push_back(c);
  }
  return out;
}

inline std::string text_content(xmlNodePtr el) {
  if (!el) return "";
  std::string out;
  std::function<void(xmlNodePtr)> walk = [&](xmlNodePtr cur) {
    for (xmlNodePtr c = cur->children; c; c = c->next) {
      if (c->type == XML_TEXT_NODE || c->type == XML_CDATA_SECTION_NODE) {
        if (c->content) out += reinterpret_cast<const char *>(c->content);
      } else if (c->type == XML_ELEMENT_NODE) {
        walk(c);
      }
    }
  };
  walk(el);
  return out;
}

inline std::string text_of(xmlNodePtr el) { return trim_copy(text_content(el)); }

inline bool id_name(const std::string &local) { return local == "ID" || local == "Id" || local == "id"; }

inline void assert_unique_ids(xmlNodePtr root) {
  std::set<std::string> seen;
  std::function<void(xmlNodePtr)> walk = [&](xmlNodePtr el) {
    if (!el || el->type != XML_ELEMENT_NODE) return;
    for (xmlAttrPtr a = el->properties; a; a = a->next) {
      std::string local = a->name ? reinterpret_cast<const char *>(a->name) : "";
      if (!id_name(local)) continue;
      std::string value = attr_value(a);
      if (value.empty()) continue;
      if (!seen.insert(value).second) fail("signature", "two elements carry the ID " + value);
    }
    for (xmlNodePtr c = el->children; c; c = c->next) walk(c);
  };
  walk(root);
}

inline xmlNodePtr find_id(xmlNodePtr node, const std::string &id) {
  if (!node) return nullptr;
  if (node->type == XML_ELEMENT_NODE) {
    std::string v;
    if (attr(node, "ID", v) && v == id) return node;
    for (xmlNodePtr c = node->children; c; c = c->next) {
      if (xmlNodePtr found = find_id(c, id)) return found;
    }
  }
  return nullptr;
}

inline void xsi_type(xmlNodePtr el, std::string &ns, std::string &local, bool &ok) {
  ok = false;
  std::string value;
  if (!attr_ns(el, NS_XSI, "type", value) || value.empty()) return;
  auto colon = value.find(':');
  if (colon != std::string::npos) {
    std::string prefix = trim_copy(value.substr(0, colon));
    local = trim_copy(value.substr(colon + 1));
    ns = lookup_prefix(el, prefix);
  } else {
    local = trim_copy(value);
    ns = lookup_prefix(el, "");
  }
  ok = true;
}

inline std::vector<std::string> wsa_addresses(xmlNodePtr el) {
  std::vector<xmlNodePtr> nodes;
  descendants(el, NS_WSA, "Address", nodes);
  descendants(el, NS_WSA2004, "Address", nodes);
  std::vector<std::string> out;
  for (xmlNodePtr n : nodes) {
    std::string v = text_of(n);
    if (!v.empty()) out.push_back(v);
  }
  return out;
}

inline std::string dump_root(xmlDocPtr doc) {
  xmlNodePtr root = xmlDocGetRootElement(doc);
  xmlBufferPtr buf = xmlBufferCreate();
  xmlNodeDump(buf, doc, root, 0, 0);
  std::string out(reinterpret_cast<const char *>(xmlBufferContent(buf)), xmlBufferLength(buf));
  xmlBufferFree(buf);
  return out;
}

inline void ensure_ns(xmlNodePtr node) {
  if (!node) return;
  if (node->type == XML_ELEMENT_NODE && node->ns && node->ns->href) {
    std::string prefix = node->ns->prefix ? reinterpret_cast<const char *>(node->ns->prefix) : "";
    bool found = false;
    for (xmlNodePtr cur = node; cur && !found; cur = cur->parent) {
      if (cur->type != XML_ELEMENT_NODE) continue;
      for (xmlNsPtr ns = cur->nsDef; ns; ns = ns->next) {
        std::string p = ns->prefix ? reinterpret_cast<const char *>(ns->prefix) : "";
        if (p == prefix && ns->href && xmlStrEqual(ns->href, node->ns->href)) found = true;
      }
    }
    if (!found) {
      xmlNsPtr created = xmlNewNs(node, node->ns->href, node->ns->prefix);
      xmlSetNs(node, created);
    }
  }
  for (xmlNodePtr c = node->children; c; c = c->next) ensure_ns(c);
}

inline bool c14n_mode(const std::string &algorithm, int &mode, int &comments) {
  if (algorithm == EXC_C14N) {
    mode = XML_C14N_EXCLUSIVE_1_0;
    comments = 0;
    return true;
  }
  if (algorithm == EXC_C14N_COMMENTS) {
    mode = XML_C14N_EXCLUSIVE_1_0;
    comments = 1;
    return true;
  }
  if (algorithm == C14N10) {
    mode = XML_C14N_1_0;
    comments = 0;
    return true;
  }
  if (algorithm == C14N10_COMMENTS) {
    mode = XML_C14N_1_0;
    comments = 1;
    return true;
  }
  return false;
}

inline std::string canonicalize(xmlNodePtr node, const std::string &algorithm, const std::string &prefix_list,
                                bool drop_signature) {
  int mode = 0;
  int comments = 0;
  if (!c14n_mode(algorithm, mode, comments)) fail("signature", "canonicalization " + algorithm + " is refused");
  xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
  xmlNodePtr copy = xmlDocCopyNode(node, doc, 1);
  if (!copy) {
    xmlFreeDoc(doc);
    fail("signature", "canonicalization failed: copy");
  }
  xmlDocSetRootElement(doc, copy);
  if (drop_signature) {
    for (xmlNodePtr c = copy->children; c;) {
      xmlNodePtr next = c->next;
      if (is_el(c, NS_DS, "Signature")) {
        xmlUnlinkNode(c);
        xmlFreeNode(c);
        break;
      }
      c = next;
    }
  }
  ensure_ns(copy);
  std::vector<std::string> prefixes;
  std::string cur;
  for (size_t i = 0; i <= prefix_list.size(); i++) {
    if (i == prefix_list.size() || std::isspace(static_cast<unsigned char>(prefix_list[i]))) {
      if (!cur.empty()) prefixes.push_back(cur);
      cur.clear();
    } else {
      cur.push_back(prefix_list[i]);
    }
  }
  std::vector<xmlChar *> raw;
  std::vector<std::vector<xmlChar>> storage;
  for (const auto &p : prefixes) {
    storage.emplace_back(p.begin(), p.end());
    storage.back().push_back(0);
  }
  for (auto &s : storage) raw.push_back(s.data());
  if (!raw.empty()) raw.push_back(nullptr);
  xmlChar *out = nullptr;
  int rc = xmlC14NDocDumpMemory(doc, nullptr, mode, raw.empty() ? nullptr : raw.data(), comments, &out);
  std::string result;
  if (rc >= 0 && out) result.assign(reinterpret_cast<char *>(out));
  if (out) xmlFree(out);
  xmlFreeDoc(doc);
  if (rc < 0) fail("signature", "canonicalization failed");
  return result;
}

inline std::string prefixes_of(xmlNodePtr method) {
  if (!method) return "";
  for (xmlNodePtr c = method->children; c; c = c->next) {
    if (c->type == XML_ELEMENT_NODE && c->name &&
        std::strcmp(reinterpret_cast<const char *>(c->name), "InclusiveNamespaces") == 0) {
      std::string v;
      if (!attr(c, "PrefixList", v)) return "";
      return v;
    }
  }
  return "";
}

}  // namespace iya::wsfed
