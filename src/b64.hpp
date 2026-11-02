// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#pragma once

#include "iya/wsfed.hpp"

#include <cctype>
#include <map>
#include <string>
#include <vector>

namespace iya::wsfed {

inline int b64_val(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+' || c == '-') return 62;
  if (c == '/' || c == '_') return 63;
  return -1;
}

inline std::string b64_encode(const unsigned char *data, size_t len) {
  static const char *tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((len + 2) / 3) * 4);
  for (size_t i = 0; i < len; i += 3) {
    unsigned n = static_cast<unsigned>(data[i]) << 16;
    if (i + 1 < len) n |= static_cast<unsigned>(data[i + 1]) << 8;
    if (i + 2 < len) n |= static_cast<unsigned>(data[i + 2]);
    out.push_back(tbl[(n >> 18) & 63]);
    out.push_back(tbl[(n >> 12) & 63]);
    out.push_back(i + 1 < len ? tbl[(n >> 6) & 63] : '=');
    out.push_back(i + 2 < len ? tbl[n & 63] : '=');
  }
  return out;
}

inline std::string b64_encode(const std::string &s) {
  return b64_encode(reinterpret_cast<const unsigned char *>(s.data()), s.size());
}

inline std::string b64url_encode(const unsigned char *data, size_t len) {
  std::string out = b64_encode(data, len);
  for (char &c : out) {
    if (c == '+') c = '-';
    else if (c == '/') c = '_';
  }
  while (!out.empty() && out.back() == '=') out.pop_back();
  return out;
}

inline std::vector<unsigned char> b64_decode(const std::string &in, bool url) {
  std::string raw;
  raw.reserve(in.size());
  for (char c : in) {
    if (std::isspace(static_cast<unsigned char>(c))) continue;
    raw.push_back(c);
  }
  if (url) {
    for (char c : raw) {
      if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) {
        fail("signature", "the SET's value is not base64url");
      }
    }
  }
  while (raw.size() % 4) raw.push_back('=');
  std::vector<unsigned char> out;
  for (size_t i = 0; i + 3 < raw.size(); i += 4) {
    int a = raw[i] == '=' ? 0 : b64_val(raw[i]);
    int b = raw[i + 1] == '=' ? 0 : b64_val(raw[i + 1]);
    int c = raw[i + 2] == '=' ? 0 : b64_val(raw[i + 2]);
    int d = raw[i + 3] == '=' ? 0 : b64_val(raw[i + 3]);
    if (a < 0 || b < 0 || (raw[i + 2] != '=' && c < 0) || (raw[i + 3] != '=' && d < 0)) {
      fail("signature", "the SET's value is not base64url");
    }
    out.push_back(static_cast<unsigned char>((a << 2) | (b >> 4)));
    if (raw[i + 2] != '=') out.push_back(static_cast<unsigned char>(((b & 15) << 4) | (c >> 2)));
    if (raw[i + 3] != '=') out.push_back(static_cast<unsigned char>(((c & 3) << 6) | d));
  }
  return out;
}

inline std::string b64_decode_string(const std::string &in) {
  auto v = b64_decode(in, false);
  return std::string(reinterpret_cast<char *>(v.data()), v.size());
}

inline std::string pem_body(std::string pem) {
  std::string out;
  bool begin = false;
  std::string line;
  for (size_t i = 0; i <= pem.size(); i++) {
    if (i == pem.size() || pem[i] == '\n' || pem[i] == '\r') {
      if (line.find("-----") != std::string::npos) {
        begin = line.find("BEGIN") != std::string::npos;
      } else if (begin) {
        out += line;
      }
      line.clear();
      if (i < pem.size() && pem[i] == '\r' && i + 1 < pem.size() && pem[i + 1] == '\n') i++;
    } else {
      line.push_back(pem[i]);
    }
  }
  return out;
}

inline std::string to_pem(const std::string &b64) {
  std::string body;
  for (char c : b64) {
    if (!std::isspace(static_cast<unsigned char>(c))) body.push_back(c);
  }
  std::string out = "-----BEGIN CERTIFICATE-----\n";
  for (size_t i = 0; i < body.size(); i += 64) {
    out.append(body, i, 64);
    out.push_back('\n');
  }
  out += "-----END CERTIFICATE-----\n";
  return out;
}

inline std::string escape_xml(const std::string &value) {
  std::string out;
  for (char c : value) {
    switch (c) {
      case '&':
        out += "&amp;";
        break;
      case '<':
        out += "&lt;";
        break;
      case '>':
        out += "&gt;";
        break;
      case '"':
        out += "&quot;";
        break;
      case '\'':
        out += "&apos;";
        break;
      default:
        out.push_back(c);
    }
  }
  return out;
}

inline std::string trim_copy(const std::string &s) {
  size_t a = 0;
  size_t b = s.size();
  while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) a++;
  while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) b--;
  return s.substr(a, b - a);
}

inline std::string query_escape(const std::string &s) {
  static const char *hex = "0123456789ABCDEF";
  std::string out;
  for (unsigned char c : s) {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
        c == '.' || c == '~') {
      out.push_back(static_cast<char>(c));
    } else if (c == ' ') {
      out.push_back('+');
    } else {
      out.push_back('%');
      out.push_back(hex[c >> 4]);
      out.push_back(hex[c & 15]);
    }
  }
  return out;
}

inline bool query_unescape(const std::string &s, std::string &out) {
  out.clear();
  for (size_t i = 0; i < s.size(); i++) {
    char c = s[i];
    if (c == '+') {
      out.push_back(' ');
    } else if (c == '%') {
      if (i + 2 >= s.size()) return false;
      auto hex = [](char h) -> int {
        if (h >= '0' && h <= '9') return h - '0';
        if (h >= 'a' && h <= 'f') return h - 'a' + 10;
        if (h >= 'A' && h <= 'F') return h - 'A' + 10;
        return -1;
      };
      int hi = hex(s[i + 1]);
      int lo = hex(s[i + 2]);
      if (hi < 0 || lo < 0) return false;
      out.push_back(static_cast<char>((hi << 4) | lo));
      i += 2;
    } else {
      out.push_back(c);
    }
  }
  return true;
}

inline std::map<std::string, std::string> parse_query(const std::string &raw) {
  std::map<std::string, std::string> out;
  auto manual = [&]() {
    out.clear();
    size_t i = 0;
    while (i < raw.size()) {
      size_t amp = raw.find('&', i);
      if (amp == std::string::npos) amp = raw.size();
      std::string part = raw.substr(i, amp - i);
      i = amp + 1;
      if (part.empty()) continue;
      size_t eq = part.find('=');
      std::string key = eq == std::string::npos ? part : part.substr(0, eq);
      std::string val = eq == std::string::npos ? "" : part.substr(eq + 1);
      std::string dk, dv;
      if (!query_unescape(key, dk)) dk = key;
      if (!query_unescape(val, dv)) dv = val;
      if (!out.count(dk)) out[dk] = dv;
    }
  };
  bool bad = false;
  size_t i = 0;
  while (i <= raw.size()) {
    size_t amp = raw.find('&', i);
    if (amp == std::string::npos) amp = raw.size();
    std::string part = raw.substr(i, amp - i);
    if (i > raw.size()) break;
    if (!part.empty()) {
      size_t eq = part.find('=');
      std::string key = eq == std::string::npos ? part : part.substr(0, eq);
      std::string val = eq == std::string::npos ? "" : part.substr(eq + 1);
      std::string dk, dv;
      if (!query_unescape(key, dk) || !query_unescape(val, dv)) {
        bad = true;
        break;
      }
      if (!out.count(dk)) out[dk] = dv;
    }
    if (amp == raw.size()) break;
    i = amp + 1;
  }
  if (bad) manual();
  return out;
}

inline std::string encode_query(const std::vector<std::pair<std::string, std::string>> &pairs) {
  std::string out;
  std::map<std::string, bool> seen;
  for (const auto &kv : pairs) {
    if (seen[kv.first]) continue;
    seen[kv.first] = true;
    if (!out.empty()) out.push_back('&');
    out += query_escape(kv.first);
    out.push_back('=');
    out += query_escape(kv.second);
  }
  return out;
}

}  // namespace iya::wsfed
