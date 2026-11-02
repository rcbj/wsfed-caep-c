// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#pragma once

#include "iya/wsfed.hpp"

#include <cctype>
#include <cmath>
#include <cstdio>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace iya::wsfed {

struct Json {
  enum Type { Null, Bool, Number, String, Array, Object } type = Null;
  bool b = false;
  std::string text;
  std::vector<Json> arr;
  std::vector<std::pair<std::string, Json>> obj;

  bool has(const std::string &key) const {
    for (const auto &kv : obj) {
      if (kv.first == key) return true;
    }
    return false;
  }
  const Json *get(const std::string &key) const {
    const Json *found = nullptr;
    for (const auto &kv : obj) {
      if (kv.first == key) found = &kv.second;
    }
    return found;
  }
  Json *get(const std::string &key) {
    Json *found = nullptr;
    for (auto &kv : obj) {
      if (kv.first == key) found = &kv.second;
    }
    return found;
  }
  std::string str(const std::string &key) const {
    const Json *v = get(key);
    if (!v || v->type != String) return "";
    return v->text;
  }
};

inline void append_utf8(std::string &out, unsigned code) {
  if (code <= 0x7F) {
    out.push_back(static_cast<char>(code));
  } else if (code <= 0x7FF) {
    out.push_back(static_cast<char>(0xC0 | (code >> 6)));
    out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
  } else if (code <= 0xFFFF) {
    out.push_back(static_cast<char>(0xE0 | (code >> 12)));
    out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
  } else {
    out.push_back(static_cast<char>(0xF0 | (code >> 18)));
    out.push_back(static_cast<char>(0x80 | ((code >> 12) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
  }
}

class JsonParser {
 public:
  explicit JsonParser(std::string in) : s_(std::move(in)) {}

  Json parse() {
    skip();
    if (i_ >= s_.size()) fail("config", "the configuration must be an object");
    Json v = value();
    skip();
    if (i_ != s_.size()) fail("config", "the configuration must be an object");
    return v;
  }

  Json parse_value(const std::string &what) {
    try {
      skip();
      Json v = value();
      skip();
      if (i_ != s_.size()) fail("signature", what);
      return v;
    } catch (const failure &err) {
      if (err.code == "config") fail("signature", what);
      throw;
    }
  }

 private:
  std::string s_;
  size_t i_ = 0;

  void skip() {
    while (i_ < s_.size() && std::isspace(static_cast<unsigned char>(s_[i_]))) i_++;
  }
  char peek() {
    skip();
    if (i_ >= s_.size()) return 0;
    return s_[i_];
  }
  char getc() {
    if (i_ >= s_.size()) fail("config", "the configuration must be an object");
    return s_[i_++];
  }

  Json value() {
    char c = peek();
    if (c == '{') return object();
    if (c == '[') return array();
    if (c == '"') {
      Json j;
      j.type = Json::String;
      j.text = string();
      return j;
    }
    if (c == 't' || c == 'f') return boolean();
    if (c == 'n') return null();
    if (c == '-' || (c >= '0' && c <= '9')) return number();
    fail("config", "the configuration must be an object");
  }

  Json object() {
    getc();
    Json j;
    j.type = Json::Object;
    skip();
    if (peek() == '}') {
      getc();
      return j;
    }
    while (true) {
      if (peek() != '"') fail("config", "the configuration must be an object");
      std::string key = string();
      skip();
      if (getc() != ':') fail("config", "the configuration must be an object");
      j.obj.emplace_back(key, value());
      skip();
      char c = getc();
      if (c == '}') break;
      if (c != ',') fail("config", "the configuration must be an object");
    }
    return j;
  }

  Json array() {
    getc();
    Json j;
    j.type = Json::Array;
    skip();
    if (peek() == ']') {
      getc();
      return j;
    }
    while (true) {
      j.arr.push_back(value());
      skip();
      char c = getc();
      if (c == ']') break;
      if (c != ',') fail("config", "the configuration must be an object");
    }
    return j;
  }

  std::string string() {
    if (getc() != '"') fail("config", "the configuration must be an object");
    std::string out;
    while (i_ < s_.size()) {
      char c = getc();
      if (c == '"') return out;
      if (c == '\\') {
        if (i_ >= s_.size()) fail("config", "the configuration must be an object");
        char e = getc();
        switch (e) {
          case '"':
          case '\\':
          case '/':
            out.push_back(e);
            break;
          case 'b':
            out.push_back('\b');
            break;
          case 'f':
            out.push_back('\f');
            break;
          case 'n':
            out.push_back('\n');
            break;
          case 'r':
            out.push_back('\r');
            break;
          case 't':
            out.push_back('\t');
            break;
          case 'u': {
            unsigned code = hex4();
            if (code >= 0xD800 && code <= 0xDBFF) {
              if (i_ + 1 < s_.size() && s_[i_] == '\\' && s_[i_ + 1] == 'u') {
                i_ += 2;
                unsigned low = hex4();
                if (low >= 0xDC00 && low <= 0xDFFF) {
                  code = 0x10000 + (((code - 0xD800) << 10) | (low - 0xDC00));
                }
              }
            }
            append_utf8(out, code);
            break;
          }
          default:
            fail("config", "the configuration must be an object");
        }
      } else if (static_cast<unsigned char>(c) < 0x20) {
        fail("config", "the configuration must be an object");
      } else {
        out.push_back(c);
      }
    }
    fail("config", "the configuration must be an object");
  }

  unsigned hex4() {
    unsigned v = 0;
    for (int n = 0; n < 4; n++) {
      if (i_ >= s_.size()) fail("config", "the configuration must be an object");
      char c = getc();
      v <<= 4;
      if (c >= '0' && c <= '9') v |= static_cast<unsigned>(c - '0');
      else if (c >= 'a' && c <= 'f') v |= static_cast<unsigned>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') v |= static_cast<unsigned>(c - 'A' + 10);
      else fail("config", "the configuration must be an object");
    }
    return v;
  }

  Json boolean() {
    Json j;
    j.type = Json::Bool;
    if (s_.compare(i_, 4, "true") == 0) {
      i_ += 4;
      j.b = true;
      return j;
    }
    if (s_.compare(i_, 5, "false") == 0) {
      i_ += 5;
      j.b = false;
      return j;
    }
    fail("config", "the configuration must be an object");
  }

  Json null() {
    if (s_.compare(i_, 4, "null") != 0) fail("config", "the configuration must be an object");
    i_ += 4;
    Json j;
    j.type = Json::Null;
    return j;
  }

  Json number() {
    size_t start = i_;
    if (peek() == '-') i_++;
    if (i_ >= s_.size() || !std::isdigit(static_cast<unsigned char>(s_[i_]))) {
      fail("config", "the configuration must be an object");
    }
    if (s_[i_] == '0') {
      i_++;
    } else {
      while (i_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[i_]))) i_++;
    }
    if (i_ < s_.size() && s_[i_] == '.') {
      i_++;
      if (i_ >= s_.size() || !std::isdigit(static_cast<unsigned char>(s_[i_]))) {
        fail("config", "the configuration must be an object");
      }
      while (i_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[i_]))) i_++;
    }
    if (i_ < s_.size() && (s_[i_] == 'e' || s_[i_] == 'E')) {
      i_++;
      if (i_ < s_.size() && (s_[i_] == '+' || s_[i_] == '-')) i_++;
      if (i_ >= s_.size() || !std::isdigit(static_cast<unsigned char>(s_[i_]))) {
        fail("config", "the configuration must be an object");
      }
      while (i_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[i_]))) i_++;
    }
    Json j;
    j.type = Json::Number;
    j.text = s_.substr(start, i_ - start);
    return j;
  }
};

inline Json parse_json(const std::string &text) {
  JsonParser p(text);
  return p.parse();
}

inline std::string json_escape(const std::string &in) {
  std::string out;
  out.push_back('"');
  for (unsigned char c : in) {
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\b':
        out += "\\b";
        break;
      case '\f':
        out += "\\f";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof buf, "\\u%04x", c);
          out += buf;
        } else {
          out.push_back(static_cast<char>(c));
        }
    }
  }
  out.push_back('"');
  return out;
}

inline std::string json_dump(const Json &j) {
  switch (j.type) {
    case Json::Null:
      return "null";
    case Json::Bool:
      return j.b ? "true" : "false";
    case Json::Number:
      return j.text.empty() ? "0" : j.text;
    case Json::String:
      return json_escape(j.text);
    case Json::Array: {
      std::string out = "[";
      for (size_t i = 0; i < j.arr.size(); i++) {
        if (i) out.push_back(',');
        out += json_dump(j.arr[i]);
      }
      out.push_back(']');
      return out;
    }
    case Json::Object: {
      std::string out = "{";
      for (size_t i = 0; i < j.obj.size(); i++) {
        if (i) out.push_back(',');
        out += json_escape(j.obj[i].first);
        out.push_back(':');
        out += json_dump(j.obj[i].second);
      }
      out.push_back('}');
      return out;
    }
  }
  return "null";
}

inline Json obj_string(const std::string &s) {
  Json j;
  j.type = Json::String;
  j.text = s;
  return j;
}
inline Json obj_bool(bool v) {
  Json j;
  j.type = Json::Bool;
  j.b = v;
  return j;
}
inline Json obj_number(long long n) {
  Json j;
  j.type = Json::Number;
  j.text = std::to_string(n);
  return j;
}

inline bool json_whole(const Json &j) {
  if (j.type != Json::Number) return false;
  return j.text.find_first_of(".eE") == std::string::npos;
}

inline bool json_as_float(const Json &j, double &out) {
  if (j.type != Json::Number) return false;
  char *end = nullptr;
  out = std::strtod(j.text.c_str(), &end);
  if (end == j.text.c_str() || *end != '\0') return false;
  if (std::isnan(out)) return false;
  return true;
}

inline std::string string_of(const Json *j) {
  if (!j || j->type != Json::String) return "";
  return j->text;
}

}  // namespace iya::wsfed
