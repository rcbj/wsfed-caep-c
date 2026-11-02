// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "detail.hpp"

#include <openssl/rand.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

namespace iya::wsfed {

std::string itoa_i(long long n) {
  if (n == 0) return "0";
  bool neg = n < 0;
  unsigned long long v = neg ? static_cast<unsigned long long>(-n) : static_cast<unsigned long long>(n);
  char buf[32];
  int i = 32;
  while (v > 0) {
    buf[--i] = static_cast<char>('0' + (v % 10));
    v /= 10;
  }
  std::string out(buf + i, buf + 32);
  if (neg) out.insert(out.begin(), '-');
  return out;
}

int64_t now_ms() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

bool parse_instant(const std::string &value, const std::string &what, int64_t &ms_out) {
  if (value.empty()) return false;
  if (value.size() < 20 || value.back() != 'Z') fail("validation", what + " is not a UTC dateTime: " + value);
  int Y = 0, M = 0, D = 0, h = 0, m = 0, s = 0;
  char extra = 0;
  int n = std::sscanf(value.c_str(), "%4d-%2d-%2dT%2d:%2d:%2d%c", &Y, &M, &D, &h, &m, &s, &extra);
  if (n < 6) fail("validation", what + " is not a UTC dateTime: " + value);
  std::string rest;
  if (n == 7) {
    if (extra != '.') fail("validation", what + " is not a UTC dateTime: " + value);
    rest = value.substr(19);
  } else if (value.size() != 20) {
    fail("validation", what + " is not a UTC dateTime: " + value);
  }
  int frac = 0;
  if (!rest.empty()) {
    if (rest.back() != 'Z' || rest.size() < 3) fail("validation", what + " is not a UTC dateTime: " + value);
    std::string digits = rest.substr(1, rest.size() - 2);
    if (digits.empty()) fail("validation", what + " is not a UTC dateTime: " + value);
    for (char c : digits) {
      if (c < '0' || c > '9') fail("validation", what + " is not a UTC dateTime: " + value);
    }
    std::string ms = digits.substr(0, 3);
    while (ms.size() < 3) ms.push_back('0');
    frac = std::stoi(ms);
  }
  std::tm tm{};
  tm.tm_year = Y - 1900;
  tm.tm_mon = M - 1;
  tm.tm_mday = D;
  tm.tm_hour = h;
  tm.tm_min = m;
  tm.tm_sec = s;
  time_t sec = timegm(&tm);
  if (sec == static_cast<time_t>(-1) && (Y < 1970)) {
    fail("validation", what + " is not a dateTime: " + value);
  }
  ms_out = static_cast<int64_t>(sec) * 1000 + frac;
  return true;
}

std::string iso_time(int64_t ms) {
  time_t sec = static_cast<time_t>(ms / 1000);
  int frac = static_cast<int>(ms % 1000);
  if (frac < 0) {
    sec -= 1;
    frac += 1000;
  }
  std::tm tm{};
  gmtime_r(&sec, &tm);
  char buf[40];
  std::snprintf(buf, sizeof buf, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec, frac);
  return buf;
}

std::string random_hex(size_t nbytes) {
  std::vector<unsigned char> buf(nbytes);
  if (RAND_bytes(buf.data(), static_cast<int>(buf.size())) != 1) fail("config", "a request id could not be chosen");
  static const char *hex = "0123456789abcdef";
  std::string out;
  out.resize(nbytes * 2);
  for (size_t i = 0; i < nbytes; i++) {
    out[i * 2] = hex[buf[i] >> 4];
    out[i * 2 + 1] = hex[buf[i] & 15];
  }
  return out;
}

std::string read_file(const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return "";
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

void write_file_mode(const std::string &path, const std::string &body, int mode) {
  std::string dir = path;
  auto slash = dir.find_last_of('/');
  if (slash != std::string::npos && slash > 0) {
    std::string parent = dir.substr(0, slash);
    std::string cur;
    for (size_t i = 0; i < parent.size(); i++) {
      cur.push_back(parent[i]);
      if (parent[i] == '/' && cur.size() > 1) mkdir(cur.c_str(), 0755);
    }
    mkdir(parent.c_str(), 0755);
  }
  FILE *f = std::fopen(path.c_str(), "wb");
  if (!f) fail("config", path + " cannot be written");
  if (!body.empty()) std::fwrite(body.data(), 1, body.size(), f);
  std::fclose(f);
  chmod(path.c_str(), static_cast<mode_t>(mode));
}

bool file_exists(const std::string &path) {
  struct stat st;
  return stat(path.c_str(), &st) == 0;
}

std::string cwd_path() {
  char buf[4096];
  if (!getcwd(buf, sizeof buf)) return ".";
  return buf;
}

std::string abs_path(const std::string &path) {
  if (!path.empty() && path[0] == '/') return path;
  return join_path(cwd_path(), path);
}

std::string join_path(const std::string &dir, const std::string &rel) {
  if (rel.empty()) return dir;
  if (!rel.empty() && rel[0] == '/') return rel;
  if (dir.empty() || dir == ".") return rel;
  if (dir.back() == '/') return dir + rel;
  return dir + "/" + rel;
}

std::string clip_runes(const std::string &value, int n) {
  int count = 0;
  size_t i = 0;
  while (i < value.size() && count < n) {
    unsigned char c = static_cast<unsigned char>(value[i]);
    size_t step = 1;
    if ((c & 0x80) == 0) step = 1;
    else if ((c & 0xE0) == 0xC0) step = 2;
    else if ((c & 0xF0) == 0xE0) step = 3;
    else if ((c & 0xF8) == 0xF0) step = 4;
    if (i + step > value.size()) break;
    i += step;
    count++;
  }
  return value.substr(0, i);
}

ReplayCache::ReplayCache(int max_entries) : max_(max_entries <= 0 ? 10000 : max_entries) {}

bool ReplayCache::check_and_record(const std::string &id, int64_t expires_ms) {
  std::lock_guard<std::mutex> lock(mu_);
  int64_t now = now_ms();
  auto it = entries_.find(id);
  if (it != entries_.end() && it->second > now) return true;
  if (static_cast<int>(entries_.size()) >= max_) {
    for (auto cur = entries_.begin(); cur != entries_.end();) {
      if (cur->second <= now) cur = entries_.erase(cur);
      else ++cur;
    }
    if (static_cast<int>(entries_.size()) >= max_) {
      fail("replay", "the replay cache holds " + itoa_i(max_) + " live assertions and cannot record another");
    }
  }
  entries_[id] = expires_ms;
  return false;
}

}  // namespace iya::wsfed
