// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
#pragma once
// The demo web app: an HTTP front end over a RelyingParty, used by wsfed-demo and the
// tests. Not part of the library: it is the iya_wsfed_demo target, never installed.
#include "iya/wsfed.hpp"

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace iya::wsfed {
class DemoApp {
 public:
  explicit DemoApp(RelyingParty party);
  ~DemoApp();
  DemoApp(DemoApp &&) noexcept;
  DemoApp &operator=(DemoApp &&) noexcept;
  DemoApp(const DemoApp &) = delete;
  DemoApp &operator=(const DemoApp &) = delete;

  struct Handled {
    int status = 200;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
  };
  Handled Handle(const std::string &method, const std::string &target,
                 const std::vector<std::pair<std::string, std::string>> &headers, const std::string &body);
  void StartSignals(const std::string &transmitter, int poll_interval_ms, const std::string &ca_pem,
                    const std::string &cert_pem, const std::string &key_pem);
  void Listen(int port);
  int ListenEphemeral();
  void Close();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

int DemoMain(int argc, char **argv);

}  // namespace iya::wsfed
