// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "iya/wsfed.hpp"

int main() {
  auto resolved = iya::wsfed::ResolveConfig(
      R"({"realm":"https://rp.test/","replyUrl":"https://rp.test/wsfed","idpMetadata":"https://idp.example/metadata"})",
      "");
  if (resolved.realm != "https://rp.test/") return 1;
  if (resolved.signals_set) return 1;
  return 0;
}
