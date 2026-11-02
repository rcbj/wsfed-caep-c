// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
#pragma once
// The C wrapper's handle types and error report, shared by src/c_api.cpp (the
// library) and src/demo_c_api.cpp (the demo). Private: not installed.
#include "iya/wsfed.hpp"
#include "iya_wsfed.h"

#include <exception>
#include <string>
#include <utility>
#include <vector>

namespace iya::wsfed::capi {

struct ResolvedBox {
  iya::wsfed::Resolved resolved;
};

struct PartyBox {
  iya::wsfed::RelyingParty party;
  ResolvedBox resolved;
  std::string entity;
  std::string passive;
  std::vector<std::string> tokens;
  explicit PartyBox(iya::wsfed::RelyingParty party_in) : party(std::move(party_in)) {
    resolved.resolved = party.config();
    entity = party.IdpEntityId();
    passive = party.PassiveEndpoint();
    tokens = party.TokenTypesOffered();
  }
};

int report_std(iya_wsfed_error *err, const std::exception &ex);

}  // namespace iya::wsfed::capi
