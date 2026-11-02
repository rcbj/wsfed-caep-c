// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
// The demo web app's C interface (src/iya_wsfed_demo.h), for the tests.
// Part of the iya_wsfed_demo target, never of the library.
#include "c_api_internal.hpp"
#include "demo.hpp"
#include "iya_wsfed_demo.h"

#include <exception>
#include <utility>

using iya::wsfed::capi::PartyBox;
using iya::wsfed::capi::report_std;

namespace {

struct AppBox {
  iya::wsfed::DemoApp app;
  explicit AppBox(iya::wsfed::RelyingParty party) : app(std::move(party)) {}
};

}  // namespace

iya_wsfed_app *iya_wsfed_app_new(iya_wsfed_party *party) {
  if (!party) return nullptr;
  auto *from = reinterpret_cast<PartyBox *>(party);
  try {
    return reinterpret_cast<iya_wsfed_app *>(new AppBox(std::move(from->party)));
  } catch (const std::exception &ex) {
    report_std(nullptr, ex);
    return nullptr;
  }
}

int iya_wsfed_app_listen(iya_wsfed_app *app, int *port, iya_wsfed_error *err) {
  try {
    auto *box = reinterpret_cast<AppBox *>(app);
    int requested = port ? *port : 0;
    int bound = requested > 0 ? requested : 0;
    if (requested > 0) box->app.Listen(requested);
    else bound = box->app.ListenEphemeral();
    if (port) *port = bound;
    return 0;
  } catch (const std::exception &ex) {
    return report_std(err, ex);
  }
}

void iya_wsfed_app_close(iya_wsfed_app *app) {
  if (!app) return;
  reinterpret_cast<AppBox *>(app)->app.Close();
  delete reinterpret_cast<AppBox *>(app);
}
