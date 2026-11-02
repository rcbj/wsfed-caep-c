// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
#ifndef IYA_WSFED_DEMO_H
#define IYA_WSFED_DEMO_H
/* The demo web app's C interface, for the tests. Not part of the library: it is
   the iya_wsfed_demo target, never installed. */
#include "iya_wsfed.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct iya_wsfed_app iya_wsfed_app;

iya_wsfed_app *iya_wsfed_app_new(iya_wsfed_party *party);
int iya_wsfed_app_listen(iya_wsfed_app *app, int *port, iya_wsfed_error *err);
void iya_wsfed_app_close(iya_wsfed_app *app);

#ifdef __cplusplus
}
#endif
#endif
