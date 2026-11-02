# wsfed-caep

Server-side WS-Federation 1.2 passive relying party for C and C++. One implementation, in C++17, lives in this repository. C++ classes are that implementation. `include/iya_wsfed.h` declares the same operations as `extern "C"`. Those functions are defined in this library and call the C++ classes. C callers and C++ callers link one library binary.

The library accepts SAML 2.0 bearer assertions, reads identity-provider federation metadata, writes relying-party metadata, verifies XML signatures, decrypts encrypted assertions, and remembers assertion ids so a bearer token cannot be replayed. A Shared Signals poll receiver for CAEP and RISC is included. The relying party does not start that receiver.

Version 0.1.0. License: MIT. Publishing is not a package registry. `develop` and `main` are the same commit when this tree is published.

## Call surfaces

C++:

```cpp
#include "iya/wsfed.hpp"

auto party = iya::wsfed::RelyingParty::FromFile("wsfed.json", "");
iya::wsfed::RelyingParty::LoginOptions options;
options.relay_state = std::string("/");
auto request = party.Login(options);
auto who = party.HandleReply("POST", "/wsfed", body, {request.id});
```

C, the same library:

```c
#include "iya_wsfed.h"

iya_wsfed_error err = {0};
iya_wsfed_party *party = iya_wsfed_party_create(json, "", &err);
iya_wsfed_login_request *request = iya_wsfed_begin_login(party, NULL, &err);
```

A C function logs once with `fprintf(stderr, ...)` and returns an error. The C++ method throws `std::runtime_error` with that message and does not log a second time.

## Configuration

JSON keys: `realm`, `replyUrl`, `idpMetadata`, `privateKey`, `certificate`, `idpCa`, `idpEntityId`, `clockSkewSeconds`, `wantAssertionsEncrypted`, `allowUnsolicited`, `requestTokenType`, `signals`, `ssf`. `file:` and `env:` prefixes are accepted. The default subject attribute is `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier`.

Sign-in uses `wa=wsignin1.0`, `wtrealm`, `wreply`, and `wctx`.

`signals` omitted or `true` is on. The resolved configuration omits the key in that case (`signals_set` stays false) and the receiver runs when a transmitter is configured. `false` is stored, does not start a receiver, and does not require transmitter metadata. Any other value is refused with `signals must be true or false`.

Signatures use exclusive canonicalization `http://www.w3.org/2001/10/xml-exc-c14n#`, RSA-SHA256 `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`, and digest sha256. Content encryption is AES-GCM and AES-CBC. Key transport is RSA-OAEP. Success status is `urn:oasis:names:tc:SAML:2.0:status:Success`. OpenSSL performs the cryptography. libxml2 parses XML and performs exclusive canonicalization. The JSON parser and the HTTP/1.1 client are in this repository.

## Tests

```bash
docker build --target test .
```

The suite runs in the `test` stage. It does not run on `docker build .`.

## Demo

`PORT` defaults to 3000. `GET /healthz` returns `200` and the body `ok` before the identity provider is dialed. Loopback realm and reply URLs follow the running port. Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The page links to `/login`, which redirects with `wa=wsignin1.0`, `wtrealm`, `wreply`, and `wctx`. The reply URL handles the POST and sign-out cleanup. `POST /logout` signs out. Demo JSON uses `file:` placeholders and omits `signals`. Do not commit `demo/generated`.

```sh
docker compose build
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/demo:/app/demo" \
  wsfed-caep-c-demo \
  wsfed-caep generate-keys --config demo/wsfed.json
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/demo:/app/demo" \
  wsfed-caep-c-demo \
  wsfed-caep metadata --config demo/wsfed.json
```

The generated certificate's common name defaults to `wsfed-caep-nodejs relying party` plus the realm, cut at 64 characters. Key generation is the `wsfed-caep` command in the demo image.

`python scripts/configure_iya_sts.py` registers the demo with iya-sts. The container `PORT` wins over the shell `PORT`. The script calls `wsfed-caep` on `PATH` for key generation and does not import a Python protocol package.

`Dockerfile` and comment-free `docker-compose.yml` use image `wsfed-caep-c-demo`, `network_mode: host`, `ENV PORT=3000`, and a health check of `http://127.0.0.1:${PORT}/healthz`. Compose does not publish host port 3000.
