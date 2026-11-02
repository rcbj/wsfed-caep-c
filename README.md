# wsfed-caep

Server-side WS-Federation 1.2 passive relying party for C and C++. One implementation, in C++17, lives in this repository. C++ classes are that implementation. `include/iya_wsfed.h` declares the same operations as `extern "C"`. Those functions are defined in this library and call the C++ classes. C callers and C++ callers link one library binary.

The library accepts SAML 2.0 bearer assertions, reads identity-provider federation metadata, writes relying-party metadata, verifies XML signatures, decrypts encrypted assertions, and remembers assertion ids so a bearer token cannot be replayed. A Shared Signals poll receiver for CAEP and RISC is included. The relying party does not start that receiver.

Version 0.1.0. License: MIT. `develop` and `main` are the same commit when this tree is published.

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

## Live iya-sts test and the nightly suite

```bash
python3 scripts/live_iya_sts.py
```

The script starts the latest `main` of iya-sts in a container (memory mode, no persistence, no clustering), registers the demo with it, signs in through the demo, emits CAEP `credential-change` and then `session-revoked`, and requires the demo's `GET /live-status` to show both, the second one with the local session ended. It prints JSON ending in `"ok": true`. `IYA_STS_URL` uses an iya-sts that is already running (and does not stop it), `IYA_STS_IMAGE` starts a fresh container from that image, and otherwise iya-sts `main` is cloned and built. `LIVE_STS_PORT` (default 18529) and `LIVE_DEMO_PORT` (default 18629) are the host ports. The library and the demo build and run only in containers; the script needs the host's `python3` (standard library) and Docker.

`GET /live-status` answers `{"signedIn", "subject", "receiver", "events": [{"type", "jti"}]}` and never a token or an assertion. iya-sts `main` puts the assertion id in `SessionIndex`, so a `session-revoked` event matches no tracked session; the demo then ends its one local session and untracks it.

`.github/workflows/nightly.yml` runs the unit suite and the live script every day at 07:54 UTC (`54 7 * * *`), and on demand. Push and pull-request CI stays in `tests.yml`.

## The iya-sts trust chain (`idpCa`)

`idpCa` (demo default `file:generated/idp-ca.pem`, relative to `demo/`) is iya-sts's TLS listener CA trust chain. `scripts/configure_iya_sts.py` writes it on every run through `scripts/trust_chain.py`: the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain presented in the TLS handshake when that is missing. It prints the path, the anchor's subject and its SHA-256. `python3 scripts/trust_chain.py --idp <url>` does only that step.

The install script never prints a generated test-user password: it writes it to `demo/generated/<user>.password` (created mode 0600) and prints only that path. No line it or the live script prints carries anything derived from a password or secret.

The library loads every PEM block of `idpCa` into its OpenSSL trust store, so the path ends at the self-signed Root, and it verifies that the listener's certificate names the host in the URL: a DNS name against a DNS SAN, an IP literal (such as `127.0.0.1`) against an IP SAN. A certificate that chains to the trusted root but does not name the host is refused.

The demo image build copies `demo/` after compiling, and `.dockerignore` admits only `demo/generated/idp-ca.pem` from `demo/generated`, so the image carries the chain at `/app/demo/generated/idp-ca.pem` with no bind mount. Keys, secrets and metadata stay out of the image. A build before the install script has run still succeeds; the image then has no chain. Rebuild the image after re-running the install script against a different iya-sts.

## Demo

`PORT` defaults to 3000. `GET /healthz` returns `200` and the body `ok` before the identity provider is dialed. Loopback realm and reply URLs follow the running port. Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The page links to `/login`, which redirects with `wa=wsignin1.0`, `wtrealm`, `wreply`, and `wctx`. The reply URL handles the POST and sign-out cleanup. `POST /logout` signs out. `GET /live-status` reports the sign-in and accepted Shared Signals events as JSON, without tokens. Demo JSON uses `file:` placeholders and omits `signals`. Do not commit `demo/generated`.

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

`python scripts/configure_iya_sts.py` registers the demo with iya-sts and writes its listener CA trust chain where `idpCa` names it (see above); rebuild the demo image afterwards. The container `PORT` wins over the shell `PORT`. The script calls `wsfed-caep` on `PATH` for key generation and does not import a Python protocol package.

`Dockerfile` and comment-free `docker-compose.yml` use image `wsfed-caep-c-demo`, `network_mode: host`, `ENV PORT=3000`, and a health check of `http://127.0.0.1:${PORT}/healthz`. Compose does not publish host port 3000.

## Using it from CMake

The build installs the library, its public headers and a CMake package. It builds static by
default and shared with `-DBUILD_SHARED_LIBS=ON`; `-DIYA_WSFED_BUILD_TESTS=OFF -DIYA_WSFED_BUILD_PROGRAMS=OFF`
builds the library alone (both are on only when this is the top-level project). Then:

```cmake
find_package(iya_wsfed REQUIRED)
target_link_libraries(app PRIVATE iya::wsfed)
```

The package finds the library's own dependencies, and the target carries the include
directory and C++17. The Docker test stage checks this: it installs the static and the shared
library and builds the C++ smoke test against each through `find_package` (`tests/package/`).

A pull request merged into `main` releases the library after the test workflow succeeds on that commit: `release.yml` tags `v<VERSION>` and makes a GitHub Release, whose source archive is what a package recipe (such as a ConanCenter one) builds from. A direct push does not release. A tag that already exists stays; the next release is a new version in `VERSION`, which the CMake project, the package and the tag all read.
