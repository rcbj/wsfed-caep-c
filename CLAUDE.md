# wsfed-caep

C and C++ WS-Federation relying party. One implementation, in C++17. `include/iya/wsfed.hpp` is the class surface. `include/iya_wsfed.h` is the `extern "C"` ABI over those classes. Both link the CMake target `iya_wsfed` (`iya::wsfed` to a consumer of the installed package). Version 0.1.1. License MIT (`LICENSE`). The library is a CMake package: `find_package(iya_wsfed)` gives `iya::wsfed`; static by default, shared with `BUILD_SHARED_LIBS`; `IYA_WSFED_BUILD_TESTS` and `IYA_WSFED_BUILD_PROGRAMS` default on only at the top level. `tests/package/check.sh` (run by the Docker test stage) installs both variants and builds the smoke test against each. A pull request merged into `main` releases the library after the test workflow succeeds on that commit: `release.yml` tags `v<VERSION>` and makes a GitHub Release, whose source archive is what a package recipe (such as a ConanCenter one) builds from. A direct push does not release. A tag that already exists stays; the next release is a new version in `VERSION`, which the CMake project, the package and the tag all read. When this tree is published, `develop` and `main` are the same commit.

## Usage

`iya::wsfed::RelyingParty::FromFile("wsfed.json", "")`, then `Login` and `HandleReply`. The C functions are `iya_wsfed_party_create`, `iya_wsfed_begin_login`, and `iya_wsfed_handle_reply`. JSON keys are `realm`, `replyUrl`, `idpMetadata`, `privateKey`, `certificate`, `idpCa`, `idpEntityId`, `clockSkewSeconds`, `wantAssertionsEncrypted`, `allowUnsolicited`, `requestTokenType`, `signals`, and `ssf`.

The party accepts SAML 2.0 assertions with bearer confirmation `urn:oasis:names:tc:SAML:2.0:cm:bearer`. It reads IdP metadata, writes RP metadata, verifies XML signatures (rsa-sha256 is `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`), decrypts encrypted elements, and caches assertion ids. Exclusive canonicalization is `http://www.w3.org/2001/10/xml-exc-c14n#`. Status success is `urn:oasis:names:tc:SAML:2.0:status:Success`. The default subject attribute is `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier`. `wsfed-caep generate-keys` writes a self-signed RSA key pair. The subject key identifier is the SHA-1 of the PKCS#1 public key. The common name follows the realm and is cut at 64 characters.

A C function logs once with `fprintf(stderr, ...)` and returns an error. The C++ method throws `std::runtime_error` with that message and does not log again.

## signals

Omitted or `true` means on. The resolved configuration leaves `signals_set` false in that case, which is the omitted key, and the receiver runs when a transmitter is configured. `false` sets `signals_set` and stores `signals` false. It does not start the receiver and does not require transmitter metadata. The relying party never starts the receiver itself; `SignalsReceiver` is separate. `Stop` waits until the background poll loop has finished. Sign-in does not change when signals are off, because WS-Federation does not send OAuth scopes. A non-boolean raises a config error: `signals must be true or false`. The shipped demo omits the key.

**Plain http (#14).** `http_send()` in `src/http.cpp` is the one place every fetch goes through; it refuses a URL with whitespace or a control character, and plain `http://` to a non-loopback host (`127.0.0.0/8`, `::1`, `localhost`; userinfo never counts), before connecting, naming only `http://host[:port]`. It follows no redirect. The tests are `PlainHttpMetadataChecks()` and `PlainHttpTransmitterChecks()` in `tests/cases.c`, run from the registered `TestReadsTheSecurityTokenServiceRole` and `TestRefusesATransmitterWithoutPollDelivery`.

## Tests

```bash
docker build --target test .
```

The `test` stage builds with CMake and runs `ctest` in `debian:bookworm`. GitHub Actions uses that command. The demo image does not run the suite. OpenSSL and libxml2 come from Debian packages. This tree does not wrap another WS-Federation relying party.

C tests cover configuration, metadata, sign-in, signed and encrypted assertions, replay, the self-signed certificate, the SSF poll receiver, the setup script's signals behavior, and the demo handler. `tests/cpp_smoke.cpp` calls the C++ classes and links the same library. `tests/trust.c` serves HTTPS from a four-certificate chain shaped like iya-sts's and checks that the whole `idpCa` chain file is the trust store (the leaf alone is refused), that the host name is verified (right chain, wrong name refused; DNS name and `127.0.0.1` via an IP SAN accepted), and that `scripts/trust_chain.py` writes the whole chain from `GET /tls/server-certificate` and from the handshake.

## Live test and nightly

`python3 scripts/live_iya_sts.py` (host stdlib python3 and Docker; never CMake on the host) starts a fresh iya-sts `main` in memory mode as container `iya-sts-live-wsfed-caep-c` on `LIVE_STS_PORT` (default 18529), builds the demo image from a scratch copy of the checkout, generates the key pair with `wsfed-caep` inside it, runs `scripts/configure_iya_sts.py` on the host (which writes the trust chain), rebuilds the image (which bakes the chain in), checks the image's chain equals the saved one, runs `wsfed-caep-c-live-demo` with `--network host` on `LIVE_DEMO_PORT` (default 18629) mounting only `rp.key`, `rp.crt` and `idp-metadata.xml`, signs in through `/authn-api`, emits `credential-change` then `session-revoked`, and checks `GET /live-status`. `IYA_STS_URL` and `IYA_STS_IMAGE` select an existing iya-sts or image. It never binds 3000, 8081 or 18481-18495. Always against a fresh iya-sts: a second run against an already-registered relying party is not supported. `.github/workflows/nightly.yml` runs the unit image and the live script at 07:54 UTC (`54 7 * * *`).

`/live-status` is `{signedIn, subject, receiver, events: [{type, jti}]}`, never tokens. iya-sts `main` puts the assertion id in `SessionIndex`, so `session-revoked` matches no tracked session; the demo (`Impl::remember` in `src/demo.cpp`, not the library) then ends its one local session and untracks it.

## idpCa, the iya-sts trust chain

`idpCa` (demo default `file:generated/idp-ca.pem`) is iya-sts's listener CA trust chain. `scripts/configure_iya_sts.py` writes the whole chain on every run via `scripts/trust_chain.py` (`GET /tls/server-certificate`, falling back to the handshake) and prints the path, anchor subject and SHA-256. `src/http.cpp` loads every PEM block as an anchor and verifies the host name (`SSL_set1_host`, or `X509_VERIFY_PARAM_set1_ip_asc` for an IP literal, which gets no SNI). The demo stage compiles from `CMakeLists.txt`, `VERSION`, `include`, `src`, `tests`, then `COPY demo /app/demo`; `.dockerignore` excludes `demo/generated/*` except `idp-ca.pem`, so the image carries the chain and no keys, and a build without it still succeeds. Rebuild the demo image after re-running the install script against a different iya-sts.

The install script never prints a generated test-user password: it writes it to `demo/generated/<user>.password` (created mode 0600) and prints only that path. No line it or the live script prints carries anything derived from a password or secret.

## Layout

`include/` and `src/` are the library, except the demo web app: `src/demo.cpp`, `src/demo_c_api.cpp` and the private headers `src/demo.hpp` (`DemoApp`, `DemoMain`) and `src/iya_wsfed_demo.h` (`iya_wsfed_app_*`) are the `iya_wsfed_demo` target, built only with the programs or the tests and never installed, so neither the library nor its public headers carry the demo. `src/c_api_internal.hpp` holds the C wrapper's `PartyBox` and `report_std`, which both C files use. `tests/` is the suite. `demo/` holds the demo's configuration and pages. `wsfed-demo` and `wsfed-caep` are the installed commands. `scripts/configure_iya_sts.py` registers the demo with iya-sts, writes the trust chain, and shells out to `wsfed-caep` on `PATH`; the container `PORT` wins over the shell `PORT`. `Dockerfile` and comment-free `docker-compose.yml` use image `wsfed-caep-c-demo`, `network_mode: host`, `ENV PORT=3000`, and a health check of `http://127.0.0.1:${PORT}/healthz`.

## Demo

`PORT` defaults to 3000. Loopback realm and reply URLs follow the running port. Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `200` and `ok`. The page links to `/login`, which redirects with `wa=wsignin1.0`, `wtrealm`, `wreply`, and `wctx`. The reply URL handles the POST and sign-out cleanup. `POST /logout` signs out. Demo JSON uses `file:` placeholders. Do not commit `demo/generated`.

```sh
docker compose build
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/demo:/app/demo" \
  wsfed-caep-c-demo \
  wsfed-caep generate-keys --config demo/wsfed.json
```
