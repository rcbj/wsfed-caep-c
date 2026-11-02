# wsfed-caep

C and C++ WS-Federation relying party. One implementation, in C++17. `include/iya/wsfed.hpp` is the class surface. `include/iya_wsfed.h` is the `extern "C"` ABI over those classes. Both link the CMake target `wsfed`. Version 0.1.0. License MIT (`LICENSE`). Publishing is not a package registry. When this tree is published, `develop` and `main` are the same commit.

## Usage

`iya::wsfed::RelyingParty::FromFile("wsfed.json", "")`, then `Login` and `HandleReply`. The C functions are `iya_wsfed_party_create`, `iya_wsfed_begin_login`, and `iya_wsfed_handle_reply`. JSON keys are `realm`, `replyUrl`, `idpMetadata`, `privateKey`, `certificate`, `idpCa`, `idpEntityId`, `clockSkewSeconds`, `wantAssertionsEncrypted`, `allowUnsolicited`, `requestTokenType`, `signals`, and `ssf`.

The party accepts SAML 2.0 assertions with bearer confirmation `urn:oasis:names:tc:SAML:2.0:cm:bearer`. It reads IdP metadata, writes RP metadata, verifies XML signatures (rsa-sha256 is `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`), decrypts encrypted elements, and caches assertion ids. Exclusive canonicalization is `http://www.w3.org/2001/10/xml-exc-c14n#`. Status success is `urn:oasis:names:tc:SAML:2.0:status:Success`. The default subject attribute is `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier`. `wsfed-caep generate-keys` writes a self-signed RSA key pair. The subject key identifier is the SHA-1 of the PKCS#1 public key. The common name follows the realm and is cut at 64 characters.

A C function logs once with `fprintf(stderr, ...)` and returns an error. The C++ method throws `std::runtime_error` with that message and does not log again.

## signals

Omitted or `true` means on. The resolved configuration leaves `signals_set` false in that case, which is the omitted key, and the receiver runs when a transmitter is configured. `false` sets `signals_set` and stores `signals` false. It does not start the receiver and does not require transmitter metadata. The relying party never starts the receiver itself; `SignalsReceiver` is separate. `Stop` waits until the background poll loop has finished. Sign-in does not change when signals are off, because WS-Federation does not send OAuth scopes. A non-boolean raises a config error: `signals must be true or false`. The shipped demo omits the key.

## Tests

```bash
docker build --target test .
```

The `test` stage builds with CMake and runs `ctest` in `debian:bookworm`. GitHub Actions uses that command. The demo image does not run the suite. OpenSSL and libxml2 come from Debian packages. This tree does not wrap another WS-Federation relying party.

C tests cover configuration, metadata, sign-in, signed and encrypted assertions, replay, the self-signed certificate, the SSF poll receiver, the setup script's signals behavior, and the demo handler. `tests/cpp_smoke.cpp` calls the C++ classes and links the same library. No live iya-sts.

## Layout

`include/` and `src/` are the library. `tests/` is the suite. `demo/` is the HTTP handler. `wsfed-demo` and `wsfed-caep` are the installed commands. `scripts/configure_iya_sts.py` registers the demo with iya-sts and shells out to `wsfed-caep` on `PATH`; the container `PORT` wins over the shell `PORT`. `Dockerfile` and comment-free `docker-compose.yml` use image `wsfed-caep-c-demo`, `network_mode: host`, `ENV PORT=3000`, and a health check of `http://127.0.0.1:${PORT}/healthz`.

## Demo

`PORT` defaults to 3000. Loopback realm and reply URLs follow the running port. Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `200` and `ok`. The page links to `/login`, which redirects with `wa=wsignin1.0`, `wtrealm`, `wreply`, and `wctx`. The reply URL handles the POST and sign-out cleanup. `POST /logout` signs out. Demo JSON uses `file:` placeholders. Do not commit `demo/generated`.

```sh
docker compose build
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/demo:/app/demo" \
  wsfed-caep-c-demo \
  wsfed-caep generate-keys --config demo/wsfed.json
```
