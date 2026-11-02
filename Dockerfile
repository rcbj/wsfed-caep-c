# `docker build --target test` runs the suite in this image.
# The demo image below does not run it.
FROM debian:bookworm AS test
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake pkg-config libssl-dev libxml2-dev python3 ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake pkg-config libssl-dev libxml2-dev wget ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# Only what the build reads, so a new trust chain in demo/ does not rebuild the binaries.
COPY CMakeLists.txt VERSION ./
COPY include include
COPY src src
COPY tests tests
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build --target wsfed-caep wsfed-demo \
 && cmake --install build \
 && apt-get purge -y build-essential cmake pkg-config libssl-dev libxml2-dev \
 && apt-get install -y --no-install-recommends libssl3 libxml2 wget ca-certificates \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/* /src
WORKDIR /app
# demo/ comes after the build. .dockerignore admits one file of demo/generated:
# idp-ca.pem, the iya-sts listener CA trust chain scripts/configure_iya_sts.py
# writes where idpCa names it. When it exists, this COPY puts it at
# /app/demo/generated/idp-ca.pem; when it does not (a fresh clone, CI), the
# directory carries nothing from demo/generated and the build still succeeds.
# Keys and metadata never enter the image.
COPY demo /app/demo
COPY scripts /app/scripts
ENV PORT=3000
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD wget -qO- "http://127.0.0.1:${PORT}/healthz" || exit 1
CMD ["wsfed-demo"]
