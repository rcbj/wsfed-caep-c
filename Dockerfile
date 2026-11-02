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
COPY . .
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build --target wsfed-caep wsfed-demo \
 && cmake --install build \
 && apt-get purge -y build-essential cmake pkg-config libssl-dev libxml2-dev \
 && apt-get install -y --no-install-recommends libssl3 libxml2 wget ca-certificates \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/* /src
WORKDIR /app
COPY demo /app/demo
COPY scripts /app/scripts
ENV PORT=3000
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD wget -qO- "http://127.0.0.1:${PORT}/healthz" || exit 1
CMD ["wsfed-demo"]
