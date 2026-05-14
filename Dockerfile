# syntax=docker/dockerfile:1.7
#
# Multi-stage build for speedy-socials. Works under both `podman build`
# and `docker build`. The runtime image is distroless so the final
# binary has no shell or package manager surface.

# ── Stage 1: builder ──────────────────────────────────────────────────
FROM debian:bookworm-slim AS builder

ARG ZIG_VERSION=0.16.0
ARG TARGETARCH

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        xz-utils \
 && rm -rf /var/lib/apt/lists/*

# Resolve TARGETARCH (set automatically by buildx / podman buildx) to
# the Zig tarball naming. Defaults to x86_64 if unset (plain `docker
# build` without buildx).
RUN set -eux; \
    arch="${TARGETARCH:-amd64}"; \
    case "$arch" in \
        amd64) zig_arch="x86_64" ;; \
        arm64) zig_arch="aarch64" ;; \
        *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    url="https://ziglang.org/download/${ZIG_VERSION}/zig-linux-${zig_arch}-${ZIG_VERSION}.tar.xz"; \
    curl -fsSL "$url" -o /tmp/zig.tar.xz; \
    mkdir -p /opt/zig; \
    tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1; \
    rm /tmp/zig.tar.xz; \
    ln -s /opt/zig/zig /usr/local/bin/zig; \
    zig version

WORKDIR /src

# Copy build manifest first so the dependency fetch layer caches.
COPY build.zig build.zig.zon ./

# Copy the rest of the source tree.
COPY src ./src
COPY third_party ./third_party
COPY bench ./bench
COPY tests ./tests

RUN zig build -Doptimize=ReleaseSafe

# ── Stage 2: runtime ──────────────────────────────────────────────────
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

LABEL org.opencontainers.image.title="speedy-socials" \
      org.opencontainers.image.description="Tiger-Style ActivityPub + AT Protocol social server in Zig" \
      org.opencontainers.image.licenses="See LICENSE in source tree"

COPY --from=builder /src/zig-out/bin/speedy-socials /speedy-socials

EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/speedy-socials"]
