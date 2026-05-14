# speedy-socials task runner. Requires `just` (https://just.systems).
# Container recipes use podman per project preference; substitute
# `docker` if you prefer — the Dockerfile is compatible with both.

default:
    @just --list

# ── Zig build targets ─────────────────────────────────────────────────

build:
    zig build

build-release:
    zig build -Doptimize=ReleaseSafe

test:
    zig build test --summary all

sim:
    zig build sim

bench:
    zig build bench-storage

run:
    zig build run

clean:
    rm -rf .zig-cache zig-out

# ── Container ─────────────────────────────────────────────────────────

container-build:
    podman build -t speedy-socials:dev .

container-run: container-build
    podman run --rm -p 8080:8080 speedy-socials:dev

# ── Convenience ───────────────────────────────────────────────────────

# Run zig fmt across the tree.
fmt:
    zig fmt build.zig src tests bench

# Check formatting without rewriting files.
fmt-check:
    zig fmt --check build.zig src tests bench
