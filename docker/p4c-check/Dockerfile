# Multi-stage image for running `p4test --parse-only` against the
# bundled .p4 vocab files. Pinned to a specific p4c version so CI
# behaviour does not drift when `p4lang/p4c:latest` is repointed.
#
# Bumping the version: edit the FROM tag below and re-run
# `make p4c-check` to regenerate the local image; CI rebuilds via
# buildx cache automatically.

# --- Stage 1: p4c base + missing system dep ---
#
# p4lang/p4c:1.2.5.12 (Ubuntu 20.04) ships p4test but forgets to
# install libboost-iostreams1.71.0 that the binary dlopens.
# Install it once at image build time so the runtime container
# doesn't need network access.
FROM p4lang/p4c:1.2.5.12 AS p4c-base

RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      libboost-iostreams1.71.0 \
 && rm -rf /var/lib/apt/lists/*

# --- Stage 2: wrapper script that iterates the vocab dir ---
#
# Splitting check.sh into its own COPY layer means buildx caches the
# (heavier) base + libboost layers separately from the (tiny) script
# layer — a script edit only invalidates this final layer.
FROM p4c-base AS p4c-check

COPY check.sh /usr/local/bin/p4c-check
RUN chmod +x /usr/local/bin/p4c-check

WORKDIR /work
ENTRYPOINT ["/usr/local/bin/p4c-check"]
