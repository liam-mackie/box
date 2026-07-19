# ── box-proxy build stage ───────────────────────────────────────────────────
# box's egress sidecar is box-proxy: a hudsucker MITM forward proxy that enforces
# the per-source allowlist, decrypts allowlisted (non-pinned) hosts to inject
# scoped secrets and log full URLs, and tunnels pinned hosts untouched. Compiled
# here from the embedded crate source; the openssl-ca + aws-lc-rs deps need cmake,
# clang, perl and the OpenSSL headers at build time.
FROM rust:1-bookworm AS proxybuild
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake clang perl pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY proxy/ ./
RUN cargo build --release --locked && cp target/release/box-proxy /box-proxy

# box: a Linux image that runs Claude Code inside an Apple `container` microVM,
# with all outbound traffic forced through the box-proxy egress sidecar. The SAME
# image runs in two roles (selected by BOX_ROLE, see entrypoint.sh):
#   client — the agent VM: runs claude, no proxy; egress iptables-locked to the
#            box-proxy sidecar it was told about.
#   proxy  — the box-proxy egress sidecar (shared daemon-owned, or a per-box
#            dedicated one): a MITM forward proxy over the per-source allowlist.
FROM node:22-bookworm-slim

# --- system deps -----------------------------------------------------------
#  openssl / ca-certificates : the MITM CA (update-ca-certificates) + general TLS,
#            and libssl3 at runtime for box-proxy (openssl-sys links it).
#  iptables  : client-role default-deny egress firewall (lock traffic to the sidecar)
#  gosu      : drop root -> non-root 'agent' after the firewall is up
#  iproute2  : `ss`/`ip` for readiness checks and gateway discovery
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssl iptables iproute2 dnsutils ca-certificates curl wget git \
        gosu less procps \
    && rm -rf /var/lib/apt/lists/*

# --- box-proxy: the egress sidecar binary (proxy role) ---------------------
COPY --from=proxybuild /box-proxy /usr/local/bin/box-proxy
RUN /usr/local/bin/box-proxy --version

# --- Claude Code (native build, NOT npm) -----------------------------------
# The official installer downloads the self-contained native binary — no npm
# global install, so no root-owned npm prefix for the in-guest auto-updater to
# trip over (box disables that updater anyway and keeps this version in sync
# with the host's claude itself). `box update [--to <ver>]` / the launch-time
# sync override CLAUDE_VERSION; changing it invalidates only this layer.
ARG CLAUDE_VERSION=latest
RUN mkdir -p /opt/claude \
    && HOME=/opt/claude bash -c "curl -fsSL https://claude.ai/install.sh | bash -s -- ${CLAUDE_VERSION}" \
    && ln -s /opt/claude/.local/bin/claude /usr/local/bin/claude \
    && chmod -R a+rX /opt/claude \
    && claude --version

# --- non-root agent --------------------------------------------------------
# uid 501 matches the default macOS primary-user uid so files written to the
# bind-mounted /workspace are owned by you on the host (no root-owned files).
RUN useradd -m -u 501 -s /bin/bash agent

# --- global egress allowlist (seeded on first run; live-editable via box allow) --
RUN mkdir -p /etc/box
COPY config/allowlist.txt /etc/box/allowlist.txt

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# --- clipboard shim ---------------------------------------------------------
# No X/Wayland in the guest, so the real xclip could never read a clipboard.
# Claude Code's Linux image-paste path shells out to xclip; this shim serves
# the host-synced image (mounted at /run/box-clipboard) instead.
COPY xclip-shim.sh /usr/local/bin/xclip
RUN chmod +x /usr/local/bin/xclip

WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["claude"]
