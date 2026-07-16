# box: a Linux image that runs Claude Code inside an Apple `container`
# microVM, with all outbound traffic forced through a hostname-allowlist proxy.
FROM node:22-bookworm-slim

# --- system deps -----------------------------------------------------------
#  squid     : egress proxy that enforces the hostname allowlist.
#              KNOWN LIMITATION: Debian's apt `squid` is built `--with-gnutls`,
#              NOT `--with-openssl` (verified on the bookworm squid 5.7 base). The
#              GnuTLS build does NOT support SSL-Bump (`http_port … ssl-bump` is a
#              FATAL "Unknown http_port option") and ships no security_file_certgen
#              helper. So SNI peek-and-splice + MITM are only available if/when this
#              image is rebuilt against an openssl-enabled squid. We do NOT ship a
#              broken proxy: the entrypoint runs a FUNCTIONAL `squid -k parse` probe
#              of an ssl-bump line and, when it fails (the apt case), falls back to
#              today's hostname-only (CONNECT host) filtering so the box still works.
#              To get SNI/MITM, build squid `--with-openssl` (or swap in such a pkg).
#  openssl   : generate the dummy self-signed cert SSL-Bump needs on its
#              `http_port … tls-cert=` line (peek/splice never serves it to a
#              client, but squid requires a cert to instantiate the TLS context).
#  iptables  : default-deny firewall so nothing can bypass the proxy
#  gosu      : drop from root -> non-root 'agent' after the firewall is up
#  iproute2  : `ss` for the readiness check in the entrypoint
#  ca-certificates : also gives us `update-ca-certificates` for the opt-in MITM CA
# (the entrypoint polls the allowlist with md5sum/coreutils to hot-reconfigure
#  squid, so no inotify package is needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
        squid openssl iptables iproute2 dnsutils ca-certificates curl wget git \
        python3 python3-pip python3-venv gosu jq less procps \
    && rm -rf /var/lib/apt/lists/*

# --- Claude Code (native build, NOT npm) -----------------------------------
# The official installer downloads the self-contained native binary — no npm
# global install, so no root-owned npm prefix for the in-guest auto-updater to
# trip over (box disables that updater anyway and keeps this version in sync
# with the host's claude itself). `box update [--to <ver>]` / the launch-time
# sync override CLAUDE_VERSION; changing it invalidates only this layer.
# HOME=/opt/claude keeps the install out of /home/agent — which the persisted
# agent-home mount hides at runtime — and out of /root (0700); the launcher is
# then exposed on PATH and the tree made world-readable for the agent.
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

# --- squid: config, allowlist, and the custom "blocked" page ---------------
COPY squid.conf /etc/squid/squid.conf
RUN mkdir -p /etc/box
COPY config/allowlist.txt /etc/box/allowlist.txt
# Replace squid's default ACCESS_DENIED page with our actionable one, in every
# language dir squid ships, so the agent sees the fix instructions on a block.
COPY deny.html /tmp/deny.html
RUN find /usr/share/squid/errors -name ERR_ACCESS_DENIED -exec cp /tmp/deny.html {} \; \
    && mkdir -p /var/log/squid /var/spool/squid \
    && chown -R proxy:proxy /var/log/squid /var/spool/squid

# --- SSL-Bump: dummy splice cert + leaf-cert DB ----------------------------
# SSL-Bump's `http_port … ssl-bump tls-cert=` needs a cert to build squid's TLS
# context even when we only peek/splice (the cert is never served on a splice).
# Generate a throwaway self-signed cert at BUILD time so first boot is fast and
# no key generation happens in the agent's runtime path.
#   /etc/squid/ssl/box-splice.pem  — combined key+cert, readable by proxy.
# `generate-host-certificates=on` (set on the port line by the entrypoint when
# MITM is enabled) makes squid forge leaf certs into a disk DB managed by the
# `security_file_certgen` helper; pre-create + initialize that DB here. Both are
# guarded against the helper being absent on a hypothetical non-openssl squid.
RUN mkdir -p /etc/squid/ssl \
    && openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
        -subj "/CN=box-splice/O=box" \
        -keyout /etc/squid/ssl/box-splice.key \
        -out    /etc/squid/ssl/box-splice.crt 2>/dev/null \
    && cat /etc/squid/ssl/box-splice.key /etc/squid/ssl/box-splice.crt \
        > /etc/squid/ssl/box-splice.pem \
    && rm -f /etc/squid/ssl/box-splice.key /etc/squid/ssl/box-splice.crt \
    && CERTGEN="$(command -v security_file_certgen || echo /usr/lib/squid/security_file_certgen)" \
    && if [ -x "$CERTGEN" ]; then \
           "$CERTGEN" -c -s /var/lib/squid/ssl_db -M 4MB || true; \
       else \
           echo "WARN: security_file_certgen not found — this squid build lacks SSL-Bump; box will fall back to hostname-only filtering at runtime." >&2; \
           mkdir -p /var/lib/squid/ssl_db; \
       fi \
    && chmod 0640 /etc/squid/ssl/box-splice.pem \
    && chown -R proxy:proxy /etc/squid/ssl /var/lib/squid/ssl_db

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
