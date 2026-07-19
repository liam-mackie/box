# box CLIENT layers applied ON TOP of a project's devcontainer base image.
#
# Generated into a build by Devcontainer.dockerfile(base:template:postCreate:):
# `__DC_BASE__` is replaced with the devcontainer's `image` (e.g. swift:6.3).
#
# Split-proxy design: the egress proxy does NOT live in this image. `--devcontainer`
# boots TWO VMs — a proxy sidecar running box's own image (box-proxy, allowlist,
# CA, secret injection; entrypoint BOX_ROLE=proxy) and this dev VM (BOX_ROLE=client)
# whose egress is iptables-locked to the sidecar's 3128. So the devcontainer
# base stays essentially stock: we only add Claude Code, the agent user, and
# the tiny toolset the client entrypoint needs. No proxy build, no glibc
# parity risk, and secret values never enter the VM the agent runs in.
#
# Constraints (v1): the base must be DEBIAN-FAMILY (apt) for the package layer
# and the uid-501 user handling below.
FROM __DC_BASE__

# Fail early and clearly on a non-apt base (alpine/musl, etc.) rather than deep
# in an apt step.
RUN command -v apt-get >/dev/null 2>&1 \
    || { echo "box: devcontainer base must be debian-family (apt); got a non-apt base" >&2; exit 1; }

# Client-entrypoint needs: iptables (egress lockdown), iproute2 (gateway/`ip`),
# gosu (privilege drop), ca-certificates (CA trust + TLS), curl (claude
# install), git/jq/less/procps (agent ergonomics, cheap).
RUN apt-get update && apt-get install -y --no-install-recommends \
        iptables iproute2 ca-certificates curl wget git gosu jq less procps \
    && rm -rf /var/lib/apt/lists/*

# Claude Code (native binary; no node needed at runtime, so a non-node base is fine).
ARG CLAUDE_VERSION=latest
RUN mkdir -p /opt/claude \
    && HOME=/opt/claude bash -c "curl -fsSL https://claude.ai/install.sh | bash -s -- ${CLAUDE_VERSION}" \
    && ln -s /opt/claude/.local/bin/claude /usr/local/bin/claude \
    && chmod -R a+rX /opt/claude \
    && claude --version

# Non-root agent at uid 501 (macOS primary uid → workspace files aren't root-owned).
# Reuse an existing uid-501 user if the base already ships one (devcontainer bases
# often have a `vscode`/`node` user; uid may or may not be 501).
RUN if getent passwd 501 >/dev/null; then \
        echo "box: reusing existing uid-501 user: $(getent passwd 501 | cut -d: -f1)"; \
    else \
        useradd -m -u 501 -s /bin/bash agent; \
    fi

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
COPY xclip-shim.sh /usr/local/bin/xclip
RUN chmod +x /usr/local/bin/xclip

WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["claude"]
