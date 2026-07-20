#!/usr/bin/env bash
# box entrypoint (runs as root inside the microVM). Two roles, selected by
# BOX_ROLE (set by the host runner / daemon):
#
#   proxy  — the box-proxy EGRESS SIDECAR. A hudsucker MITM forward proxy that
#            allows only CONNECTs on the allowlist for the requesting source,
#            decrypts allowlisted (non-pinned) hosts to inject scoped secrets and
#            log full URLs, and tunnels pinned hosts untouched. Shared (one proxy
#            for many boxes, per-source isolation) or dedicated. No agent, no claude.
#   client — the AGENT VM. No proxy here; egress is iptables-locked to the
#            sidecar at BOX_PROXY_ADDR, then we drop to the non-root 'agent'.
#
# There is no co-located single-VM role any more: every box is an agent VM plus
# a box-proxy sidecar. Because 'agent' is non-root without NET_ADMIN, it can't
# flush the firewall or reach anything but the sidecar.
set -euo pipefail

PROXY_PORT=3128
ROLE="${BOX_ROLE:-client}"

# Per-box egress access log (box-proxy appends to it; the host mounts the parent).
if [ -n "${BOX_ID:-}" ]; then
    ACCESS_LOG="/var/log/box/${BOX_ID}/access.log"
else
    ACCESS_LOG="/var/log/box/access.log"
fi

# === Dynamic filesystem visibility (box fs-allow / fs-deny) — client role =====
#
# Broad read-only roots are mounted by the host at the HIDDEN path
# /mnt/.roots/<basename> (the framework locks the mount LIST at boot, so a new
# root can't appear live — but we CAN bind/unbind subpaths of an already-present
# mount). The agent's working view lives at /mnt/<basename>, which we (root)
# rebuild as bind-mounts of only the ALLOWED subpaths, reconciled from the
# host-edited /etc/box/fs-policy.txt every 2s.
#
# This is VISIBILITY control, not a hard boundary: an already-open fd survives a
# umount (we use `umount -l` and accept the race), the reconcile lags up to ~2s,
# and a brand-new root needs a restart. For real secrets, exclude at create time
# via a scoped readOnlyRoots — see FsPolicy.swift.
FS_POLICY=/etc/box/fs-policy.txt
ROOTS_HIDDEN=/mnt/.roots

# fs_decision <path>  →  prints "allow" or "deny"
#   The effective verb for <path> under the current policy: the verb of the
#   LONGEST rule path that is a prefix of (or equal to) <path>; default "allow"
#   (whole root visible, deny subtracts — matches FsPolicy.swift). Rules come
#   from $FS_POLICY: lines "allow <path>" / "deny <path>" / bare "<path>" (=deny).
fs_decision() {
    local target="$1" best_len=-1 best_verb="allow"
    [ -f "$FS_POLICY" ] || { printf 'allow'; return; }
    local verb path line
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line#"${line%%[![:space:]]*}"}"   # ltrim
        [ -z "$line" ] && continue
        case "$line" in \#*) continue ;; esac
        case "$line" in
            allow\ *) verb="allow"; path="${line#allow }" ;;
            deny\ *)  verb="deny";  path="${line#deny }" ;;
            *)        verb="deny";  path="$line" ;;        # bare path = deny
        esac
        path="${path#"${path%%[![:space:]]*}"}"; path="${path%"${path##*[![:space:]]}"}"
        case "$path" in /*) : ;; *) continue ;; esac       # absolute only
        case "$path" in *..*) continue ;; esac             # no escapes
        # Is $path a prefix of (or equal to) $target?
        if [ "$path" = "$target" ] || [ "${target#"$path"/}" != "$target" ]; then
            if [ "${#path}" -gt "$best_len" ]; then best_len="${#path}"; best_verb="$verb"; fi
        fi
    done < "$FS_POLICY"
    printf '%s' "$best_verb"
}

# fs_policy_touches <root>  →  exit 0 if any rule targets <root> or a descendant.
fs_policy_touches() {
    local root="$1" line path
    [ -f "$FS_POLICY" ] || return 1
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line#"${line%%[![:space:]]*}"}"
        [ -z "$line" ] && continue
        case "$line" in \#*) continue ;; esac
        case "$line" in allow\ *) path="${line#allow }" ;; deny\ *) path="${line#deny }" ;; *) path="$line" ;; esac
        path="${path#"${path%%[![:space:]]*}"}"; path="${path%"${path##*[![:space:]]}"}"
        if [ "$path" = "$root" ] || [ "${path#"$root"/}" != "$path" ]; then return 0; fi
    done < "$FS_POLICY"
    return 1
}

# fs_carve_dir <visible-dir> <hidden-dir>
#   Recursively bind-mount the ALLOWED parts of <hidden-dir> onto <visible-dir>.
#   If the whole subtree is allowed (no deeper deny under it), bind it in one go;
#   otherwise mkdir the visible dir and descend per child. Mirrors the recursive
#   carve in FsPolicy.reconcile.
fs_carve_dir() {
    local vis="$1" hidden="$2"
    # Any rule strictly below this node? Compute this FIRST: a denied directory
    # may still contain an allowed child (e.g. `deny .../secret` + `allow
    # .../secret/public`), so we must descend before honoring a deny here.
    local deeper=0 line path
    if [ -f "$FS_POLICY" ]; then
        while IFS= read -r line || [ -n "$line" ]; do
            line="${line#"${line%%[![:space:]]*}"}"; [ -z "$line" ] && continue
            case "$line" in \#*) continue ;; esac
            case "$line" in allow\ *) path="${line#allow }" ;; deny\ *) path="${line#deny }" ;; *) path="$line" ;; esac
            path="${path#"${path%%[![:space:]]*}"}"; path="${path%"${path##*[![:space:]]}"}"
            if [ "$path" != "$vis" ] && [ "${path#"$vis"/}" != "$path" ]; then deeper=1; break; fi
        done < "$FS_POLICY"
    fi
    if [ "$deeper" -eq 0 ]; then
        # Leaf decision: bind the entire subtree iff it's allowed here.
        [ "$(fs_decision "$vis")" = "deny" ] && return 0
        mkdir -p "$vis"
        mount --bind -o ro "$hidden" "$vis" 2>/dev/null \
            || echo "[box] fs: failed to bind $hidden -> $vis" >&2
        return 0
    fi
    # Deeper rule(s) exist → descend per child (only meaningful for directories).
    if [ -d "$hidden" ]; then
        mkdir -p "$vis"
        local name
        for name in "$hidden"/* "$hidden"/.[!.]* "$hidden"/..?*; do
            [ -e "$name" ] || continue
            fs_carve_dir "$vis/$(basename "$name")" "$name"
        done
    else
        # A file with a deeper rule can't happen meaningfully; bind it if allowed.
        mount --bind -o ro "$hidden" "$vis" 2>/dev/null || true
    fi
}

# fs_reconcile
#   Reconcile every /mnt/<basename> to the current policy. For each hidden root
#   /mnt/.roots/<basename>: lazily unmount whatever's currently at the visible
#   /mnt/<basename> (so a deny takes hold — open fds survive, accepted), then
#   rebuild it. Roots untouched by any rule are bound whole (today's behavior).
fs_reconcile() {
    [ -d "$ROOTS_HIDDEN" ] || return 0
    local hidden base vis name
    for hidden in "$ROOTS_HIDDEN"/*; do
        [ -e "$hidden" ] || continue
        base="$(basename "$hidden")"
        vis="/mnt/$base"
        # Tear down any existing binds under the visible view (deepest first), then
        # the visible mount itself. Lazy unmount: in-use mounts detach when freed.
        while read -r _ mnt _; do
            case "$mnt" in
                "$vis"|"$vis"/*) umount -l "$mnt" 2>/dev/null || true ;;
            esac
        done < <(awk '{print $1" "$2" "$3}' /proc/self/mounts | sort -rk2)
        rm -rf "$vis" 2>/dev/null || true
        if fs_policy_touches "$vis"; then
            fs_carve_dir "$vis" "$hidden"      # carve per policy
        else
            mkdir -p "$vis"                    # untouched → whole root visible
            mount --bind -o ro "$hidden" "$vis" 2>/dev/null \
                || echo "[box] fs: failed to bind $hidden -> $vis" >&2
        fi
    done
    echo "[box] fs-policy reconciled"
}

# The vmnet-gateway (= the Mac) name + scoped local egress holes (client role).
# Resolve the gateway and expose it as `host.box` in /etc/hosts, then open OUTPUT
# to it on the requested TCP ports ONLY. Public egress stays proxy-gated; just
# these private-gateway:port flows bypass the proxy, so an agent can reach a
# Mac-side service (SQL Server, a colima/container port forwarded to the Mac).
apply_local_egress() {
    BOX_GATEWAY="$(ip route 2>/dev/null | awk '/^default/ {print $3; exit}')"
    [ -n "${BOX_GATEWAY}" ] || return 0
    if ! grep -q ' host.box$' /etc/hosts 2>/dev/null; then
        printf '%s host.box\n' "${BOX_GATEWAY}" >> /etc/hosts
    fi
    if [ -n "${BOX_LOCAL_EGRESS:-}" ]; then
        IFS=',' read -ra _ports <<< "${BOX_LOCAL_EGRESS}"
        for _p in "${_ports[@]}"; do
            _p="${_p##*:}"                       # accept host:port or bare port
            case "$_p" in ''|*[!0-9]*) continue ;; esac   # numeric ports only
            iptables -A OUTPUT -p tcp -d "${BOX_GATEWAY}" --dport "${_p}" -j ACCEPT
            echo "[box] local egress allowed: host.box:${_p} (${BOX_GATEWAY}:${_p})"
        done
    fi
}

# The shared default-deny OUTPUT skeleton (loopback, return traffic, DNS).
apply_firewall_base() {
    iptables -F OUTPUT
    iptables -P OUTPUT DROP
    iptables -A OUTPUT -o lo -j ACCEPT                                # loopback
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT # return traffic
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT                    # DNS
    iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
}

# ── proxy role: run the box-proxy egress sidecar ────────────────────────────
# box-proxy needs no firewall of its own: it IS the egress point, and each
# per-run vmnet network holds only this sidecar + its client box(es) + the host
# gateway. It reads the allowlists, MITM CA, and secret-injection config from
# their mounted paths and re-reads them every 2s, so there is nothing to render
# or reload from here.
if [ "$ROLE" = proxy ]; then
    mkdir -p "$(dirname "$ACCESS_LOG")"
    export BOX_ACCESS_LOG="$ACCESS_LOG"
    echo "[box] egress proxy (box-proxy) ready on :${PROXY_PORT}."
    exec box-proxy
fi

# ── client role: no proxy here — lock egress to the sidecar ─────────────────
if [ "$ROLE" != client ]; then
    echo "[box] FATAL: unknown BOX_ROLE='$ROLE' (expected client or proxy)." >&2
    exit 1
fi
if [ -z "${BOX_PROXY_ADDR:-}" ]; then
    echo "[box] FATAL: BOX_ROLE=client but BOX_PROXY_ADDR is unset." >&2
    exit 1
fi
PROXY_HOST="${BOX_PROXY_ADDR%:*}"
PROXY_TCP_PORT="${BOX_PROXY_ADDR##*:}"
case "$PROXY_TCP_PORT" in ''|*[!0-9]*) PROXY_TCP_PORT="$PROXY_PORT" ;; esac

# MITM CA: the box-proxy sidecar bumps allowlisted (non-pinned) hosts by default,
# so the agent must trust box's CA. The host mounts the cert only (the signing
# key stays in the sidecar). Pinned hosts (Anthropic API, npm, git) are tunneled
# untouched, so their real certs are unaffected.
CA_MOUNT=/run/box-ca
CA_CERT_SRC="$CA_MOUNT/ca.crt"
CA_CERT_GUEST=/usr/local/share/ca-certificates/box-mitm-ca.crt
if [ -f "$CA_CERT_SRC" ]; then
    cp "$CA_CERT_SRC" "$CA_CERT_GUEST" 2>/dev/null || true
    update-ca-certificates >/dev/null 2>&1 || true
    echo "[box] MITM CA trusted (the sidecar decrypts allowlisted hosts)."
fi

# Wait for the sidecar's Envoy to listen before cutting direct egress (max ~10s;
# claude retries anyway, this just avoids a noisy first request).
for _ in $(seq 1 50); do
    if (echo -n > "/dev/tcp/${PROXY_HOST}/${PROXY_TCP_PORT}") 2>/dev/null; then break; fi
    sleep 0.2
done

echo "[box] applying egress firewall (default-deny, sidecar ${BOX_PROXY_ADDR})…"
apply_firewall_base
iptables -A OUTPUT -p tcp -d "${PROXY_HOST}" --dport "${PROXY_TCP_PORT}" -j ACCEPT
apply_local_egress
# Everything else is dropped: the agent's only route out is the sidecar proxy.

CLAUDE_SETTINGS_SRC=/run/box-claude-settings/settings.json
CLAUDE_SETTINGS_DST=/home/agent/.claude/settings.json
if [ -f "$CLAUDE_SETTINGS_SRC" ] && [ -f "$CLAUDE_SETTINGS_DST" ]; then
    mount --bind -o ro "$CLAUDE_SETTINGS_SRC" "$CLAUDE_SETTINGS_DST" \
        && echo "[box] host claude hooks/statusline stripped from the mounted config."
fi

# Dynamic filesystem visibility: build the agent's /mnt/<basename> views from the
# hidden read-only roots per the initial policy, then re-carve whenever the host
# edits fs-policy.txt (2s md5sum poll). Runs as root BEFORE `gosu agent`, so the
# agent (uid 501, no CAP_SYS_ADMIN) can neither undo a deny nor re-bind a denied
# path. No-op when there are no read-only roots. Supervisory `set +e`:
# fs-policy.txt is absent until the first `box fs-deny`, and md5sum of a missing
# file exits 1 — errexit would kill the loop before its first tick.
if [ -d "$ROOTS_HIDDEN" ]; then
    fs_reconcile
    ( set +e
      fs_last="$(md5sum "$FS_POLICY" 2>/dev/null | cut -d' ' -f1)"
      while sleep 2; do
          cur="$(md5sum "$FS_POLICY" 2>/dev/null | cut -d' ' -f1)"
          if [ "$cur" != "$fs_last" ]; then fs_last="$cur"; fs_reconcile; fi
      done ) &
fi

echo "[box] ready — egress limited to the allowlist; handing off to 'agent'."

# Source the host-mounted secrets ENV file into our (root) environment just
# before the privilege drop. `set -a` exports every KEY so the final
# `exec gosu agent env …` inherits them. Values live in the environment block
# (not argv), so they never show in the guest `ps`, and are never echoed here.
# (This is env-var injection, where the agent CAN read the value; proxy-side
# header/query/cookie injection — where it can't — happens in the box-proxy
# sidecar.) The host writes this file 0600 in a per-box dir mounted ro.
SECRETS_ENV=/run/box-secrets/env
if [ -f "$SECRETS_ENV" ]; then
    set -a
    # shellcheck disable=SC1090
    . "$SECRETS_ENV"
    set +a
    echo "[box] sourced injected env ($(grep -c '=' "$SECRETS_ENV" 2>/dev/null || echo 0) keys)"
fi

# When a MITM CA is trusted, point cert-aware clients at the guest CA bundle
# (regenerated by update-ca-certificates to include it). Empty otherwise, so the
# Anthropic API and other pinned clients see no extra cert.
CA_ENV=()
if [ -f "$CA_CERT_SRC" ]; then
    CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
    CA_ENV=(
        NODE_EXTRA_CA_CERTS="${CA_CERT_GUEST}"
        GIT_SSL_CAINFO="${CA_BUNDLE}"
        PIP_CERT="${CA_BUNDLE}"
        REQUESTS_CA_BUNDLE="${CA_BUNDLE}"
        SSL_CERT_FILE="${CA_BUNDLE}"
    )
fi

# The agent's proxy env points at the sidecar (parsed from BOX_PROXY_ADDR).
PROXY_URL="http://${PROXY_HOST}:${PROXY_TCP_PORT}"
exec gosu agent env \
    HOME=/home/agent \
    HTTP_PROXY="${PROXY_URL}"  HTTPS_PROXY="${PROXY_URL}" \
    http_proxy="${PROXY_URL}"  https_proxy="${PROXY_URL}" \
    NO_PROXY="localhost,127.0.0.1,::1" no_proxy="localhost,127.0.0.1,::1" \
    "${CA_ENV[@]+"${CA_ENV[@]}"}" \
    "$@"
