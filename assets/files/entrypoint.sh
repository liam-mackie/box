#!/usr/bin/env bash
# box entrypoint (runs as root inside the microVM):
#   1. start the squid egress proxy (enforces the hostname allowlist)
#   2. lock down iptables so ONLY squid can reach the outside world
#   3. drop privileges and exec the requested command as the 'agent' user
# Because 'agent' is non-root and has no NET_ADMIN capability, it cannot flush
# the firewall or bypass the proxy.
set -euo pipefail

PROXY_PORT=3128

# Egress allowlist files squid's `dstdomain` ACL unions:
#   GLOBAL_ALLOWLIST  — always present (host-materialized, live-editable via `box allow`)
#   PROJECT_ALLOWLIST — present only when a project `.box/` has been TRUSTED; the
#                       host mounts a read-only snapshot of the trusted content here.
GLOBAL_ALLOWLIST=/etc/box/allowlist.txt
PROJECT_ALLOWLIST=/run/box-allowlist/allowlist.project.txt
ALLOWLIST_ACL=/etc/squid/box-allowlist.acl

# ── SNI peek-and-splice (default-on) + opt-in MITM CA ──────────────────────
# squid.conf `include`s these three runtime-rendered files. We render them here
# (and re-render on allowlist reload) so a single squid.conf works whether or not
# this squid build supports SSL-Bump, and whether or not the user opted into MITM.
PORT_ACL=/etc/squid/box-port.acl          # the http_port line (with/without ssl-bump)
SSLBUMP_ACL=/etc/squid/box-sslbump.acl     # the ssl_bump peek/splice/bump rules
LOGFORMAT_ACL=/etc/squid/box-logformat.acl # the `logformat box …` line (SNI field gated)
SPLICE_CERT=/etc/squid/ssl/box-splice.pem  # dummy self-signed cert for the TLS context
CERT_DB=/var/lib/squid/ssl_db              # security_file_certgen leaf-cert DB (MITM)

# Opt-in MITM CA: the host mounts ~/.box/ca read-only here when `tlsInspect` is
# set (and `box ca init` has been run). Its presence is the signal to turn on
# bumping; absence ⇒ SNI splice only (the default, no decryption).
CA_MOUNT=/run/box-ca
CA_CERT_SRC="$CA_MOUNT/ca.crt"
CA_KEY_SRC="$CA_MOUNT/ca.key"
BUMP_HOSTS_SRC="$CA_MOUNT/bump-hosts.txt"  # one host/domain per line (the ONLY bumped hosts)
# Where the CA key is staged for squid: readable by squid (uid proxy) but NOT by
# the agent (uid 501). Staged root:proxy 0640 before the privilege drop.
CA_KEY_STAGED=/etc/squid/ssl/box-ca.key
CA_CERT_GUEST=/usr/local/share/ca-certificates/box-mitm-ca.crt

# Does this squid support SSL-Bump? We never assume — and we MUST NOT, because
# Debian builds its apt `squid` `--with-gnutls`, NOT `--with-openssl`, and the
# GnuTLS build does NOT implement SSL-Bump at all (`http_port … ssl-bump` is
# rejected as an "Unknown http_port option", and `%ssl::>sni` as an unsupported
# logformat code — verified against the bookworm squid 5.7 base). So a
# configure-string grep is not enough; we run a FUNCTIONAL probe:
# write a one-line ssl-bump http_port and ask `squid -k parse` whether it's
# accepted. Only a build that truly supports SSL-Bump passes. If it doesn't, we
# fall back to plain hostname-only filtering (today's behavior) so the box still
# works — just without SNI verification or MITM. Memoized into SSLBUMP_OK (0/1).
SSLBUMP_OK=
sslbump_supported() {
    if [ -z "$SSLBUMP_OK" ]; then
        SSLBUMP_OK=0
        if [ -f "$SPLICE_CERT" ]; then
            local probe; probe="$(mktemp)"
            printf 'http_port %s ssl-bump tls-cert=%s\nhttp_access deny all\n' \
                "$PROXY_PORT" "$SPLICE_CERT" > "$probe"
            # `-f <probe>` parses an isolated config; success ⇒ ssl-bump is real.
            if squid -k parse -f "$probe" >/dev/null 2>&1; then
                SSLBUMP_OK=1
            fi
            rm -f "$probe"
        fi
    fi
    [ "$SSLBUMP_OK" = 1 ]
}

# Is MITM bumping requested AND possible? Requires ssl-bump support, a mounted CA
# (cert + key), and the certgen helper. Absence of ANY ⇒ splice-only.
CERTGEN_BIN=
certgen_path() {
    if [ -z "$CERTGEN_BIN" ]; then
        CERTGEN_BIN="$(command -v security_file_certgen 2>/dev/null \
            || echo /usr/lib/squid/security_file_certgen)"
    fi
    printf '%s' "$CERTGEN_BIN"
}
mitm_enabled() {
    sslbump_supported \
        && [ -f "$CA_CERT_SRC" ] && [ -f "$CA_KEY_SRC" ] \
        && [ -x "$(certgen_path)" ]
}

# Render the `acl allowlist dstdomain …` line that squid.conf `include`s, AND the
# parallel SNI ACL + ssl_bump rules. squid refuses to parse if a listed file is
# absent, so we list the project file ONLY when it exists (i.e. a trusted project
# allowlist was mounted). Idempotent; called before `squid -k parse` and on every
# reload, so a project file appearing/disappearing (or a live `box allow`) is
# reflected in BOTH the dstdomain and the SNI ACL.
render_allowlist_acl() {
    mkdir -p "$(dirname "$ALLOWLIST_ACL")" 2>/dev/null || true
    if [ -f "$PROJECT_ALLOWLIST" ]; then
        printf 'acl allowlist dstdomain "%s" "%s"\n' "$GLOBAL_ALLOWLIST" "$PROJECT_ALLOWLIST" > "$ALLOWLIST_ACL"
    else
        printf 'acl allowlist dstdomain "%s"\n' "$GLOBAL_ALLOWLIST" > "$ALLOWLIST_ACL"
    fi
    render_sslbump_acl
}

# Render the SNI ACL + ssl_bump rules into SSLBUMP_ACL. Three shapes:
#   * ssl-bump unavailable      → empty file (fallback: hostname-only filtering)
#   * ssl-bump, no MITM (default) → `acl sni_allow ssl::server_name <same files>`
#     then peek step1 / splice sni_allow / terminate all — verify the REAL SNI,
#     no decryption.
#   * ssl-bump + MITM (`box ca init` CA mounted) → additionally bump ONLY the
#     explicitly-listed bumpHosts; everything else (Anthropic/Claude API, npm,
#     git, …) is still spliced so cert-pinned / auth-sensitive clients keep
#     working. The bump decision is by SNI, so the splice-everything-else default
#     holds even if a CONNECT host header is spoofed.
# The `sni_allow` ACL reads the SAME one-or-two allowlist files as the dstdomain
# ACL above, conditionally (project file only when present) — kept `-k parse`-clean.
render_sslbump_acl() {
    mkdir -p "$(dirname "$SSLBUMP_ACL")" 2>/dev/null || true
    if ! sslbump_supported; then
        printf '# ssl-bump unavailable in this squid build; hostname-only filtering.\n' \
            > "$SSLBUMP_ACL"
        return 0
    fi
    {
        # `step1` is NOT a builtin — squid needs the bump-step ACL declared.
        printf 'acl step1 at_step SslBump1\n'
        if [ -f "$PROJECT_ALLOWLIST" ]; then
            printf 'acl sni_allow ssl::server_name "%s" "%s"\n' \
                "$GLOBAL_ALLOWLIST" "$PROJECT_ALLOWLIST"
        else
            printf 'acl sni_allow ssl::server_name "%s"\n' "$GLOBAL_ALLOWLIST"
        fi
        # Peek at the ClientHello (step1) so squid sees the real SNI.
        printf 'ssl_bump peek step1\n'
        if mitm_enabled && [ -s "$BUMP_HOSTS_SRC" ]; then
            # Opt-in MITM: bump ONLY the listed hosts; splice the rest. The
            # bumpHosts ACL is its own list so it never widens the splice default.
            printf 'acl box_bump ssl::server_name "%s"\n' "$BUMP_HOSTS_SRC"
            # A bumped host must also be allowlisted (splice/terminate still apply
            # to non-allowlisted SNIs first): only bump when it's both allowed and
            # explicitly listed for inspection.
            printf 'ssl_bump bump box_bump\n'
        fi
        printf 'ssl_bump splice sni_allow\n'
        printf 'ssl_bump terminate all\n'
    } > "$SSLBUMP_ACL"
}

# Render the `logformat box …` line. The `%ssl::>sni` code only exists in an
# SSL-Bump-capable squid (the GnuTLS build rejects it as an unsupported code), so
# we emit the real SNI field only when ssl-bump is available, and a literal "-"
# in that column otherwise — same 7-field shape either way, so EgressLog (which
# treats "-" as "no SNI") parses both. Static; rendered once before the parse.
render_logformat_acl() {
    mkdir -p "$(dirname "$LOGFORMAT_ACL")" 2>/dev/null || true
    if sslbump_supported; then
        printf 'logformat box %%ts.%%03tu %%>a %%Ss/%%03>Hs %%<st %%rm %%ru %%ssl::>sni\n' \
            > "$LOGFORMAT_ACL"
    else
        printf 'logformat box %%ts.%%03tu %%>a %%Ss/%%03>Hs %%<st %%rm %%ru -\n' \
            > "$LOGFORMAT_ACL"
    fi
}

# Render the http_port line. ssl-bump capable ⇒ enable peek/splice on 3128 with
# the dummy splice cert; when MITM is on, also enable host-cert generation backed
# by the certgen DB. NOT capable ⇒ plain `http_port 3128` (today's fallback).
render_port_acl() {
    mkdir -p "$(dirname "$PORT_ACL")" 2>/dev/null || true
    if ! sslbump_supported; then
        printf 'http_port %s\n' "$PROXY_PORT" > "$PORT_ACL"
        return 0
    fi
    {
        if mitm_enabled && [ -s "$BUMP_HOSTS_SRC" ]; then
            # generate-host-certificates lets squid forge leaf certs (signed by the
            # mounted CA) for the bumped hosts; the splice cert seeds the TLS context.
            printf 'http_port %s ssl-bump tls-cert=%s generate-host-certificates=on dynamic_cert_mem_cache_size=4MB\n' \
                "$PROXY_PORT" "$CA_KEY_STAGED"
            printf 'sslcrtd_program %s -s %s -M 4MB\n' "$(certgen_path)" "$CERT_DB"
        else
            # Peek/splice only: a self-signed cert is enough to build the TLS ctx;
            # it is never served on a splice (the connection is tunneled verbatim).
            printf 'http_port %s ssl-bump tls-cert=%s\n' "$PROXY_PORT" "$SPLICE_CERT"
        fi
    } > "$PORT_ACL"
}

# Stage the opt-in MITM CA: install the CA cert into the guest trust store, copy
# the CA key+cert to a squid-readable PEM owned root:proxy 0640 (so squid (uid
# proxy) can sign forged leaf certs but the agent (uid 501) can NOT read the key),
# and export the env vars cert-aware clients honor. No-op unless MITM is enabled.
stage_mitm_ca() {
    mitm_enabled || return 0
    mkdir -p /etc/squid/ssl
    # squid's `tls-cert=` for a bumping port must point at a PEM holding BOTH the
    # signing key and its cert; build it from the mounted CA, key first.
    cat "$CA_KEY_SRC" "$CA_CERT_SRC" > "$CA_KEY_STAGED"
    chown root:proxy "$CA_KEY_STAGED"
    chmod 0640 "$CA_KEY_STAGED"          # proxy can read; agent (501, not in proxy) cannot
    # Trust the CA inside the guest so the agent's TLS clients accept forged leafs.
    cp "$CA_CERT_SRC" "$CA_CERT_GUEST" 2>/dev/null || true
    update-ca-certificates >/dev/null 2>&1 || true
    echo "[box] MITM TLS inspection ON — bumping only: $(tr '\n' ' ' < "$BUMP_HOSTS_SRC" 2>/dev/null)"
}

# poll_file_onchange <path> <hook-cmd…>
#   Background a loop that md5sums <path> every 2s and runs the hook whenever the
#   content changes. This is the established live-reload primitive: with no
#   apiserver to exec into us, the guest watches host-mounted files and
#   reconfigures itself. We poll rather than use inotify because inotify events
#   don't reliably cross virtiofs for host-side edits; re-reading always sees the
#   new content. No-op if the file is absent at start.
poll_file_onchange() {
    local path="$1"; shift
    [ -f "$path" ] || return 0
    (
        last="$(md5sum "$path" 2>/dev/null | cut -d' ' -f1)"
        while sleep 2; do
            cur="$(md5sum "$path" 2>/dev/null | cut -d' ' -f1)"
            if [ -n "$cur" ] && [ "$cur" != "$last" ]; then
                last="$cur"
                "$@"
            fi
        done
    ) &
}

# Reload squid's ACLs (used as the allowlist-change hook). Re-render the ACL
# include first so a project file appearing/disappearing is reflected, then ask
# squid to reload its config.
reload_squid() {
    render_allowlist_acl
    squid -k reconfigure 2>/dev/null && echo "[box] allowlist reloaded"
}

# poll_allowlists <hook-cmd…>
#   Like poll_file_onchange, but watches BOTH allowlist files at once by hashing
#   their concatenation, so a change to EITHER the global (live `box allow`) or
#   the project allowlist triggers the hook. The project file is a trusted
#   snapshot (its content is fixed for the session), so in practice only global
#   edits fire — but watching both keeps the loop correct if that ever changes.
poll_allowlists() {
    (
        hashboth() { cat "$GLOBAL_ALLOWLIST" "$PROJECT_ALLOWLIST" 2>/dev/null | md5sum | cut -d' ' -f1; }
        last="$(hashboth)"
        while sleep 2; do
            cur="$(hashboth)"
            if [ -n "$cur" ] && [ "$cur" != "$last" ]; then
                last="$cur"
                "$@"
            fi
        done
    ) &
}

# === Dynamic filesystem visibility (box fs-allow / fs-deny) ===================
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

# Stage the opt-in MITM CA (no-op unless `tlsInspect` mounted one), then render
# the runtime includes before the first parse: the http_port line (ssl-bump
# capable or plain fallback), the dstdomain allowlist, and the SNI/ssl_bump rules.
# `stage_mitm_ca` must precede `render_port_acl` (it creates the CA-key PEM the
# bumping port references). `render_allowlist_acl` also calls `render_sslbump_acl`.
stage_mitm_ca
render_logformat_acl
render_port_acl
render_allowlist_acl
if sslbump_supported; then
    echo "[box] SNI peek-and-splice ON (allowlisted SNIs spliced, others terminated)."
else
    echo "[box] NOTE: this squid lacks --with-openssl/ssl-bump; falling back to" \
         "hostname-only (CONNECT host) filtering — no SNI verification." >&2
fi

echo "[box] starting egress proxy (squid)…"
if ! squid -k parse >/dev/null 2>&1; then
    echo "[box] FATAL: squid config error:" >&2
    squid -k parse || true
    exit 1
fi
rm -f /run/squid.pid               # clear any stale pid baked into the image
squid                              # daemonise (master=root, workers=proxy); no disk cache

# wait for squid to listen before we cut off direct egress
for _ in $(seq 1 50); do
    ss -ltn 2>/dev/null | grep -q ":${PROXY_PORT}[[:space:]]" && break
    sleep 0.2
done

# Best-effort: mirror squid's access log to the host-mounted dir so
# `box denied` can read blocked hosts from the Mac side. Never fatal —
# a virtiofs mount may not be writable here, in which case `denied` is just empty.
if [ -d /var/log/box ]; then
    ( tail -n0 -F /var/log/squid/access.log >> /var/log/box/access.log 2>/dev/null & ) || true
fi

echo "[box] applying egress firewall (default-deny, proxy-only)…"
PROXY_UID="$(id -u proxy)"
if ! iptables -m owner --help >/dev/null 2>&1; then
    echo "[box] FATAL: iptables 'owner' match unavailable in this kernel." >&2
    echo "             Cannot guarantee egress isolation; refusing to start." >&2
    exit 1
fi
iptables -F OUTPUT
iptables -P OUTPUT DROP
iptables -A OUTPUT -o lo -j ACCEPT                                   # loopback (agent -> squid)
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT    # return traffic
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT                       # DNS
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner "${PROXY_UID}" -j ACCEPT     # squid's own egress
# Everything else is dropped: the agent has no direct route out and MUST use squid.

# Self-managing allowlist: `box allow <domain>` just edits the host-mounted
# global file and every running box picks it up live via the 2s poll — no
# restart, no cross-process exec. We watch both the global and the (trusted,
# snapshotted) project allowlist so a change to EITHER reloads squid.
poll_allowlists reload_squid

# [slot: extra poll loops]
# Append additional `poll_file_onchange <path> <hook>` calls here (e.g. the
# dynamic fs-policy reconciler). Keep them background loops launched before the
# final exec; they run as root so they can re-bind mounts the agent can't touch.

# Dynamic filesystem visibility: build the agent's /mnt/<basename> views from the
# hidden read-only roots per the initial policy, then re-carve whenever the host
# edits fs-policy.txt (2s md5sum poll, same primitive as the allowlist). Runs as
# root BEFORE `gosu agent`, so the agent (uid 501, no CAP_SYS_ADMIN) can neither
# undo a deny nor re-bind a denied path. No-op when there are no read-only roots.
#
# We poll the policy file directly (not via `poll_file_onchange`, which bails if
# the file is ABSENT at launch). md5sum of a missing file is empty, so this loop
# also fires the first time the host CREATES fs-policy.txt (e.g. `box fs-deny`):
# the hash flips from empty to non-empty and we re-carve.
if [ -d "$ROOTS_HIDDEN" ]; then
    fs_reconcile
    ( fs_last="$(md5sum "$FS_POLICY" 2>/dev/null | cut -d' ' -f1)"
      while sleep 2; do
          cur="$(md5sum "$FS_POLICY" 2>/dev/null | cut -d' ' -f1)"
          if [ "$cur" != "$fs_last" ]; then fs_last="$cur"; fs_reconcile; fi
      done ) &
fi

# Per-box egress audit: tee squid's access log into a box-specific dir under the
# host-mounted /var/log/box so `box log --box <id>` reads this session's traffic
# in isolation. BOX_ID is set by the host runner. The global tee above still runs
# (kept for backwards compat / `box denied`); this is best-effort and never fatal.
if [ -n "${BOX_ID:-}" ] && [ -d /var/log/box ]; then
    mkdir -p "/var/log/box/${BOX_ID}" 2>/dev/null || true
    ( tail -n0 -F /var/log/squid/access.log >> "/var/log/box/${BOX_ID}/access.log" 2>/dev/null & ) || true
fi

echo "[box] ready — egress limited to the allowlist; handing off to 'agent'."

# [slot: env-file sourcing]
# Source the host-mounted secrets file into our (root) environment, just before
# the privilege drop. `set -a` marks subsequently-assigned vars for export, so
# every KEY in the file is exported and then inherited by the final
# `exec gosu agent env … "$@"` — reaching the agent's environment. Because the
# values live in the environment block (not argv), they never show in the guest
# `ps`; they're also never echoed here, so they don't leak to box's host stderr.
# The host writes this file 0600 inside a dedicated per-box dir mounted ro, so it
# never hits the image or any persisted dir.
SECRETS_ENV=/run/box-secrets/env
if [ -f "$SECRETS_ENV" ]; then
    set -a
    # shellcheck disable=SC1090
    . "$SECRETS_ENV"
    set +a
    echo "[box] sourced injected env ($(grep -c '=' "$SECRETS_ENV" 2>/dev/null || echo 0) keys)"
fi

# When MITM TLS inspection is on, point the agent's cert-aware clients at the
# guest CA bundle (which `update-ca-certificates` regenerated to include our CA)
# so a forged leaf for a bumped host validates. Tools that ignore the system
# store read these explicitly. Empty (no extra vars) on the splice-only default,
# so the Anthropic API and other spliced/pinned clients see no MITM cert at all.
CA_ENV=()
if mitm_enabled; then
    CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
    CA_ENV=(
        NODE_EXTRA_CA_CERTS="${CA_CERT_GUEST}"
        GIT_SSL_CAINFO="${CA_BUNDLE}"
        PIP_CERT="${CA_BUNDLE}"
        REQUESTS_CA_BUNDLE="${CA_BUNDLE}"
        SSL_CERT_FILE="${CA_BUNDLE}"
    )
fi

PROXY_URL="http://127.0.0.1:${PROXY_PORT}"
exec gosu agent env \
    HOME=/home/agent \
    HTTP_PROXY="${PROXY_URL}"  HTTPS_PROXY="${PROXY_URL}" \
    http_proxy="${PROXY_URL}"  https_proxy="${PROXY_URL}" \
    NO_PROXY="localhost,127.0.0.1,::1" no_proxy="localhost,127.0.0.1,::1" \
    "${CA_ENV[@]+"${CA_ENV[@]}"}" \
    "$@"
