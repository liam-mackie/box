import Foundation

/// Pure allowlist merge logic: append new domains to the existing list,
/// skipping duplicates and blanks, preserving order. Kept side-effect-free so
/// it can be unit-tested without touching the filesystem.
public enum Allowlist {
    public struct MergeResult: Equatable, Sendable {
        public let lines: [String]
        public let added: [String]
        public let skipped: [String]
    }

    public static func merge(existing: [String], adding: [String]) -> MergeResult {
        var lines = existing
        var seen = Set(existing.map { $0.trimmingCharacters(in: .whitespaces) })
        var added: [String] = []
        var skipped: [String] = []
        for raw in adding {
            let d = raw.trimmingCharacters(in: .whitespaces)
            guard !d.isEmpty else { continue }
            if seen.contains(d) {
                skipped.append(d)
            } else {
                lines.append(d)
                seen.insert(d)
                added.append(d)
            }
        }
        return MergeResult(lines: lines, added: added, skipped: skipped)
    }

    /// Squid's `dstdomain`/`ssl::server_name` ACLs treat a leading-dot entry
    /// (`.example.com`, "this domain and all subdomains") and the bare form
    /// (`example.com`, "exactly this host") as a *fatal* conflict if both appear
    /// — `squid -k parse` rejects the config. Detect such pairs so callers can
    /// warn before writing a list that would wedge the proxy.
    ///
    /// Pure: returns `(dotted, bare)` pairs found in `lines`, ignoring blanks,
    /// comments (`#…`), and surrounding whitespace. Order follows first
    /// appearance of the bare host.
    public static func conflicts(in lines: [String]) -> [(String, String)] {
        var dotted = Set<String>()  // bare host => ".host" was seen
        var bare = Set<String>()  // bare host => "host" was seen
        var order: [String] = []  // first-seen order of bare hosts
        for raw in lines {
            let d = raw.trimmingCharacters(in: .whitespaces)
            guard !d.isEmpty, !d.hasPrefix("#") else { continue }
            if d.hasPrefix(".") {
                let host = String(d.dropFirst())
                guard !host.isEmpty else { continue }
                if dotted.insert(host).inserted, !order.contains(host) { order.append(host) }
            } else {
                if bare.insert(d).inserted, !order.contains(d) { order.append(d) }
            }
        }
        return order.filter { dotted.contains($0) && bare.contains($0) }
            .map { (".\($0)", $0) }
    }
}

/// Pure helpers for the `denied → allow` promotion flow: turning a raw squid
/// access-log host token into a candidate allowlist entry, and parsing the
/// interactive selection grammar. Both are filesystem- and TTY-free so they can
/// be unit-tested directly.
public enum DeniedHost {
    /// Map a raw blocked host (as it appears in the squid log — possibly a bare
    /// host, `host:port`, or a full URL, maybe with a trailing dot or mixed
    /// case) to a candidate `exact` host and its leading-dot `wildcard` form.
    ///
    /// Returns `nil` for anything we won't offer to allow: blanks, junk, hosts
    /// without a dot (e.g. `localhost`), hosts with characters illegal in a DNS
    /// name, and IP literals (v4/v6) — squid allowlist entries are hostnames,
    /// and an IP rule wouldn't survive the dotted-subdomain default anyway.
    public static func normalize(_ raw: String) -> (exact: String, wildcard: String)? {
        var s = raw.trimmingCharacters(in: .whitespaces).lowercased()
        guard !s.isEmpty else { return nil }

        // Strip a scheme + path/query if this is a URL: take the authority.
        if let schemeRange = s.range(of: "://") {
            s = String(s[schemeRange.upperBound...])
            if let slash = s.firstIndex(of: "/") { s = String(s[..<slash]) }
        }
        // Drop any path/query that survived (host token without a scheme).
        if let slash = s.firstIndex(of: "/") { s = String(s[..<slash]) }
        // Drop userinfo (`user@host`).
        if let at = s.lastIndex(of: "@") { s = String(s[s.index(after: at)...]) }

        // Bracketed IPv6 authority `[::1]:443` → reject outright.
        if s.hasPrefix("[") { return nil }

        // Strip a trailing `:port` (only when the remainder is all digits, so we
        // don't mistake a bare IPv6 literal's colons for a port separator).
        if let colon = s.lastIndex(of: ":") {
            let port = s[s.index(after: colon)...]
            if !port.isEmpty, port.allSatisfy(\.isNumber) {
                s = String(s[..<colon])
            }
        }

        // Multiple remaining colons ⇒ bare IPv6 literal → reject.
        if s.contains(":") { return nil }

        // Drop a trailing FQDN-root dot.
        while s.hasSuffix(".") { s = String(s.dropLast()) }
        guard !s.isEmpty else { return nil }

        // Must look like a dotted hostname: at least two labels, each made of
        // [a-z0-9-], not empty, not leading/trailing-hyphen.
        let labels = s.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard labels.count >= 2 else { return nil }
        for label in labels {
            guard !label.isEmpty, label.count <= 63 else { return nil }
            guard !label.hasPrefix("-"), !label.hasSuffix("-") else { return nil }
            guard label.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" }) else { return nil }
        }
        // Reject IPv4 literals (all labels numeric, four of them).
        if labels.count == 4, labels.allSatisfy({ $0.allSatisfy(\.isNumber) }) { return nil }

        return (exact: s, wildcard: "." + s)
    }

    /// Parse the interactive selection grammar over a `1...count` menu.
    ///
    /// Accepts `1,3` (list), `1-3` (range, inclusive, either direction), `all`
    /// (every index), `q`/empty (quit → empty set), or any combination of lists
    /// and ranges separated by commas. Whitespace is ignored.
    ///
    /// Returns the selected indices, an empty set for quit, or `nil` for invalid
    /// input (junk, malformed tokens, or any index outside `1...count`).
    public static func parseSelection(_ raw: String, count: Int) -> Set<Int>? {
        let s = raw.trimmingCharacters(in: .whitespaces).lowercased()
        if s.isEmpty || s == "q" { return [] }
        if s == "all" { return count > 0 ? Set(1...count) : [] }

        var out = Set<Int>()
        for tokenRaw in s.split(separator: ",", omittingEmptySubsequences: false) {
            let token = tokenRaw.trimmingCharacters(in: .whitespaces)
            guard !token.isEmpty else { return nil }
            if let dash = token.firstIndex(of: "-") {
                let lo = token[..<dash].trimmingCharacters(in: .whitespaces)
                let hi = token[token.index(after: dash)...].trimmingCharacters(in: .whitespaces)
                guard let a = Int(lo), let b = Int(hi) else { return nil }
                let (from, to) = a <= b ? (a, b) : (b, a)
                guard from >= 1, to <= count else { return nil }
                out.formUnion(from...to)
            } else {
                guard let n = Int(token), n >= 1, n <= count else { return nil }
                out.insert(n)
            }
        }
        return out
    }
}
