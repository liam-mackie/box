import Foundation

/// Pure rendering cores that turn resolved secrets into the artifacts the guest
/// consumes: the squid header/cookie include, the query-rewrite helper config,
/// and the redacted manifest. Value *resolution* (reading env/Keychain) and file
/// staging are impure and live in `Runner.secretMounts`; everything here is
/// filesystem-free and unit-tested directly.
public enum SecretInjection {
    /// A requirement paired with its resolved (raw, un-templated) value.
    public struct Resolved: Sendable, Equatable {
        public let requirement: SecretRequirement
        public let value: String
        public init(requirement: SecretRequirement, value: String) {
            self.requirement = requirement
            self.value = value
        }
    }

    /// Merge global + project requirements, deduped by name. **Global wins** on a
    /// name clash so a project can never redefine (or widen the scope of) a
    /// globally-defined secret. Order: globals first, then project-only ones.
    public static func effectiveRequirements(
        global: [SecretRequirement], project: [SecretRequirement]
    ) -> [SecretRequirement] {
        var seen = Set(global.map { $0.name })
        var out = global
        for r in project where !seen.contains(r.name) {
            seen.insert(r.name)
            out.append(r)
        }
        return out
    }

    /// Split requirements into resolved secrets and the names of unmet ones (no
    /// binding, or a binding whose value didn't resolve / was empty). `resolve`
    /// returns the raw value for a requirement's binding, or nil.
    public static func partition(
        _ reqs: [SecretRequirement], resolve: (SecretRequirement) -> String?
    ) -> (resolved: [Resolved], unmet: [String]) {
        var resolved: [Resolved] = []
        var unmet: [String] = []
        for r in reqs {
            if let v = resolve(r), !v.isEmpty {
                resolved.append(Resolved(requirement: r, value: v))
            } else {
                unmet.append(r.name)
            }
        }
        return (resolved, unmet)
    }

    /// Union of scope hosts across resolved secrets (deduped, input order). The
    /// caller still passes these through `Runner.caBumpHosts` (which drops pinned
    /// hosts and lowercases) before use.
    public static func bumpHosts(_ resolved: [Resolved]) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for r in resolved {
            for s in r.requirement.scopes {
                let h = s.host.trimmingCharacters(in: .whitespaces)
                if !h.isEmpty && seen.insert(h).inserted { out.append(h) }
            }
        }
        return out
    }

    // MARK: - squid header/cookie include

    /// Render `/etc/squid/box-inject.acl` for the header + cookie secrets. Per
    /// (secret, scope): strip any client-supplied value for that field on the host,
    /// then inject our rendered literal when the host (and path, if constrained)
    /// matches. Query secrets are handled separately (`renderQueryConfig`).
    /// Throws if a rendered value contains CR/LF (header-injection guard).
    public static func renderHeaderCookieACL(_ resolved: [Resolved]) throws -> String {
        var lines: [String] = []
        for r in resolved where r.requirement.injection.location != .query {
            let field = r.requirement.injection.location == .cookie
                ? "Cookie" : r.requirement.injection.field
            let literal = try renderedLiteral(r)
            for (i, scope) in r.requirement.scopes.enumerated() {
                let base = "sec_\(aclSafe(r.requirement.name))_\(i)"
                lines.append("acl \(base)_host dstdomain \(scope.host)")
                var addAcls = "\(base)_host"
                if let rx = pathRegex(scope) {
                    lines.append("acl \(base)_path urlpath_regex \(rx)")
                    addAcls += " \(base)_path"
                }
                lines.append("request_header_access \(field) deny \(base)_host")
                lines.append("request_header_add \(field) \"\(squidQuote(literal))\" \(addAcls)")
            }
        }
        return lines.isEmpty ? "" : lines.joined(separator: "\n") + "\n"
    }

    // MARK: - query-rewrite helper config

    /// Render the tab-separated config the `box-url-rewrite` helper reads
    /// (`host<TAB>path-regex-or-*<TAB>param<TAB>rendered-value`, one line per
    /// scope). Empty string when there are no query secrets. Throws if a rendered
    /// value contains CR/LF/TAB (would corrupt the URL or the config format).
    public static func renderQueryConfig(_ resolved: [Resolved]) throws -> String {
        var lines: [String] = []
        for r in resolved where r.requirement.injection.location == .query {
            let literal = try renderedLiteral(r, forbidTab: true)
            let param = r.requirement.injection.field
            for scope in r.requirement.scopes {
                let rx = pathRegex(scope) ?? "*"
                lines.append([scope.host, rx, param, literal].joined(separator: "\t"))
            }
        }
        return lines.isEmpty ? "" : lines.joined(separator: "\n") + "\n"
    }

    /// True if any resolved secret injects into the URL query (⇒ the entrypoint
    /// must wire up the url_rewrite helper).
    public static func hasQuery(_ resolved: [Resolved]) -> Bool {
        resolved.contains { $0.requirement.injection.location == .query }
    }

    struct HudsuckerConfig: Codable, Equatable {
        let secrets: [Entry]
        struct Entry: Codable, Equatable {
            let name: String
            let value: String
            let injection: SecretInjectionSpec
            let scopes: [SecretScope]
        }
    }

    public static func renderHudsuckerConfig(_ resolved: [Resolved]) -> String {
        let doc = HudsuckerConfig(
            secrets: resolved.map {
                HudsuckerConfig.Entry(
                    name: $0.requirement.name, value: $0.value,
                    injection: $0.requirement.injection, scopes: $0.requirement.scopes)
            })
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(doc), let json = String(data: data, encoding: .utf8)
        else {
            return #"{"secrets":[]}"#
        }
        return json
    }

    // MARK: - redacted manifest

    struct ManifestEntry: Codable {
        let name: String
        let location: String
        let field: String
        let scopes: [ScopeEntry]
        let source: String
        let note: String
        struct ScopeEntry: Codable {
            let host: String
            let pathPrefix: String?
            let pathRegex: String?
        }
    }

    /// Redacted JSON manifest (names + scopes + source label — never values) for
    /// the agent to read. `sourceLabel` maps a name to e.g. "env:GH_TOKEN".
    public static func renderManifest(
        _ resolved: [Resolved], sourceLabel: (String) -> String
    ) -> String {
        let entries = resolved.map { r in
            ManifestEntry(
                name: r.requirement.name,
                location: r.requirement.injection.location.rawValue,
                field: r.requirement.injection.location == .cookie
                    ? "Cookie" : r.requirement.injection.field,
                scopes: r.requirement.scopes.map {
                    .init(host: $0.host, pathPrefix: $0.pathPrefix, pathRegex: $0.pathRegex)
                },
                source: sourceLabel(r.requirement.name),
                note: "value hidden; box auto-attaches it to matching requests")
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(entries),
            let s = String(data: data, encoding: .utf8)
        else { return "[]" }
        return s
    }

    /// One-line human summary for the boot log (names + location + hosts).
    public static func bootSummary(_ resolved: [Resolved]) -> String {
        resolved.map { r in
            let hosts = r.requirement.scopes.map { $0.host }.joined(separator: ",")
            return "\(r.requirement.name)(\(r.requirement.injection.location.rawValue)→\(hosts))"
        }.joined(separator: " ")
    }

    // MARK: - helpers

    /// Apply the injection template to the resolved value, rejecting CR/LF (and
    /// optionally TAB) so a value can't split headers or corrupt the config.
    static func renderedLiteral(_ r: Resolved, forbidTab: Bool = false) throws -> String {
        let literal = try SecretTemplate.render(r.requirement.injection.template, value: r.value)
        if literal.contains("\r") || literal.contains("\n") {
            throw CBError(
                "secret \"\(r.requirement.name)\" renders to a value containing a newline; refusing to inject")
        }
        if forbidTab && literal.contains("\t") {
            throw CBError(
                "secret \"\(r.requirement.name)\" renders to a value containing a tab; refusing to inject as query")
        }
        return literal
    }

    /// squid ACL identifiers: keep to alphanumerics + `_` (map `-` to `_`).
    static func aclSafe(_ name: String) -> String {
        String(name.map { $0 == "-" ? "_" : $0 })
    }

    /// The urlpath_regex for a scope, or nil when the scope has no path constraint.
    static func pathRegex(_ scope: SecretScope) -> String? {
        if let rx = scope.pathRegex { return rx }
        if let p = scope.pathPrefix { return "^" + regexEscape(p) }
        return nil
    }

    /// Escape regex metacharacters in a literal path prefix.
    static func regexEscape(_ s: String) -> String {
        let special = Set("\\^$.|?*+()[]{}")
        var out = ""
        for c in s { if special.contains(c) { out.append("\\") }; out.append(c) }
        return out
    }

    /// Escape a value for a squid double-quoted string (`\` and `"`).
    static func squidQuote(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
    }
}
