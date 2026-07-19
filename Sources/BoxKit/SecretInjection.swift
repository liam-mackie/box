import Foundation

/// Pure cores that turn resolved secrets into the box-proxy injection config the
/// sidecar consumes. Value *resolution* (reading env/Keychain) and file staging
/// are impure and live in `Runner`; everything here is filesystem-free and
/// unit-tested directly.
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

    struct HudsuckerConfig: Codable, Equatable {
        let secrets: [Entry]
        struct Entry: Codable, Equatable {
            let name: String
            let value: String
            let injection: SecretInjectionSpec
            let scopes: [SecretScope]
        }
    }

    /// The box-proxy secrets config (raw value + template + scopes per secret).
    /// The sidecar renders the template and matches scopes itself, so this passes
    /// the untemplated value through verbatim.
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

    /// One-line human summary for the boot log (names + location + hosts).
    public static func bootSummary(_ resolved: [Resolved]) -> String {
        resolved.map { r in
            let hosts = r.requirement.scopes.map { $0.host }.joined(separator: ",")
            return "\(r.requirement.name)(\(r.requirement.injection.location.rawValue)→\(hosts))"
        }.joined(separator: " ")
    }
}
