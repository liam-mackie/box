import Foundation

/// Proxy-injected credentials: the data model + registry I/O.
///
/// The design goal is that Claude can *use* a credential without ever *seeing*
/// its value. A secret is split into two independently-owned parts so a project
/// can **request** a credential without being able to **grant** one:
///
///  - `SecretRequirement` — *what* a secret is and *where* it may be used
///    (injection spec + host/path scopes). Authored by the human (global) OR by a
///    project's `.box/secrets.json`. Carries **no value and no source** — the type
///    has no field for one, so a project literally cannot express a binding.
///  - binding (`name → SecretSource`) — ties a requirement to a real value
///    (a host env var or a Keychain entry). **Only the human writes these**, via
///    `box secret set`/`setup`, into the global registry.
///
/// The pure model + validation here is filesystem-free (and unit tested directly);
/// `SecretStore` is the thin JSON read/write wrapper. Value *resolution* and
/// squid *rendering* live in `SecretInjection`.
public enum SecretLocation: String, Codable, Sendable, Equatable, CaseIterable {
    /// Inject as a request header named `field`.
    case header
    /// Inject as a cookie named `field` (merged into the `Cookie:` header).
    case cookie
    /// Inject as a URL query parameter named `field` (needs the url_rewrite helper).
    case query
}

/// A host + optional path constraint on where a secret may be injected. `host`
/// matches the request host exactly (squid `dstdomain`; a leading dot matches
/// subdomains); at most one of `pathPrefix`/`pathRegex` narrows by path.
public struct SecretScope: Codable, Sendable, Equatable {
    public var host: String
    public var pathPrefix: String?
    public var pathRegex: String?

    public init(host: String, pathPrefix: String? = nil, pathRegex: String? = nil) {
        self.host = host
        self.pathPrefix = pathPrefix
        self.pathRegex = pathRegex
    }
}

/// How a secret's value is placed onto a matching request. Fixed at
/// definition time — Claude never chooses this at runtime.
public struct SecretInjectionSpec: Codable, Sendable, Equatable {
    public var location: SecretLocation
    /// Header/cookie/query-param name the value is injected under.
    public var field: String
    /// Template applied host-side to shape the value, e.g. `Bearer ${value}` or
    /// `${value|base64}`. Must contain `${value}`.
    public var template: String

    public init(location: SecretLocation, field: String, template: String) {
        self.location = location
        self.field = field
        self.template = template
    }
}

/// A declared credential requirement — no value, no source.
public struct SecretRequirement: Codable, Sendable, Equatable {
    public var name: String
    public var injection: SecretInjectionSpec
    public var scopes: [SecretScope]

    public init(name: String, injection: SecretInjectionSpec, scopes: [SecretScope]) {
        self.name = name
        self.injection = injection
        self.scopes = scopes
    }
}

/// Where a secret's value comes from at launch. Never stores the value itself.
public enum SecretSource: Sendable, Equatable {
    /// A host environment variable, resolved at launch.
    case env(String)
    /// A login-Keychain generic password, read at launch via `security`.
    case keychain(service: String, account: String)
}

extension SecretSource: Codable {
    enum CodingKeys: String, CodingKey { case kind, ref, service, account }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        switch try c.decode(String.self, forKey: .kind) {
        case "env":
            self = .env(try c.decode(String.self, forKey: .ref))
        case "keychain":
            self = .keychain(
                service: try c.decode(String.self, forKey: .service),
                account: try c.decode(String.self, forKey: .account))
        case let other:
            throw DecodingError.dataCorruptedError(
                forKey: .kind, in: c, debugDescription: "unknown secret source kind \"\(other)\"")
        }
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .env(let ref):
            try c.encode("env", forKey: .kind)
            try c.encode(ref, forKey: .ref)
        case .keychain(let service, let account):
            try c.encode("keychain", forKey: .kind)
            try c.encode(service, forKey: .service)
            try c.encode(account, forKey: .account)
        }
    }

    /// Short human label for `box secret ls`/manifests (never the value).
    public var label: String {
        switch self {
        case .env(let v): return "env:\(v)"
        case .keychain(let s, let a): return "keychain:\(s)/\(a)"
        }
    }
}

/// The global registry: human-authored requirements + name→source bindings.
public struct SecretRegistry: Codable, Sendable, Equatable {
    /// Globally-defined requirements (from `box secret set`).
    public var requirements: [SecretRequirement]
    /// name → source. Includes bindings for project-declared requirements
    /// provided via `box secret setup`.
    public var bindings: [String: SecretSource]

    public init(requirements: [SecretRequirement] = [], bindings: [String: SecretSource] = [:]) {
        self.requirements = requirements
        self.bindings = bindings
    }

    enum CodingKeys: String, CodingKey { case requirements, bindings }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.requirements = try c.decodeIfPresent([SecretRequirement].self, forKey: .requirements) ?? []
        self.bindings = try c.decodeIfPresent([String: SecretSource].self, forKey: .bindings) ?? [:]
    }

    /// Replace-or-append a requirement by name.
    public mutating func upsert(_ req: SecretRequirement) {
        if let i = requirements.firstIndex(where: { $0.name == req.name }) {
            requirements[i] = req
        } else {
            requirements.append(req)
        }
    }

    /// Remove a requirement and its binding by name; returns whether anything changed.
    @discardableResult
    public mutating func remove(name: String) -> Bool {
        let before = requirements.count + bindings.count
        requirements.removeAll { $0.name == name }
        bindings.removeValue(forKey: name)
        return requirements.count + bindings.count != before
    }
}

/// The project's declared requirements, decoded from `.box/secrets.json`. Shape:
/// `{ "requirements": [ … ] }`. There is deliberately no place for a source or a
/// value — a project can only ask.
public struct ProjectSecretsFile: Codable, Sendable, Equatable {
    public var requirements: [SecretRequirement]

    public init(requirements: [SecretRequirement] = []) { self.requirements = requirements }

    enum CodingKeys: String, CodingKey { case requirements }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.requirements = try c.decodeIfPresent([SecretRequirement].self, forKey: .requirements) ?? []
    }
}

// MARK: - Validation (pure)

extension SecretRequirement {
    /// The characters allowed in a secret name (used to form squid ACL names and
    /// the Keychain service, so keep it conservative).
    static let nameCharset = CharacterSet(charactersIn:
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")

    /// HTTP header/cookie/param field token — RFC 7230 token chars.
    static let fieldCharset = CharacterSet(charactersIn:
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~")

    /// Return a list of human-readable validation problems (empty ⇒ valid).
    /// `isPinned` decides whether a scope host is a never-inject host; callers
    /// pass `Runner.isAlwaysSpliced` (injected so this stays pure/testable).
    public func validationErrors(isPinned: (String) -> Bool) -> [String] {
        var errs: [String] = []
        let trimmedName = name.trimmingCharacters(in: .whitespaces)
        if trimmedName.isEmpty {
            errs.append("name is empty")
        } else if trimmedName.unicodeScalars.contains(where: { !Self.nameCharset.contains($0) }) {
            errs.append("name \"\(name)\" has invalid characters (use A-Z a-z 0-9 _ -)")
        }

        let field = injection.field.trimmingCharacters(in: .whitespaces)
        if field.isEmpty {
            errs.append("injection field name is empty")
        } else if field.unicodeScalars.contains(where: { !Self.fieldCharset.contains($0) }) {
            errs.append("injection field \"\(injection.field)\" has invalid characters")
        }

        errs.append(contentsOf: SecretTemplate.validationErrors(injection.template))

        if scopes.isEmpty {
            errs.append("at least one scope (host) is required")
        }
        for s in scopes {
            let host = s.host.trimmingCharacters(in: .whitespaces)
            if host.isEmpty {
                errs.append("a scope has an empty host")
                continue
            }
            if isPinned(host) {
                errs.append(
                    "host \"\(host)\" is pinned (Anthropic/npm/git) and can never be injected/bumped")
            }
            if s.pathPrefix != nil && s.pathRegex != nil {
                errs.append("scope \"\(host)\" sets both pathPrefix and pathRegex (pick one)")
            }
            if let p = s.pathPrefix, !p.hasPrefix("/") {
                errs.append("scope \"\(host)\" pathPrefix must start with \"/\"")
            }
        }
        return errs
    }
}

// MARK: - Template (pure) — value shaping done host-side

/// Renders/validates injection templates like `Bearer ${value}` or
/// `${value|base64}`. All transforms run host-side so squid/the helper only ever
/// inject a fully-rendered literal.
public enum SecretTemplate {
    public static let knownTransforms: Set<String> = ["base64", "urlencode"]

    /// Parse a template into literal/token pieces. A token is `${value}` optionally
    /// followed by `|transform` segments. Throws on a malformed or unknown token.
    enum Piece: Equatable { case literal(String); case value([String]) }

    static func parse(_ template: String) throws -> [Piece] {
        var pieces: [Piece] = []
        var literal = ""
        let chars = Array(template)
        var i = 0
        while i < chars.count {
            if chars[i] == "$" && i + 1 < chars.count && chars[i + 1] == "{" {
                guard let close = (i + 2..<chars.count).first(where: { chars[$0] == "}" }) else {
                    throw CBError("template has an unterminated \"${\"")
                }
                if !literal.isEmpty { pieces.append(.literal(literal)); literal = "" }
                let inner = chars[(i + 2)..<close].map(String.init).joined()
                let parts = inner.split(separator: "|", omittingEmptySubsequences: false)
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                guard parts.first == "value" else {
                    throw CBError("template token \"${\(inner)}\" must start with \"value\"")
                }
                let transforms = Array(parts.dropFirst())
                for t in transforms where !knownTransforms.contains(t) {
                    throw CBError(
                        "template uses unknown transform \"\(t)\" (known: \(knownTransforms.sorted().joined(separator: ", ")))")
                }
                pieces.append(.value(transforms))
                i = close + 1
            } else {
                literal.append(chars[i])
                i += 1
            }
        }
        if !literal.isEmpty { pieces.append(.literal(literal)) }
        return pieces
    }

    /// Human-readable validation problems for a template (empty ⇒ valid). Requires
    /// at least one `${value}` token so a secret can't render to a constant.
    public static func validationErrors(_ template: String) -> [String] {
        let pieces: [Piece]
        do { pieces = try parse(template) } catch { return [String(describing: error)] }
        let hasValue = pieces.contains { if case .value = $0 { return true }; return false }
        return hasValue ? [] : ["template must contain \"${value}\""]
    }

}

// MARK: - Registry store (thin FS wrapper)

/// Loads/saves the global secret registry at `Box.secretsRegistryURL` (0600).
/// Tolerant of a missing/invalid file (treated as empty), like the rest of the
/// config stack.
public enum SecretStore {
    public static func load() -> SecretRegistry {
        guard let data = try? Data(contentsOf: Box.secretsRegistryURL) else {
            return SecretRegistry()
        }
        do {
            return try JSONDecoder().decode(SecretRegistry.self, from: data)
        } catch {
            FileHandle.standardError.write(
                Data("box: ignoring invalid \(Box.secretsRegistryURL.path): \(error)\n".utf8))
            return SecretRegistry()
        }
    }

    /// Write the registry back atomically at 0600, creating `Box.dir` if needed.
    public static func save(_ registry: SecretRegistry) throws {
        try FileManager.default.createDirectory(at: Box.dir, withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(registry)
        try data.write(to: Box.secretsRegistryURL, options: .atomic)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: Box.secretsRegistryURL.path)
    }

    /// Load the project's declared requirements from a `.box/secrets.json` URL,
    /// or an empty file if absent/invalid.
    public static func loadProject(from url: URL) -> ProjectSecretsFile {
        guard let data = try? Data(contentsOf: url) else { return ProjectSecretsFile() }
        return (try? JSONDecoder().decode(ProjectSecretsFile.self, from: data)) ?? ProjectSecretsFile()
    }
}
