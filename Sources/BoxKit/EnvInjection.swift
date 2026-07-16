import Foundation

/// Secret/env injection helpers.
///
/// Two pieces of state feed the agent's environment: the structured `env`
/// config map and an optional dotenv-style `envFile`. We merge them into one
/// `KEY=VALUE` map (config `env` wins over the file), write that to a per-box
/// `0600` file inside a dedicated directory, and mount the *directory* read-only
/// into the guest. The entrypoint sources the file just before dropping to the
/// agent, so the values reach the agent's environment without ever appearing in
/// the guest `ps`, the persisted image/agent-home, or box's host stderr.
///
/// The merge + parse steps are pure (no filesystem) so they're unit-testable;
/// `Runner.envMounts` is the thin filesystem wrapper around them.
enum EnvInjection {
    /// Parse dotenv-style text into a `KEY=VALUE` map.
    ///
    /// Rules (intentionally minimal — this is a secrets handoff, not a shell):
    ///  - blank lines and lines whose first non-space char is `#` are ignored
    ///  - a leading `export ` prefix is stripped (so `.env` files meant for
    ///    `source` work)
    ///  - the line splits on the FIRST `=`; everything after is the value
    ///  - keys and values are trimmed of surrounding whitespace
    ///  - a value fully wrapped in matching single or double quotes is unquoted
    ///  - lines without `=`, or with an empty key, are skipped
    ///
    /// On duplicate keys the last occurrence wins (dotenv convention).
    static func parseDotenv(_ text: String) -> [String: String] {
        var out: [String: String] = [:]
        // Split on any newline. NOTE: a CRLF (`\r\n`) is a *single* Swift
        // `Character` (extended grapheme cluster), so splitting on the Character
        // `"\n"` would miss CRLF boundaries — split on the Unicode-scalar set of
        // line terminators instead, which sees `\r` and `\n` individually.
        let lines = text.unicodeScalars
            .split(whereSeparator: { CharacterSet.newlines.contains($0) })
            .map { String(String.UnicodeScalarView($0)) }
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }

            // Tolerate a leading `export ` (common in sourced .env files).
            var body = trimmed
            if body.hasPrefix("export ") {
                body = String(body.dropFirst("export ".count)).trimmingCharacters(in: .whitespaces)
            }

            guard let eq = body.firstIndex(of: "=") else { continue }
            let key = String(body[..<eq]).trimmingCharacters(in: .whitespaces)
            if key.isEmpty { continue }

            let rawValue = String(body[body.index(after: eq)...]).trimmingCharacters(
                in: .whitespaces)
            out[key] = unquote(rawValue)
        }
        return out
    }

    /// Merge config `env` over the parsed dotenv map. Config `env` has higher
    /// precedence, so its entries override colliding file keys.
    static func mergedEnv(configEnv: [String: String], dotenv: [String: String]) -> [String: String]
    {
        var merged = dotenv
        for (k, v) in configEnv { merged[k] = v }
        return merged
    }

    /// Serialize a merged map to `KEY='VALUE'` lines, one per key, sorted by key
    /// for determinism. Values are single-quoted (with embedded quotes escaped)
    /// so the entrypoint's `set -a; . file; set +a` treats each value as a
    /// literal — shell metacharacters in a secret can't be re-interpreted.
    static func serialize(_ map: [String: String]) -> String {
        guard !map.isEmpty else { return "" }
        var lines: [String] = []
        for key in map.keys.sorted() {
            lines.append("\(key)=\(shellSingleQuote(map[key]!))")
        }
        return lines.joined(separator: "\n") + "\n"
    }

    /// Strip a single layer of matching surrounding quotes from a value.
    private static func unquote(_ s: String) -> String {
        guard s.count >= 2 else { return s }
        let first = s.first!
        let last = s.last!
        if (first == "\"" && last == "\"") || (first == "'" && last == "'") {
            return String(s.dropFirst().dropLast())
        }
        return s
    }

    /// Quote a value for safe `source`-ing: wrap in single quotes, escaping any
    /// embedded single quote as `'\''`.
    private static func shellSingleQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
