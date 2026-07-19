import Foundation

/// One parsed line of squid's egress access log. Pure value type — no I/O.
///
/// Squid's stock `squid` logformat and the custom `box` logformat we render
/// (see `assets/files/squid.conf`) share their first columns, so a single
/// tolerant parser handles both. The custom format adds a trailing SNI column
/// (`%ssl::>sni`) carrying the real TLS server name on `CONNECT` tunnels.
public struct EgressEntry: Equatable, Sendable {
    /// Wall-clock time of the request (squid's `%ts.%03tu` epoch seconds).
    public let timestamp: Date
    /// Requesting client address (`%>a`).
    public let client: String
    /// Squid result/status code, e.g. `TCP_MISS` / `TCP_DENIED` (`%Ss`).
    public let resultCode: String
    /// Upstream HTTP status, e.g. 200 / 403 / 0 (`%03>Hs`).
    public let httpStatus: Int
    /// Bytes sent to the client (`%<st`).
    public let bytes: Int
    /// HTTP method, e.g. GET / CONNECT (`%rm`).
    public let method: String
    /// Request URL (`%ru`). For CONNECT tunnels this is `host:port`.
    public let url: String
    /// Real TLS SNI from the custom format (`%ssl::>sni`); nil for the stock
    /// format, which doesn't carry it.
    public let sni: String?

    public init(
        timestamp: Date, client: String, resultCode: String, httpStatus: Int,
        bytes: Int, method: String, url: String, sni: String?
    ) {
        self.timestamp = timestamp
        self.client = client
        self.resultCode = resultCode
        self.httpStatus = httpStatus
        self.bytes = bytes
        self.method = method
        self.url = url
        self.sni = sni
    }

    public var isDenied: Bool {
        resultCode.contains("DENIED") || resultCode.contains("UAEX")
            || (method == "CONNECT" && httpStatus == 403)
    }

    /// The destination host: prefer the real SNI, then the host part of a
    /// `host:port` CONNECT target, then the host component of an http(s) URL.
    public var host: String {
        if let sni, !sni.isEmpty, sni != "-" { return sni }
        return EgressLog.hostFromURL(url)
    }
}

/// Pure parser + summarizer for the squid egress log. Filesystem-free so the
/// core can be unit-tested over fixture lines; the command layer feeds it the
/// contents of a per-box `access.log`.
public enum EgressLog {
    /// Parse log lines in BOTH the stock `squid` logformat and the custom `box`
    /// logformat. Tolerant: blank lines, comments, and unparseable rows are
    /// skipped rather than throwing.
    ///
    /// Stock squid: `%ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt`
    ///   1592…123  156 10.0.0.1 TCP_MISS/200 1234 GET http://x/ - HIER_DIRECT/1.2.3.4 text/html
    ///
    /// Custom box: `%ts.%03tu %>a %Ss/%03>Hs %<st %rm %ru %ssl::>sni`
    ///   1592…123 10.0.0.1 TCP_MISS/200 1234 GET http://x/ x.example.com
    ///
    /// The two are distinguished structurally: the stock format's third field is
    /// the client and its fourth is `code/status`; the custom format's *second*
    /// field is the client and its third is `code/status`. We locate the
    /// `code/status` token and read fields relative to it, so both parse without
    /// a mode flag.
    public static func parse(_ lines: [String]) -> [EgressEntry] {
        lines.compactMap(parseLine)
    }

    /// Parse a single line, or nil if it isn't a recognizable access-log row.
    public static func parseLine(_ line: String) -> EgressEntry? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { return nil }
        let f = trimmed.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard f.count >= 6 else { return nil }

        // First field is always the epoch timestamp `%ts.%03tu`.
        guard let timestamp = parseTimestamp(f[0]) else { return nil }

        // Find the `code/status` token (e.g. TCP_DENIED/403). Both formats have
        // it; its position differentiates them (index 2 custom, 3 stock — after
        // an extra `%6tr` response-time field). Search from index 1.
        guard let csIndex = f.dropFirst().firstIndex(where: isCodeStatus),
            let (resultCode, httpStatus) = splitCodeStatus(f[csIndex])
        else { return nil }

        // Client is the field immediately before code/status.
        let client = csIndex >= 1 ? f[csIndex - 1] : "-"

        // Fields after code/status: bytes, method, url, [sni].
        let rest = Array(f[(csIndex + 1)...])
        guard rest.count >= 3 else { return nil }
        let bytes = Int(rest[0]) ?? 0
        let method = rest[1]
        let url = rest[2]
        // The custom format appends a real-SNI column; stock format does not.
        // squid renders an empty field as "-", which we treat as absent.
        let sni: String?
        if rest.count >= 4 {
            let raw = rest[3]
            sni = (raw == "-" || raw.isEmpty) ? nil : raw
        } else {
            sni = nil
        }

        return EgressEntry(
            timestamp: timestamp, client: client, resultCode: resultCode,
            httpStatus: httpStatus, bytes: bytes, method: method,
            url: url, sni: sni)
    }

    /// A `%ts.%03tu` epoch-seconds-with-millis token → Date. Tolerant of an
    /// integer-only form too.
    static func parseTimestamp(_ s: String) -> Date? {
        guard let secs = Double(s) else { return nil }
        // Sanity bound: squid epoch timestamps are large positive numbers.
        guard secs > 0 else { return nil }
        return Date(timeIntervalSince1970: secs)
    }

    static func isCodeStatus(_ field: String) -> Bool {
        guard let slash = field.firstIndex(of: "/") else { return false }
        let code = field[..<slash]
        let status = field[field.index(after: slash)...]
        guard !code.isEmpty, !status.isEmpty, Int(status) != nil else { return false }
        return code.allSatisfy {
            $0.isUppercase || $0.isNumber || $0 == "_" || $0 == "," || $0 == "-"
        }
    }

    static func splitCodeStatus(_ field: String) -> (String, Int)? {
        guard let slash = field.firstIndex(of: "/") else { return nil }
        let code = String(field[..<slash])
        guard let status = Int(field[field.index(after: slash)...]) else { return nil }
        return (code, status)
    }

    /// Best-effort host extraction from a squid `%ru` value. Handles
    /// `host:port` (CONNECT), `scheme://host[:port]/path`, and bare hosts.
    static func hostFromURL(_ url: String) -> String {
        var s = url
        if let range = s.range(of: "://") {
            s = String(s[range.upperBound...])
        }
        // Drop any path/query.
        if let slash = s.firstIndex(of: "/") { s = String(s[..<slash]) }
        // Drop a trailing :port (but leave bracketed IPv6 literals alone).
        if !s.contains("]"), let colon = s.lastIndex(of: ":") {
            s = String(s[..<colon])
        }
        return s.isEmpty ? url : s
    }

    // MARK: - Filtering (pure helpers reused by `box log`)

    /// Keep only denied entries.
    public static func denied(_ entries: [EgressEntry]) -> [EgressEntry] {
        entries.filter { $0.isDenied }
    }

    /// Keep entries at or after `cutoff`.
    public static func since(_ entries: [EgressEntry], _ cutoff: Date) -> [EgressEntry] {
        entries.filter { $0.timestamp >= cutoff }
    }

    /// Resolve a `--since` argument to an absolute cutoff relative to `now`.
    /// Accepts a relative duration (`10m`, `2h`, `1d`, `30s`, bare seconds) or
    /// an ISO-8601 / `yyyy-MM-dd[ HH:mm[:ss]]` timestamp. Throws on garbage.
    public static func resolveSince(_ s: String, now: Date = Date()) throws -> Date {
        let trimmed = s.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { throw CBError("empty --since value") }

        // Relative duration: <number><unit?> where unit ∈ s/m/h/d (default s).
        if let match = trimmed.lowercased().firstMatch(of: /^([0-9]+)\s*([smhd]?)$/) {
            guard let value = Double(match.1) else { throw CBError("invalid --since: \"\(s)\"") }
            let unit: Double
            switch match.2.first {
            case "s", nil: unit = 1
            case "m": unit = 60
            case "h": unit = 3600
            case "d": unit = 86400
            default: unit = 1
            }
            return now.addingTimeInterval(-value * unit)
        }

        // Absolute timestamp.
        let iso = ISO8601DateFormatter()
        iso.formatOptions = [.withInternetDateTime]
        if let d = iso.date(from: trimmed) { return d }
        iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = iso.date(from: trimmed) { return d }

        let fmts = ["yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd HH:mm", "yyyy-MM-dd"]
        let df = DateFormatter()
        df.locale = Locale(identifier: "en_US_POSIX")
        df.timeZone = TimeZone.current
        for fmt in fmts {
            df.dateFormat = fmt
            if let d = df.date(from: trimmed) { return d }
        }
        throw CBError("invalid --since: \"\(s)\" (expected e.g. 10m, 2h, 1d, or an ISO date)")
    }

    // MARK: - Denied report (`box denied`)

    /// One host in the `box denied` report: how often, how recently, and in
    /// which session(s) it was blocked.
    public struct DeniedHostReport: Equatable, Sendable {
        public let host: String
        public let count: Int
        public let lastSeen: Date
        /// Box ids that denied this host, in first-seen order. Empty when only
        /// the legacy shared log saw it (a box running an older image, whose
        /// entrypoint had no per-session tee).
        public let sessions: [String]

        public init(host: String, count: Int, lastSeen: Date, sessions: [String]) {
            self.host = host
            self.count = count
            self.lastSeen = lastSeen
            self.sessions = sessions
        }
    }

    /// Build the `box denied` report from the per-box logs plus the legacy
    /// shared log. The entrypoint tees every squid line into BOTH, so the same
    /// entry usually exists twice; we dedupe by the full line identity
    /// (timestamp, client, url, code, bytes) with per-box attribution winning.
    /// Shared-log entries with no per-box twin (old images) survive with no
    /// session. Hosts sort by most-recent denial first. Pure — the command
    /// layer feeds it file contents.
    public static func deniedReport(
        perBox: [(id: String, lines: [String])], shared: [String]
    ) -> [DeniedHostReport] {
        struct LineKey: Hashable {
            let timestamp: Date, client: String, url: String, code: String, bytes: Int
        }
        func key(_ e: EgressEntry) -> LineKey {
            LineKey(
                timestamp: e.timestamp, client: e.client, url: e.url,
                code: e.resultCode, bytes: e.bytes)
        }

        var agg: [String: (count: Int, last: Date, sessions: [String])] = [:]
        var order: [String] = []
        func add(_ e: EgressEntry, session: String?) {
            let h = e.host
            var a = agg[h] ?? (0, .distantPast, [])
            if agg[h] == nil { order.append(h) }
            a.count += 1
            a.last = max(a.last, e.timestamp)
            if let session, !a.sessions.contains(session) { a.sessions.append(session) }
            agg[h] = a
        }

        var seen = Set<LineKey>()
        for (id, lines) in perBox {
            for e in denied(parse(lines)) {
                seen.insert(key(e))
                add(e, session: id)
            }
        }
        for e in denied(parse(shared)) where !seen.contains(key(e)) {
            add(e, session: nil)
        }

        // Most recently denied first; ties keep first-seen order (stable).
        let indexOf = Dictionary(uniqueKeysWithValues: order.enumerated().map { ($1, $0) })
        return
            order
            .map { host -> DeniedHostReport in
                let a = agg[host]!
                return DeniedHostReport(
                    host: host, count: a.count, lastSeen: a.last,
                    sessions: a.sessions)
            }
            .sorted {
                $0.lastSeen != $1.lastSeen
                    ? $0.lastSeen > $1.lastSeen
                    : indexOf[$0.host]! < indexOf[$1.host]!
            }
    }

    // MARK: - Summary

    /// Aggregate stats for an end-of-session / `--all` view.
    public struct Summary: Equatable, Sendable {
        /// Total requests parsed.
        public let total: Int
        /// Number of denied requests.
        public let denied: Int
        /// Total bytes transferred to the client.
        public let totalBytes: Int
        /// Per-host request counts, descending by count then first-seen order.
        public let hosts: [HostCount]

        public struct HostCount: Equatable, Sendable {
            public let host: String
            public let count: Int
            public init(host: String, count: Int) {
                self.host = host
                self.count = count
            }
        }

        /// Distinct destination hosts seen.
        public var uniqueHosts: Int { hosts.count }
    }

    /// Format a summary as a single human-readable line for stderr/CLI footers.
    /// Pure: takes a pre-computed `Summary`.
    public static func summaryLine(_ s: Summary) -> String {
        let top = s.hosts.prefix(3).map { "\($0.host) (\($0.count))" }.joined(separator: ", ")
        var line =
            "[box] egress: \(s.total) request(s), \(s.uniqueHosts) host(s), "
            + "\(formatBytes(s.totalBytes))"
        if s.denied > 0 { line += ", \(s.denied) denied" }
        if !top.isEmpty { line += " — top: \(top)" }
        return line
    }

    /// Human-readable byte count (1024-based, like the rest of box's sizes).
    public static func formatBytes(_ n: Int) -> String {
        guard n >= 1024 else { return "\(n) B" }
        let units = ["KiB", "MiB", "GiB", "TiB"]
        var value = Double(n) / 1024
        var idx = 0
        while value >= 1024 && idx < units.count - 1 {
            value /= 1024
            idx += 1
        }
        return String(format: "%.1f %@", value, units[idx])
    }

    /// Read a box's per-box access log and return the formatted summary line, or
    /// nil if the log is missing/empty. Thin I/O wrapper over the pure core, used
    /// by the runner's end-of-session `defer`.
    static func sessionSummaryLine(forBoxID id: String) throws -> String {
        let log = Box.logDir(forBoxID: id).appendingPathComponent("access.log")
        let content = try String(contentsOf: log, encoding: .utf8)
        let entries = parse(content.components(separatedBy: "\n"))
        guard !entries.isEmpty else { throw CBError("no egress recorded") }
        return summaryLine(summarize(entries))
    }

    public static func summarize(_ entries: [EgressEntry]) -> Summary {
        var counts: [String: Int] = [:]
        var order: [String] = []
        var bytes = 0
        var denied = 0
        for e in entries {
            bytes += e.bytes
            if e.isDenied { denied += 1 }
            let h = e.host
            if counts[h] == nil { order.append(h) }
            counts[h, default: 0] += 1
        }
        // Sort by count desc, then by first-seen order (stable, deterministic).
        let indexOf = Dictionary(uniqueKeysWithValues: order.enumerated().map { ($1, $0) })
        let hosts =
            order
            .map { Summary.HostCount(host: $0, count: counts[$0]!) }
            .sorted {
                $0.count != $1.count
                    ? $0.count > $1.count
                    : indexOf[$0.host]! < indexOf[$1.host]!
            }
        return Summary(total: entries.count, denied: denied, totalBytes: bytes, hosts: hosts)
    }
}
