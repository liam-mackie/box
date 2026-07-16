import Foundation
import Testing

@testable import BoxKit

@Suite("EgressLog.parse")
struct EgressLogParseTests {
    // Stock squid logformat:
    //   %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt
    static let stockAllowed =
        "1700000000.123    156 10.0.0.2 TCP_MISS/200 5120 GET http://example.com/path - HIER_DIRECT/93.184.216.34 text/html"
    static let stockDenied =
        "1700000005.000      0 10.0.0.2 TCP_DENIED/403 419 CONNECT evil.example.net:443 - HIER_NONE/- text/html"

    // Custom box logformat:
    //   %ts.%03tu %>a %Ss/%03>Hs %<st %rm %ru %ssl::>sni
    static let boxConnectWithSNI =
        "1700000010.500 10.0.0.2 TCP_TUNNEL/200 81920 CONNECT api.anthropic.com:443 api.anthropic.com"
    static let boxDenied =
        "1700000012.000 10.0.0.2 TCP_DENIED/403 419 CONNECT blocked.example.com:443 -"
    static let boxPlainHTTP =
        "1700000015.000 10.0.0.2 TCP_MISS/200 2048 GET http://docs.python.org/3/ -"

    @Test("parses a stock allowed line")
    func stockAllowedRow() {
        let e = EgressLog.parseLine(Self.stockAllowed)
        #expect(e != nil)
        #expect(e?.client == "10.0.0.2")
        #expect(e?.resultCode == "TCP_MISS")
        #expect(e?.httpStatus == 200)
        #expect(e?.bytes == 5120)
        #expect(e?.method == "GET")
        #expect(e?.url == "http://example.com/path")
        #expect(e?.sni == nil)
        #expect(e?.host == "example.com")
        #expect(e?.isDenied == false)
    }

    @Test("parses a stock denied CONNECT line and extracts host:port host")
    func stockDeniedRow() {
        let e = EgressLog.parseLine(Self.stockDenied)
        #expect(e?.resultCode == "TCP_DENIED")
        #expect(e?.httpStatus == 403)
        #expect(e?.method == "CONNECT")
        #expect(e?.isDenied == true)
        #expect(e?.host == "evil.example.net")  // port stripped
    }

    @Test("parses a custom box CONNECT line and prefers real SNI as host")
    func boxConnectRow() {
        let e = EgressLog.parseLine(Self.boxConnectWithSNI)
        #expect(e?.client == "10.0.0.2")
        #expect(e?.resultCode == "TCP_TUNNEL")
        #expect(e?.bytes == 81920)
        #expect(e?.method == "CONNECT")
        #expect(e?.url == "api.anthropic.com:443")
        #expect(e?.sni == "api.anthropic.com")
        #expect(e?.host == "api.anthropic.com")
    }

    @Test("treats a '-' SNI field as absent and falls back to the URL host")
    func boxDashSNI() {
        let e = EgressLog.parseLine(Self.boxDenied)
        #expect(e?.sni == nil)
        #expect(e?.host == "blocked.example.com")
        #expect(e?.isDenied == true)
    }

    @Test("parses a custom box plain-HTTP line")
    func boxPlainRow() {
        let e = EgressLog.parseLine(Self.boxPlainHTTP)
        #expect(e?.host == "docs.python.org")
        #expect(e?.method == "GET")
        #expect(e?.sni == nil)
    }

    @Test("skips blanks, comments, and garbage; parses a mixed-format stream")
    func tolerantStream() {
        let lines = [
            "",
            "# a comment",
            Self.stockAllowed,
            "not a log line at all",
            Self.boxConnectWithSNI,
            "   ",
            Self.boxDenied,
        ]
        let entries = EgressLog.parse(lines)
        #expect(entries.count == 3)
        #expect(entries.map(\.host) == ["example.com", "api.anthropic.com", "blocked.example.com"])
    }

    @Test("preserves sub-second timestamps")
    func timestampPrecision() {
        let e = EgressLog.parseLine(Self.boxConnectWithSNI)
        #expect(e?.timestamp == Date(timeIntervalSince1970: 1700000010.5))
    }
}

@Suite("EgressLog.summarize")
struct EgressLogSummarizeTests {
    func entries() -> [EgressEntry] {
        EgressLog.parse([
            EgressLogParseTests.stockAllowed,  // example.com, 5120, ok
            EgressLogParseTests.boxConnectWithSNI,  // api.anthropic.com, 81920, ok
            EgressLogParseTests.boxDenied,  // blocked.example.com, 419, denied
            EgressLogParseTests.boxPlainHTTP,  // docs.python.org, 2048, ok
            "1700000020.000 10.0.0.2 TCP_TUNNEL/200 1000 CONNECT api.anthropic.com:443 api.anthropic.com",
        ])
    }

    @Test("counts totals, denials, bytes, and unique hosts")
    func totals() {
        let s = EgressLog.summarize(entries())
        #expect(s.total == 5)
        #expect(s.denied == 1)
        #expect(s.totalBytes == 5120 + 81920 + 419 + 2048 + 1000)
        #expect(s.uniqueHosts == 4)
    }

    @Test("ranks hosts by count descending, then first-seen order")
    func hostRanking() {
        let s = EgressLog.summarize(entries())
        #expect(s.hosts.first?.host == "api.anthropic.com")  // 2 requests, the rest 1
        #expect(s.hosts.first?.count == 2)
        // The remaining three appear once each, in first-seen order.
        #expect(
            s.hosts.dropFirst().map(\.host)
                == ["example.com", "blocked.example.com", "docs.python.org"])
    }

    @Test("empty input yields an empty summary")
    func emptySummary() {
        let s = EgressLog.summarize([])
        #expect(s.total == 0 && s.denied == 0 && s.totalBytes == 0 && s.uniqueHosts == 0)
    }

    @Test("summaryLine includes counts and top hosts")
    func summaryLineText() {
        let line = EgressLog.summaryLine(EgressLog.summarize(entries()))
        #expect(line.contains("5 request(s)"))
        #expect(line.contains("4 host(s)"))
        #expect(line.contains("1 denied"))
        #expect(line.contains("api.anthropic.com (2)"))
    }
}

@Suite("EgressLog filtering")
struct EgressLogFilterTests {
    func entries() -> [EgressEntry] {
        EgressLog.parse([
            EgressLogParseTests.stockAllowed,  // ts 1700000000
            EgressLogParseTests.boxConnectWithSNI,  // ts 1700000010.5
            EgressLogParseTests.boxDenied,  // ts 1700000012, denied
            EgressLogParseTests.boxPlainHTTP,  // ts 1700000015
        ])
    }

    @Test("denied keeps only blocked requests")
    func deniedFilter() {
        let d = EgressLog.denied(entries())
        #expect(d.count == 1)
        #expect(d.first?.host == "blocked.example.com")
    }

    @Test("since keeps entries at or after the cutoff")
    func sinceFilter() {
        let cutoff = Date(timeIntervalSince1970: 1_700_000_011)
        let kept = EgressLog.since(entries(), cutoff)
        #expect(kept.count == 2)  // ts 1700000012 and 1700000015
        #expect(kept.map(\.host) == ["blocked.example.com", "docs.python.org"])
    }

    @Test("resolveSince handles relative durations")
    func relativeDurations() throws {
        let now = Date(timeIntervalSince1970: 1_000_000)
        #expect(
            try EgressLog.resolveSince("30s", now: now)
                == now.addingTimeInterval(-30))
        #expect(
            try EgressLog.resolveSince("10m", now: now)
                == now.addingTimeInterval(-600))
        #expect(
            try EgressLog.resolveSince("2h", now: now)
                == now.addingTimeInterval(-7200))
        #expect(
            try EgressLog.resolveSince("1d", now: now)
                == now.addingTimeInterval(-86400))
        // Bare number defaults to seconds.
        #expect(
            try EgressLog.resolveSince("45", now: now)
                == now.addingTimeInterval(-45))
    }

    @Test("resolveSince parses absolute ISO and date-only timestamps")
    func absoluteTimestamps() throws {
        let iso = try EgressLog.resolveSince("2023-11-14T22:13:20Z")
        #expect(iso == Date(timeIntervalSince1970: 1_700_000_000))
        // A date-only form parses without throwing.
        #expect(throws: Never.self) { try EgressLog.resolveSince("2023-11-14") }
    }

    @Test("resolveSince rejects garbage")
    func rejectsGarbage() {
        #expect(throws: CBError.self) { try EgressLog.resolveSince("not-a-time") }
        #expect(throws: CBError.self) { try EgressLog.resolveSince("") }
    }
}

@Suite("EgressLog.deniedReport (session attribution)")
struct DeniedReportTests {
    // The entrypoint tees the SAME squid line into the per-box log and the
    // legacy shared log, so a modern session produces both copies.
    static let deniedA =
        "1700000012.000 10.0.0.2 TCP_DENIED/403 419 CONNECT blocked.example.com:443 -"
    static let deniedALater =
        "1700000099.000 10.0.0.2 TCP_DENIED/403 419 CONNECT blocked.example.com:443 -"
    static let deniedB =
        "1700000050.000 10.0.0.2 TCP_DENIED/403 419 CONNECT other.example.net:443 -"
    // Old-image sessions only ever wrote the shared log (stock squid format).
    static let legacyDenied =
        "1690000000.000      0 10.0.0.2 TCP_DENIED/403 419 CONNECT legacy.example.org:443 - HIER_NONE/- text/html"
    static let allowed =
        "1700000010.500 10.0.0.2 TCP_TUNNEL/200 81920 CONNECT api.anthropic.com:443 api.anthropic.com"

    @Test("attributes hosts to the box whose log denied them")
    func attributesSessions() {
        let report = EgressLog.deniedReport(
            perBox: [("box-proj-1", [Self.deniedA, Self.allowed])],
            shared: [Self.deniedA])  // teed twice; must not double-count
        #expect(report.count == 1)
        #expect(report[0].host == "blocked.example.com")
        #expect(report[0].count == 1)
        #expect(report[0].sessions == ["box-proj-1"])
    }

    @Test("shared-log-only entries survive with no session (old image)")
    func legacyUnattributed() {
        let report = EgressLog.deniedReport(
            perBox: [("box-proj-1", [Self.deniedA])],
            shared: [Self.deniedA, Self.legacyDenied])
        #expect(report.count == 2)
        let legacy = report.first { $0.host == "legacy.example.org" }
        #expect(legacy?.sessions == [])
        #expect(legacy?.count == 1)
    }

    @Test("aggregates per host across sessions, most recent denial first")
    func aggregatesAndSorts() {
        let report = EgressLog.deniedReport(
            perBox: [
                ("box-proj-1", [Self.deniedA, Self.deniedB]),
                ("box-proj-2", [Self.deniedALater]),
            ],
            shared: [])
        #expect(report.map(\.host) == ["blocked.example.com", "other.example.net"])
        let blocked = report[0]
        #expect(blocked.count == 2)
        #expect(blocked.sessions == ["box-proj-1", "box-proj-2"])
        #expect(blocked.lastSeen == Date(timeIntervalSince1970: 1_700_000_099))
    }

    @Test("allowed traffic and garbage never appear")
    func filtersToDenials() {
        let report = EgressLog.deniedReport(
            perBox: [("box-x-1", [Self.allowed, "", "# comment", "garbage line"])],
            shared: [Self.allowed])
        #expect(report.isEmpty)
    }
}
