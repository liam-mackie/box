import Testing

@testable import BoxKit

@Suite("DeniedHost.normalize")
struct DeniedHostNormalizeTests {
    @Test("strips a port suffix")
    func stripsPort() {
        let n = DeniedHost.normalize("api.x.com:443")
        #expect(n?.exact == "api.x.com")
        #expect(n?.wildcard == ".api.x.com")
    }

    @Test("parses a full URL down to its host")
    func parsesURL() {
        let n = DeniedHost.normalize("http://x.y.com/path?q=1")
        #expect(n?.exact == "x.y.com")
        #expect(n?.wildcard == ".x.y.com")
    }

    @Test("handles an https URL with a port")
    func httpsURLWithPort() {
        let n = DeniedHost.normalize("https://x.y.com:8443/a/b")
        #expect(n?.exact == "x.y.com")
        #expect(n?.wildcard == ".x.y.com")
    }

    @Test("passes a bare host through")
    func bareHost() {
        let n = DeniedHost.normalize("example.com")
        #expect(n?.exact == "example.com")
        #expect(n?.wildcard == ".example.com")
    }

    @Test("drops a trailing dot (FQDN root)")
    func trailingDot() {
        let n = DeniedHost.normalize("example.com.")
        #expect(n?.exact == "example.com")
        #expect(n?.wildcard == ".example.com")
    }

    @Test("lowercases and trims surrounding whitespace")
    func lowercasesAndTrims() {
        let n = DeniedHost.normalize("  API.X.COM:443  ")
        #expect(n?.exact == "api.x.com")
        #expect(n?.wildcard == ".api.x.com")
    }

    @Test("declines to offer an IPv4 literal")
    func declinesIPv4() {
        #expect(DeniedHost.normalize("10.0.0.1") == nil)
        #expect(DeniedHost.normalize("10.0.0.1:443") == nil)
        #expect(DeniedHost.normalize("http://192.168.1.1/x") == nil)
    }

    @Test("declines to offer an IPv6 literal")
    func declinesIPv6() {
        #expect(DeniedHost.normalize("[2001:db8::1]:443") == nil)
        #expect(DeniedHost.normalize("::1") == nil)
    }

    @Test("rejects junk with no dotted host")
    func rejectsJunk() {
        #expect(DeniedHost.normalize("") == nil)
        #expect(DeniedHost.normalize("   ") == nil)
        #expect(DeniedHost.normalize("localhost") == nil)
        #expect(DeniedHost.normalize("-") == nil)
        #expect(DeniedHost.normalize("error:") == nil)
    }

    @Test("rejects a host with invalid characters")
    func rejectsInvalidChars() {
        #expect(DeniedHost.normalize("a b.com") == nil)
        #expect(DeniedHost.normalize("a_b.com") == nil)
    }
}

@Suite("DeniedHost.parseSelection")
struct ParseSelectionTests {
    @Test("a single index")
    func single() {
        #expect(DeniedHost.parseSelection("2", count: 3) == Set([2]))
    }

    @Test("a comma list")
    func commaList() {
        #expect(DeniedHost.parseSelection("1,3", count: 3) == Set([1, 3]))
    }

    @Test("a range")
    func range() {
        #expect(DeniedHost.parseSelection("1-3", count: 5) == Set([1, 2, 3]))
    }

    @Test("a mix of lists and ranges, with spaces")
    func mixed() {
        #expect(DeniedHost.parseSelection(" 1, 3-5 ,7", count: 8) == Set([1, 3, 4, 5, 7]))
    }

    @Test("all selects every index")
    func all() {
        #expect(DeniedHost.parseSelection("all", count: 3) == Set([1, 2, 3]))
        #expect(DeniedHost.parseSelection("ALL", count: 2) == Set([1, 2]))
    }

    @Test("q (quit) yields an empty set")
    func quit() {
        #expect(DeniedHost.parseSelection("q", count: 3) == Set<Int>())
        #expect(DeniedHost.parseSelection(" Q ", count: 3) == Set<Int>())
        #expect(DeniedHost.parseSelection("", count: 3) == Set<Int>())
    }

    @Test("a reversed range still expands")
    func reversedRange() {
        #expect(DeniedHost.parseSelection("3-1", count: 5) == Set([1, 2, 3]))
    }

    @Test("out-of-range indices are rejected (nil)")
    func outOfRange() {
        #expect(DeniedHost.parseSelection("4", count: 3) == nil)
        #expect(DeniedHost.parseSelection("0", count: 3) == nil)
        #expect(DeniedHost.parseSelection("1-4", count: 3) == nil)
        #expect(DeniedHost.parseSelection("1,9", count: 3) == nil)
    }

    @Test("junk is rejected (nil)")
    func junk() {
        #expect(DeniedHost.parseSelection("abc", count: 3) == nil)
        #expect(DeniedHost.parseSelection("1,,2", count: 3) == nil)
        #expect(DeniedHost.parseSelection("1-", count: 3) == nil)
        #expect(DeniedHost.parseSelection("-2", count: 3) == nil)
        #expect(DeniedHost.parseSelection("1.5", count: 3) == nil)
    }
}
