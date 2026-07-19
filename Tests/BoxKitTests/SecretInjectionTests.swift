import Foundation
import Testing

@testable import BoxKit

@Suite("SecretInjection rendering")
struct SecretInjectionTests {
    private func req(
        _ name: String, location: SecretLocation = .header, field: String = "Authorization",
        template: String = "Bearer ${value}", scopes: [SecretScope]
    ) -> SecretRequirement {
        SecretRequirement(
            name: name,
            injection: SecretInjectionSpec(location: location, field: field, template: template),
            scopes: scopes)
    }

    private func resolved(_ r: SecretRequirement, _ value: String) -> SecretInjection.Resolved {
        SecretInjection.Resolved(requirement: r, value: value)
    }

    // MARK: merge / partition

    @Test("effectiveRequirements: global wins on name clash")
    func globalWins() {
        let g = [req("A", scopes: [SecretScope(host: "g.example.com")])]
        let p = [
            req("A", scopes: [SecretScope(host: "evil.example.com")]),
            req("B", scopes: [SecretScope(host: "b.example.com")]),
        ]
        let eff = SecretInjection.effectiveRequirements(global: g, project: p)
        #expect(eff.map { $0.name } == ["A", "B"])
        #expect(eff[0].scopes[0].host == "g.example.com")  // project's "A" ignored
    }

    @Test("partition splits resolved vs unmet")
    func partition() {
        let reqs = [
            req("HAS", scopes: [SecretScope(host: "h.example.com")]),
            req("MISS", scopes: [SecretScope(host: "m.example.com")]),
        ]
        let (res, unmet) = SecretInjection.partition(reqs) { r in
            r.name == "HAS" ? "tok" : nil
        }
        #expect(res.map { $0.requirement.name } == ["HAS"])
        #expect(unmet == ["MISS"])
    }

    @Test("empty resolved value counts as unmet")
    func emptyIsUnmet() {
        let reqs = [req("E", scopes: [SecretScope(host: "h")])]
        let (res, unmet) = SecretInjection.partition(reqs) { _ in "" }
        #expect(res.isEmpty)
        #expect(unmet == ["E"])
    }

    @Test("bumpHosts dedupes across scopes")
    func bumpHostsDedup() {
        let r = resolved(
            req("A", scopes: [SecretScope(host: "x.example.com"), SecretScope(host: "x.example.com")]),
            "t")
        #expect(SecretInjection.bumpHosts([r]) == ["x.example.com"])
    }

    @Test("renderHudsuckerConfig emits value + injection + scopes as JSON")
    func hudsuckerConfig() throws {
        let r = resolved(
            req(
                "GH", location: .header, field: "Authorization", template: "Bearer ${value}",
                scopes: [SecretScope(host: "api.github.com", pathPrefix: "/repos")]),
            "tok123")
        let json = SecretInjection.renderHudsuckerConfig([r])
        let doc = try JSONDecoder().decode(
            SecretInjection.HudsuckerConfig.self, from: Data(json.utf8))
        #expect(doc.secrets.count == 1)
        let e = doc.secrets[0]
        #expect(e.name == "GH")
        #expect(e.value == "tok123")
        #expect(e.injection.location == .header)
        #expect(e.injection.field == "Authorization")
        #expect(e.injection.template == "Bearer ${value}")
        #expect(e.scopes[0].host == "api.github.com")
        #expect(e.scopes[0].pathPrefix == "/repos")
    }

    @Test("renderHudsuckerConfig on empty resolved is an empty secrets array")
    func hudsuckerConfigEmpty() throws {
        let doc = try JSONDecoder().decode(
            SecretInjection.HudsuckerConfig.self,
            from: Data(SecretInjection.renderHudsuckerConfig([]).utf8))
        #expect(doc.secrets.isEmpty)
    }

    // MARK: header/cookie ACL

    @Test("header rule: strip + add with path regex, quote-escaped")
    func headerACL() throws {
        let r = resolved(
            req("GH", scopes: [SecretScope(host: "api.example.com", pathPrefix: "/v1/")]),
            "TOK\"EN")
        let acl = try SecretInjection.renderHeaderCookieACL([r])
        #expect(acl.contains("acl sec_GH_0_host dstdomain api.example.com"))
        #expect(acl.contains("acl sec_GH_0_path urlpath_regex ^/v1/"))
        #expect(acl.contains("request_header_access Authorization deny sec_GH_0_host"))
        #expect(acl.contains(#"request_header_add Authorization "Bearer TOK\"EN" sec_GH_0_host sec_GH_0_path"#))
    }

    @Test("cookie location injects the Cookie header")
    func cookieACL() throws {
        let r = resolved(
            req("S", location: .cookie, field: "session", template: "${value}",
                scopes: [SecretScope(host: "app.example.com")]),
            "abc")
        let acl = try SecretInjection.renderHeaderCookieACL([r])
        #expect(acl.contains("request_header_access Cookie deny sec_S_0_host"))
        #expect(acl.contains(#"request_header_add Cookie "abc" sec_S_0_host"#))
        // No path constraint ⇒ no _path acl in the add line.
        #expect(!acl.contains("sec_S_0_path"))
    }

    @Test("hyphenated name becomes a safe ACL identifier")
    func aclSafeName() throws {
        let r = resolved(req("gh-api", scopes: [SecretScope(host: "h")]), "t")
        let acl = try SecretInjection.renderHeaderCookieACL([r])
        #expect(acl.contains("acl sec_gh_api_0_host"))
    }

    @Test("a value with a newline is refused (header-injection guard)")
    func rejectsNewline() {
        let r = resolved(req("N", scopes: [SecretScope(host: "h")]), "bad\nvalue")
        #expect(throws: (any Error).self) {
            _ = try SecretInjection.renderHeaderCookieACL([r])
        }
    }

    @Test("query secrets are excluded from the header ACL")
    func queryNotInHeaderACL() throws {
        let r = resolved(
            req("Q", location: .query, field: "api_key", template: "${value}",
                scopes: [SecretScope(host: "h")]),
            "k")
        #expect(try SecretInjection.renderHeaderCookieACL([r]).isEmpty)
    }

    // MARK: query config

    @Test("query config is tab-separated with * for no path")
    func queryConfig() throws {
        let r = resolved(
            req("Q", location: .query, field: "api_key", template: "${value|urlencode}",
                scopes: [SecretScope(host: "api.example.com")]),
            "a b")
        let conf = try SecretInjection.renderQueryConfig([r])
        #expect(conf == "api.example.com\t*\tapi_key\ta%20b\n")
        #expect(SecretInjection.hasQuery([r]))
    }

    @Test("query config uses ^prefix regex when a path is set")
    func queryConfigPath() throws {
        let r = resolved(
            req("Q", location: .query, field: "k", template: "${value}",
                scopes: [SecretScope(host: "h", pathPrefix: "/api/")]),
            "v")
        let conf = try SecretInjection.renderQueryConfig([r])
        #expect(conf == "h\t^/api/\tk\tv\n")
    }

    // MARK: manifest

    @Test("manifest lists scope + source but never the value")
    func manifest() {
        let r = resolved(
            req("GH", scopes: [SecretScope(host: "api.example.com", pathPrefix: "/v1/")]),
            "SECRET-TOKEN")
        let json = SecretInjection.renderManifest([r]) { _ in "env:GH_TOKEN" }
        #expect(json.contains("\"GH\""))
        #expect(json.contains("api.example.com"))
        #expect(json.contains("env:GH_TOKEN"))
        #expect(!json.contains("SECRET-TOKEN"))
    }
}
