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
            injection: .insert(location: location, field: field, template: template),
            scopes: scopes)
    }

    private func placeholderReq(
        _ name: String, token: String, template: String = "${value}",
        scopes: [SecretScope] = [SecretScope(host: "api.example.com")]
    ) -> SecretRequirement {
        SecretRequirement(
            name: name, injection: .placeholder(token: token, template: template), scopes: scopes)
    }

    private func resolved(_ r: SecretRequirement, _ value: String) -> SecretInjection.Resolved {
        SecretInjection.Resolved(requirement: r, value: value)
    }

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
        #expect(
            e.injection
                == .insert(location: .header, field: "Authorization", template: "Bearer ${value}"))
        #expect(e.scopes[0].host == "api.github.com")
        #expect(e.scopes[0].pathPrefix == "/repos")
    }

    @Test("renderHudsuckerConfig emits placeholder as the location discriminator plus the token")
    func hudsuckerConfigPlaceholder() throws {
        let r = resolved(placeholderReq("gh", token: "BOX_SECRET_GH"), "tok123")
        let json = SecretInjection.renderHudsuckerConfig([r])
        let doc = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
        let secrets = doc?["secrets"] as? [[String: Any]]
        let injection = secrets?.first?["injection"] as? [String: Any]
        #expect(injection?["location"] as? String == "placeholder")
        #expect(injection?["token"] as? String == "BOX_SECRET_GH")
        #expect(injection?["template"] as? String == "${value}")
        #expect(injection?["field"] == nil)
    }

    @Test("renderHudsuckerConfig on empty resolved is an empty secrets array")
    func hudsuckerConfigEmpty() throws {
        let doc = try JSONDecoder().decode(
            SecretInjection.HudsuckerConfig.self,
            from: Data(SecretInjection.renderHudsuckerConfig([]).utf8))
        #expect(doc.secrets.isEmpty)
    }

    @Test("bootSummary lists name, location, and hosts (never the value)")
    func bootSummary() {
        let r = resolved(
            req("GH", scopes: [SecretScope(host: "api.github.com")]), "SECRET-TOKEN")
        let summary = SecretInjection.bootSummary([r])
        #expect(summary == "GH(header→api.github.com)")
        #expect(!summary.contains("SECRET-TOKEN"))
    }

    @Test("bootSummary labels placeholder secrets by mode, never token or value")
    func bootSummaryPlaceholder() {
        let r = resolved(placeholderReq("GH", token: "BOX_SECRET_GH"), "SECRET-TOKEN")
        let summary = SecretInjection.bootSummary([r])
        #expect(summary == "GH(placeholder→api.example.com)")
        #expect(!summary.contains("SECRET-TOKEN"))
    }

    @Test("placeholderExports maps derived env names to tokens for placeholder secrets only")
    func placeholderExports() {
        let ph = resolved(placeholderReq("gh-token", token: "BOX_SECRET_CUSTOM"), "v1")
        let ins = resolved(req("HDR", scopes: [SecretScope(host: "h.example.com")]), "v2")
        let exports = SecretInjection.placeholderExports([ph, ins])
        #expect(exports == ["BOX_SECRET_GH_TOKEN": "BOX_SECRET_CUSTOM"])
    }

    @Test("placeholderExports on no placeholder secrets is empty")
    func placeholderExportsEmpty() {
        let ins = resolved(req("HDR", scopes: [SecretScope(host: "h.example.com")]), "v")
        #expect(SecretInjection.placeholderExports([ins]).isEmpty)
        #expect(SecretInjection.placeholderExports([]).isEmpty)
    }

    @Test("tokenCollisionErrors flags duplicate tokens naming both secrets")
    func duplicateTokens() {
        let a = placeholderReq("A", token: "BOX_SECRET_ALPHA")
        let b = placeholderReq("B", token: "BOX_SECRET_ALPHA")
        let errs = SecretInjection.tokenCollisionErrors([a, b])
        #expect(errs.count == 1)
        #expect(errs[0].contains("\"A\"") && errs[0].contains("\"B\""))
    }

    @Test("tokenCollisionErrors flags substring overlap in either direction")
    func substringTokens() {
        let long = placeholderReq("A", token: "BOX_SECRET_ALPHA")
        let short = placeholderReq("B", token: "SECRET_ALPHA")
        #expect(!SecretInjection.tokenCollisionErrors([long, short]).isEmpty)
        #expect(!SecretInjection.tokenCollisionErrors([short, long]).isEmpty)
    }

    @Test("tokenCollisionErrors passes disjoint tokens and ignores insert secrets")
    func disjointTokens() {
        let a = placeholderReq("A", token: "BOX_SECRET_ALPHA")
        let b = placeholderReq("B", token: "BOX_SECRET_DELTA")
        let ins = req("HDR", scopes: [SecretScope(host: "h.example.com")])
        #expect(SecretInjection.tokenCollisionErrors([a, b, ins]).isEmpty)
        #expect(SecretInjection.tokenCollisionErrors([a]).isEmpty)
        #expect(SecretInjection.tokenCollisionErrors([]).isEmpty)
    }
}
