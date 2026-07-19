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

    @Test("bootSummary lists name, location, and hosts (never the value)")
    func bootSummary() {
        let r = resolved(
            req("GH", scopes: [SecretScope(host: "api.github.com")]), "SECRET-TOKEN")
        let summary = SecretInjection.bootSummary([r])
        #expect(summary == "GH(header→api.github.com)")
        #expect(!summary.contains("SECRET-TOKEN"))
    }
}
