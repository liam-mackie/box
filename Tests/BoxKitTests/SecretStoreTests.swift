import Foundation
import Testing

@testable import BoxKit

@Suite("SecretStore model + validation")
struct SecretStoreTests {
    /// Convenience builder.
    private func req(
        _ name: String, location: SecretLocation = .header, field: String = "Authorization",
        template: String = "Bearer ${value}",
        scopes: [SecretScope] = [SecretScope(host: "api.example.com", pathPrefix: "/v1/")]
    ) -> SecretRequirement {
        SecretRequirement(
            name: name,
            injection: SecretInjectionSpec(location: location, field: field, template: template),
            scopes: scopes)
    }

    // MARK: validation

    @Test("a well-formed requirement validates")
    func validPasses() {
        #expect(req("GH_API").validationErrors(isPinned: { _ in false }).isEmpty)
    }

    @Test("pinned scope host is rejected")
    func pinnedHostRejected() {
        let r = req("X", scopes: [SecretScope(host: "api.github.com")])
        let errs = r.validationErrors(isPinned: { $0 == "api.github.com" })
        #expect(errs.contains { $0.contains("pinned") })
    }

    @Test("empty scopes rejected")
    func emptyScopes() {
        let r = req("X", scopes: [])
        #expect(!r.validationErrors(isPinned: { _ in false }).isEmpty)
    }

    @Test("bad name characters rejected")
    func badName() {
        let r = req("has space")
        #expect(r.validationErrors(isPinned: { _ in false }).contains { $0.contains("name") })
    }

    @Test("template without ${value} rejected")
    func templateNeedsValue() {
        let r = req("X", template: "Bearer constant")
        #expect(r.validationErrors(isPinned: { _ in false }).contains { $0.contains("${value}") })
    }

    @Test("unknown transform rejected")
    func unknownTransform() {
        let r = req("X", template: "${value|rot13}")
        #expect(r.validationErrors(isPinned: { _ in false }).contains { $0.contains("rot13") })
    }

    @Test("pathPrefix + pathRegex together rejected")
    func bothPaths() {
        let r = req("X", scopes: [SecretScope(host: "h", pathPrefix: "/a", pathRegex: "^/b")])
        #expect(r.validationErrors(isPinned: { _ in false }).contains { $0.contains("pathPrefix") })
    }

    @Test("pathPrefix must be absolute")
    func relativePrefix() {
        let r = req("X", scopes: [SecretScope(host: "h", pathPrefix: "v1/")])
        #expect(r.validationErrors(isPinned: { _ in false }).contains { $0.contains("start with") })
    }

    // MARK: registry ops

    @Test("upsert replaces by name")
    func upsertReplaces() {
        var reg = SecretRegistry()
        reg.upsert(req("A", field: "Authorization"))
        reg.upsert(req("A", field: "X-Api-Key"))
        #expect(reg.requirements.count == 1)
        #expect(reg.requirements[0].injection.field == "X-Api-Key")
    }

    @Test("remove drops requirement and binding")
    func removeDrops() {
        var reg = SecretRegistry()
        reg.upsert(req("A"))
        reg.bindings["A"] = .env("A_TOKEN")
        // Pull the mutating `remove` out of `#expect` (the macro captures its
        // receiver immutably, so a mutating call inside it doesn't compile).
        let removed = reg.remove(name: "A")
        #expect(removed)
        #expect(reg.requirements.isEmpty)
        #expect(reg.bindings["A"] == nil)
        let removedAgain = reg.remove(name: "A")  // second time: nothing changed
        #expect(!removedAgain)
    }

    // MARK: source codable

    @Test("SecretSource round-trips through JSON")
    func sourceCodable() throws {
        for src in [SecretSource.env("VAR"), .keychain(service: "svc", account: "me")] {
            let data = try JSONEncoder().encode(src)
            let back = try JSONDecoder().decode(SecretSource.self, from: data)
            #expect(back == src)
        }
    }

    @Test("registry tolerates a missing bindings key")
    func registryTolerant() throws {
        let json = #"{"requirements":[]}"#
        let reg = try JSONDecoder().decode(SecretRegistry.self, from: Data(json.utf8))
        #expect(reg.bindings.isEmpty)
    }

    @Test("project file decodes requirements and has no source path")
    func projectFile() throws {
        let json = """
            {"requirements":[{"name":"P","injection":{"location":"cookie","field":"session","template":"${value}"},"scopes":[{"host":"x.example.com"}]}]}
            """
        let file = try JSONDecoder().decode(ProjectSecretsFile.self, from: Data(json.utf8))
        #expect(file.requirements.count == 1)
        #expect(file.requirements[0].injection.location == .cookie)
    }

    // MARK: template rendering

    @Test("template renders literal + base64 + urlencode")
    func templateRender() throws {
        #expect(try SecretTemplate.render("Bearer ${value}", value: "T") == "Bearer T")
        #expect(try SecretTemplate.render("${value|base64}", value: "abc") == "YWJj")
        #expect(try SecretTemplate.render("${value|urlencode}", value: "a b/c") == "a%20b%2Fc")
    }

    @Test("unknown transform throws at render")
    func renderThrowsUnknown() {
        #expect(throws: (any Error).self) {
            _ = try SecretTemplate.render("${value|nope}", value: "x")
        }
    }
}
