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

    @Test("placeholder requirement with a valid token passes")
    func placeholderValid() {
        let r = placeholderReq("gh", token: "BOX_SECRET_GH")
        #expect(r.validationErrors(isPinned: { _ in false }).isEmpty)
    }

    @Test("placeholder requirement validates its token")
    func placeholderBadToken() {
        let r = placeholderReq("gh", token: "bad token")
        #expect(r.validationErrors(isPinned: { _ in false }).contains { $0.contains("token") })
    }

    @Test("placeholder requirement still requires scopes")
    func placeholderEmptyScopes() {
        let r = placeholderReq("gh", token: "BOX_SECRET_GH", scopes: [])
        #expect(
            r.validationErrors(isPinned: { _ in false }).contains { $0.contains("scope") })
    }

    @Test("placeholder requirement rejects pinned scope hosts")
    func placeholderPinnedHost() {
        let r = placeholderReq(
            "gh", token: "BOX_SECRET_GH", scopes: [SecretScope(host: "api.github.com")])
        #expect(r.validationErrors(isPinned: { _ in true }).contains { $0.contains("pinned") })
    }

    // MARK: registry ops

    @Test("upsert replaces by name")
    func upsertReplaces() {
        var reg = SecretRegistry()
        reg.upsert(req("A", field: "Authorization"))
        reg.upsert(req("A", field: "X-Api-Key"))
        #expect(reg.requirements.count == 1)
        #expect(
            reg.requirements[0].injection
                == .insert(location: .header, field: "X-Api-Key", template: "Bearer ${value}"))
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

    // MARK: injection spec codable

    @Test("injection spec round-trips through JSON in both modes")
    func specCodable() throws {
        let specs: [SecretInjectionSpec] = [
            .insert(location: .header, field: "Authorization", template: "Bearer ${value}"),
            .insert(location: .cookie, field: "session", template: "${value}"),
            .insert(location: .query, field: "api_key", template: "${value|urlencode}"),
            .placeholder(token: "BOX_SECRET_GH", template: "${value}"),
        ]
        for spec in specs {
            let data = try JSONEncoder().encode(spec)
            #expect(try JSONDecoder().decode(SecretInjectionSpec.self, from: data) == spec)
        }
    }

    @Test("legacy insert JSON decodes unchanged")
    func legacyInsertJSON() throws {
        let json = #"{"location":"header","field":"Authorization","template":"Bearer ${value}"}"#
        let spec = try JSONDecoder().decode(SecretInjectionSpec.self, from: Data(json.utf8))
        #expect(
            spec == .insert(location: .header, field: "Authorization", template: "Bearer ${value}"))
    }

    @Test("placeholder JSON without a token fails to decode")
    func placeholderNeedsToken() {
        let json = #"{"location":"placeholder","template":"${value}"}"#
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(SecretInjectionSpec.self, from: Data(json.utf8))
        }
    }

    @Test("unknown location fails to decode")
    func unknownLocation() {
        let json = #"{"location":"trailer","field":"X","template":"${value}"}"#
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(SecretInjectionSpec.self, from: Data(json.utf8))
        }
    }

    // MARK: placeholder tokens

    @Test("derived token uppercases the name and maps other characters to underscores")
    func derivedToken() {
        #expect(SecretToken.derived(fromName: "github-token") == "BOX_SECRET_GITHUB_TOKEN")
        #expect(SecretToken.derived(fromName: "gh") == "BOX_SECRET_GH")
        #expect(SecretToken.derived(fromName: "a_b-c9") == "BOX_SECRET_A_B_C9")
    }

    @Test("token validation enforces charset and length")
    func tokenValidation() {
        #expect(SecretToken.validationErrors("BOX_SECRET_X").isEmpty)
        #expect(SecretToken.validationErrors("ABCD1234").isEmpty)
        #expect(!SecretToken.validationErrors("SHORT").isEmpty)
        #expect(!SecretToken.validationErrors("lower_case_token").isEmpty)
        #expect(!SecretToken.validationErrors("HAS-DASHES-AB").isEmpty)
        #expect(!SecretToken.validationErrors(String(repeating: "A", count: 65)).isEmpty)
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
        #expect(
            file.requirements[0].injection
                == .insert(location: .cookie, field: "session", template: "${value}"))
    }

    // MARK: template validation

    @Test("template validation accepts value tokens and known transforms")
    func templateValid() {
        #expect(SecretTemplate.validationErrors("Bearer ${value}").isEmpty)
        #expect(SecretTemplate.validationErrors("${value|base64}").isEmpty)
        #expect(SecretTemplate.validationErrors("${value|urlencode}").isEmpty)
    }

    @Test("template validation rejects a missing value token and unknown transforms")
    func templateInvalid() {
        #expect(!SecretTemplate.validationErrors("no token here").isEmpty)
        #expect(!SecretTemplate.validationErrors("${value|nope}").isEmpty)
    }
}
