import Foundation
import Testing

@testable import BoxKit

@Suite("Devcontainer: JSONC parsing (pure)")
struct DevcontainerParseTests {
    @Test("strips // and /* */ comments and trailing commas")
    func stripsComments() throws {
        let jsonc = """
            {
              // base image for the project
              "image": "swift:5.10", /* inline comment */
              "postCreateCommand": "swift build", // build on create
            }
            """
        let spec = try Devcontainer.parse(Data(jsonc.utf8))
        #expect(spec.image == "swift:5.10")
        #expect(spec.postCreateCommands == ["swift build"])
    }

    @Test("preserves // and commas inside string literals")
    func preservesInStrings() throws {
        let spec = try Devcontainer.parse(Data(#"{"image":"reg.io/a//b:1,2"}"#.utf8))
        #expect(spec.image == "reg.io/a//b:1,2")
    }

    @Test("reads build.dockerfile and context")
    func buildBlock() throws {
        let jsonc = #"{"build": {"dockerfile": "Dockerfile", "context": ".."}}"#
        let spec = try Devcontainer.parse(Data(jsonc.utf8))
        #expect(spec.dockerfile == "Dockerfile")
        #expect(spec.context == "..")
        #expect(spec.image == nil)
    }

    @Test("normalizes postCreateCommand string / array / object")
    func postCreateForms() throws {
        let s = try Devcontainer.parse(Data(#"{"postCreateCommand": "a b"}"#.utf8))
        #expect(s.postCreateCommands == ["a b"])
        let arr = try Devcontainer.parse(Data(#"{"postCreateCommand": ["swift","build"]}"#.utf8))
        #expect(arr.postCreateCommands == ["swift build"])
        let obj = try Devcontainer.parse(
            Data(#"{"postCreateCommand": {"z": "second", "a": "first"}}"#.utf8))
        #expect(obj.postCreateCommands == ["first", "second"])  // sorted by key
    }

    @Test("throws on a non-object document")
    func nonObject() {
        #expect(throws: (any Error).self) {
            _ = try Devcontainer.parse(Data("[1,2,3]".utf8))
        }
    }
}

@Suite("Devcontainer: keying + compose + detect")
struct DevcontainerComposeTests {
    @Test("variantTag is stable, input-sensitive, and dc- prefixed")
    func tag() {
        let a = Devcontainer.variantTag([Data("x".utf8)])
        let a2 = Devcontainer.variantTag([Data("x".utf8)])
        let b = Devcontainer.variantTag([Data("y".utf8)])
        #expect(a == a2)
        #expect(a != b)
        #expect(a.hasPrefix("dc-"))
    }

    @Test("dockerfile substitutes the base placeholder and appends postCreate RUNs")
    func compose() {
        let template = "FROM __DC_BASE__ AS s\nFROM __DC_BASE__\nRUN true"
        let df = Devcontainer.dockerfile(
            base: "swift:5.10", template: template, postCreate: ["echo hi"])
        #expect(df.contains("FROM swift:5.10 AS s"))
        #expect(df.contains("FROM swift:5.10\n"))
        #expect(!df.contains("__DC_BASE__"))
        #expect(df.contains("RUN echo hi"))
    }

    @Test("detect finds .devcontainer/devcontainer.json")
    func detect() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("dc-\(UUID().uuidString)", isDirectory: true)
        let dc = root.appendingPathComponent(".devcontainer")
        try FileManager.default.createDirectory(at: dc, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = dc.appendingPathComponent("devcontainer.json")
        try Data(#"{"image":"swift:5.10"}"#.utf8).write(to: file)

        #expect(Devcontainer.detect(projectRoot: root)?.path == file.path)
    }

    @Test("detect returns nil when there's no devcontainer")
    func detectNone() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("dc-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        #expect(Devcontainer.detect(projectRoot: root) == nil)
    }
}

@Suite("Devcontainer.autoDecision (flag × detect × trust)")
struct DevcontainerAutoDecisionTests {
    @Test("flagged + detected builds the devcontainer via per-run consent (trust irrelevant)")
    func flaggedDetected() {
        #expect(
            Devcontainer.autoDecision(flagged: true, detected: true, trusted: false)
                == .devcontainer(consent: .flag))
        #expect(
            Devcontainer.autoDecision(flagged: true, detected: true, trusted: true)
                == .devcontainer(consent: .flag))
    }

    @Test("flagged + nothing detected falls back to the base image with a warning")
    func flaggedMissing() {
        #expect(
            Devcontainer.autoDecision(flagged: true, detected: false, trusted: false)
                == .baseWarnMissing)
        #expect(
            Devcontainer.autoDecision(flagged: true, detected: false, trusted: true)
                == .baseWarnMissing)
    }

    @Test("unflagged + detected + trusted auto-builds the devcontainer")
    func autoTrusted() {
        #expect(
            Devcontainer.autoDecision(flagged: false, detected: true, trusted: true)
                == .devcontainer(consent: .trusted))
    }

    @Test("unflagged + detected + untrusted uses the base image with a hint")
    func untrustedHint() {
        #expect(
            Devcontainer.autoDecision(flagged: false, detected: true, trusted: false)
                == .baseWithHint)
    }

    @Test("unflagged + nothing detected silently uses the base image")
    func plainBase() {
        #expect(
            Devcontainer.autoDecision(flagged: false, detected: false, trusted: false) == .base)
        #expect(
            Devcontainer.autoDecision(flagged: false, detected: false, trusted: true) == .base)
    }

    @Test("usesDevcontainer is true only for the two devcontainer outcomes")
    func usesDevcontainerFlag() {
        #expect(
            Devcontainer.autoDecision(flagged: true, detected: true, trusted: false)
                .usesDevcontainer)
        #expect(
            Devcontainer.autoDecision(flagged: false, detected: true, trusted: true)
                .usesDevcontainer)
        #expect(
            !Devcontainer.autoDecision(flagged: false, detected: true, trusted: false)
                .usesDevcontainer)
        #expect(
            !Devcontainer.autoDecision(flagged: true, detected: false, trusted: true)
                .usesDevcontainer)
        #expect(
            !Devcontainer.autoDecision(flagged: false, detected: false, trusted: false)
                .usesDevcontainer)
    }
}
