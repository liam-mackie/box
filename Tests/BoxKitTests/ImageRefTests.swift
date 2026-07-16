import Testing

@testable import BoxKit

@Suite("Box.imageRef / storeRef toolchain derivation")
struct ImageRefTests {
    @Test("empty toolchain set yields today's exact refs (byte-identical)")
    func emptyMatchesLegacy() {
        #expect(Box.imageRef() == "box:latest")
        #expect(Box.imageRef(toolchains: []) == "box:latest")
        #expect(Box.storeRef() == "docker.io/library/box:latest")
        #expect(Box.storeRef(toolchains: []) == "docker.io/library/box:latest")
    }

    @Test("non-empty set appends sorted, deduped, lowercased toolchains")
    func variantTagged() {
        #expect(Box.imageRef(toolchains: ["go", "dotnet", "rust"]) == "box:dotnet-go-rust")
        #expect(
            Box.storeRef(toolchains: ["go", "dotnet", "rust"])
                == "docker.io/library/box:dotnet-go-rust")
    }

    @Test("dedups and normalizes case/order before tagging")
    func dedupAndNormalize() {
        #expect(Box.imageRef(toolchains: ["Rust", "rust", "GO"]) == "box:go-rust")
        #expect(Box.imageRef(toolchains: ["dotnet", "dotnet"]) == "box:dotnet")
    }
}
