// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "box",
    platforms: [.macOS("26.0")],
    products: [
        .executable(name: "box", targets: ["box"])
    ],
    dependencies: [
        // Pinned to match the API this code was written against (the local clone).
        .package(url: "https://github.com/apple/containerization.git", exact: "0.33.1"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.7.0"),
    ],
    targets: [
        .target(
            name: "BoxKit",
            dependencies: [
                .product(name: "Containerization", package: "containerization"),
                .product(name: "ContainerizationOS", package: "containerization"),
                .product(name: "ContainerizationOCI", package: "containerization"),
            ]
        ),
        .executableTarget(
            name: "box",
            dependencies: [
                "BoxKit",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
        .testTarget(
            name: "BoxKitTests",
            dependencies: ["BoxKit"]
        ),
    ]
)
