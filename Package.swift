// swift-tools-version: 6.3.3

import PackageDescription

let package = Package(
    name: "swift-tls",
    platforms: [.macOS(.v26), .iOS(.v26), .tvOS(.v26), .watchOS(.v26), .visionOS(.v26)],
    products: [
        .library(name: "TLS", targets: ["TLS"]),
        .library(name: "TLS Engine Interface", targets: ["TLS Engine Interface"]),
        .library(name: "TLS Apple Engine", targets: ["TLS Apple Engine"]),
        .library(name: "TLS OpenSSL Engine", targets: ["TLS OpenSSL Engine"]),
        .library(name: "TLS SChannel Engine", targets: ["TLS SChannel Engine"]),
    ],
    dependencies: [
        .package(url: "https://github.com/swift-foundations/swift-domain-name-system.git", revision: "4bd74b5"),
        .package(url: "https://github.com/swift-foundations/swift-ip-address.git", branch: "main"),
        .package(url: "https://github.com/swift-foundations/swift-certificate-verification.git", revision: "1b4fc68"),
        .package(
            url: "https://github.com/swift-foundations/swift-byte-channel.git",
            revision: "6a7eaf41b153f332ac2f144d105197c4b00c2a2e"
        ),
        .package(url: "https://github.com/swift-primitives/swift-span-primitives.git", branch: "main"),
    ],
    targets: [
        .target(name: "TLS", dependencies: [
            .product(name: "Domain Name System", package: "swift-domain-name-system"),
            .product(name: "IP Address", package: "swift-ip-address"),
            .product(name: "Certificates", package: "swift-certificate-verification"),
            .product(name: "Span Raw Primitives", package: "swift-span-primitives"),
        ]),
        .target(name: "TLS Engine Interface", dependencies: [
            "TLS",
            .product(name: "Byte Channel", package: "swift-byte-channel"),
        ]),
        .target(name: "TLS Apple Engine", dependencies: ["TLS Engine Interface"]),
        .target(name: "TLS OpenSSL Engine", dependencies: ["TLS Engine Interface"]),
        .target(name: "TLS SChannel Engine", dependencies: ["TLS Engine Interface"]),
        .testTarget(name: "TLS Contract Tests", dependencies: [
            "TLS",
            "TLS Engine Interface",
            "TLS Apple Engine",
            "TLS OpenSSL Engine",
            "TLS SChannel Engine",
        ]),
    ],
    swiftLanguageModes: [.v6]
)

for target in package.targets where ![.system, .binary, .plugin, .macro].contains(target.type) {
    target.swiftSettings = (target.swiftSettings ?? []) + [
        .strictMemorySafety(),
        .enableUpcomingFeature("ExistentialAny"),
        .enableUpcomingFeature("InternalImportsByDefault"),
        .enableUpcomingFeature("MemberImportVisibility"),
        .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
        .enableExperimentalFeature("LifetimeDependence"),
        .enableExperimentalFeature("Lifetimes"),
        .enableExperimentalFeature("SuppressedAssociatedTypes"),
        .enableUpcomingFeature("InferIsolatedConformances"),
    ]
}
