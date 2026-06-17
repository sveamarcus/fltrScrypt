// swift-tools-version: 6.2
import PackageDescription

// Applied to every Swift target: opt fully into the Swift 6 language mode so the
// whole package is checked under complete data-race safety on every platform.
let swiftSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6)
]

let package = Package(
    name: "fltrScrypt",
    // Minimum deployment targets for Apple platforms. Non-Apple platforms
    // (Linux, Android, Windows, WASI) are supported without an entry here.
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .tvOS(.v13),
        .watchOS(.v6),
        .macCatalyst(.v13),
        .visionOS(.v1),
    ],
    products: [
        .library(
            name: "fltrScrypt",
            targets: ["fltrScrypt"])
    ],
    targets: [
        // Colin Percival's reference scrypt + SHA-256/PBKDF2 implementation,
        // vendored as a git submodule under Sources/Clibscrypt. Only the portable
        // (non-SSE) core and the hash primitives are compiled; the CLI front-ends,
        // base64/MCF helpers and the SSE variant are excluded. `publicHeadersPath:
        // "."` puts the header directory on the include path and propagates it to
        // dependents, so no extra `cSettings` (header search paths) are required.
        .target(
            name: "Clibscrypt",
            path: "Sources/Clibscrypt",
            exclude: [
                "b64.c",
                "crypto_scrypt-check.c",
                "crypto_scrypt-hash.c",
                "crypto_scrypt-hexconvert.c",
                "crypto-mcf.c",
                "crypto-scrypt-saltgen.c",
                "slowequals.c",
                "README.md",
                "LICENSE",
                "Makefile",
                "libscrypt.version",
                "main.c",
            ],
            sources: [
                "crypto_scrypt-nosse.c",
                "sha256.c",
            ],
            publicHeadersPath: "."),
        .target(
            name: "fltrScrypt",
            dependencies: ["Clibscrypt"],
            swiftSettings: swiftSettings),
        .testTarget(
            name: "fltrScryptTests",
            dependencies: ["fltrScrypt"],
            swiftSettings: swiftSettings),
    ],
    swiftLanguageModes: [.v6]
)
