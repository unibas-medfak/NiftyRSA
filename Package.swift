// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "NiftyRSA",
    platforms: [
        .iOS(.v18),
        .macOS(.v15),
        .tvOS(.v18),
        .watchOS(.v11),
    ],
    products: [
        .library(
            name: "NiftyRSA",
            targets: ["NiftyRSA"]
        )
    ],
    targets: [
        .target(
            name: "NiftyRSA",
            resources: [
                .process("Resources/PrivacyInfo.xcprivacy")
            ]
        ),
        .testTarget(
            name: "NiftyRSATests",
            dependencies: ["NiftyRSA"],
            resources: [
                .process("Resources")
            ]
        ),
    ]
)
