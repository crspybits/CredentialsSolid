// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "CredentialsSolid",
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "CredentialsSolid",
            targets: ["CredentialsSolid"]),
    ],
    dependencies: [
        .package(url: "https://github.com/crspybits/SolidAuthSwift.git", from: "0.0.2"),
        .package(url: "https://github.com/IBM-Swift/Kitura-Credentials.git", .upToNextMajor(from: "2.4.1")),
        .package(url: "https://github.com/IBM-Swift/HeliumLogger.git", from: "1.8.1"),
    ],
    targets: [
        .target(
            name: "CredentialsSolid",
            dependencies: [
                "HeliumLogger",
                .product(name: "Credentials", package: "Kitura-Credentials"),
                .product(name: "SolidAuthSwiftTools", package: "SolidAuthSwift"),
            ]),
    ]
)
