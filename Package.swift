// swift-tools-version: 5.9
// This Package.swift defines only the ZIPFoundation dependency.
// The app itself must be built via Xcode — see README.md.
import PackageDescription

let package = Package(
    name: "IPASigner",
    platforms: [.iOS(.v16)],
    products: [
        .library(name: "IPASigner", targets: ["IPASigner"])
    ],
    dependencies: [
        // ZIPFoundation for reading/writing ZIP archives (IPA = ZIP)
        .package(
            url: "https://github.com/weichsel/ZIPFoundation.git",
            from: "0.9.19"
        )
    ],
    targets: [
        .target(
            name: "IPASigner",
            dependencies: ["ZIPFoundation"],
            path: "IPASigner",
            exclude: ["Resources/Info.plist"]
        )
    ]
)
