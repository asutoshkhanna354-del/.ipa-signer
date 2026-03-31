import Foundation
import UIKit

// MARK: - OTA Installer

/// Handles OTA (Over-The-Air) installation via the itms-services:// URL scheme
class OTAInstaller: ObservableObject {

    static let shared = OTAInstaller()
    private init() {}

    // MARK: - Properties

    private let server = LocalHTTPServer()
    @Published var isServing = false
    @Published var installURL: URL?

    // MARK: - Start OTA Installation

    /// Prepare and trigger OTA installation for a signed IPA
    /// - Parameters:
    ///   - ipaURL: Path to the signed .ipa file
    ///   - bundleID: App bundle identifier
    ///   - version: App version string
    ///   - title: App display title
    func install(
        ipaURL: URL,
        bundleID: String,
        version: String,
        title: String
    ) async throws {
        LogManager.shared.log("Preparing OTA installation...")

        // 1. Generate manifest.plist
        let manifestURL = try generateManifest(
            bundleID: bundleID,
            version: version,
            title: title
        )

        // 2. Start local HTTP server
        try server.start(ipaURL: ipaURL, manifestURL: manifestURL)
        isServing = true

        // Small delay to ensure server is ready
        try await Task.sleep(nanoseconds: 500_000_000)

        let port = server.port
        LogManager.shared.log("Local server running on port \(port)")

        // 3. Build the itms-services URL
        // NOTE: iOS requires HTTPS for OTA installs from external sources.
        // For local server installs, you may need to use a trusted certificate
        // or leverage a public tunnel (like ngrok) to provide HTTPS.
        // For development, devices with the signing cert trusted can use HTTP.
        let manifestServerURL = "http://127.0.0.1:\(port)/manifest.plist"
        let encodedURL = manifestServerURL.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? manifestServerURL
        let installURLString = "itms-services://?action=download-manifest&url=\(encodedURL)"

        guard let url = URL(string: installURLString) else {
            throw OTAError.invalidURL(installURLString)
        }

        self.installURL = url
        LogManager.shared.log("Install URL: \(installURLString)")

        // 4. Open the itms-services URL to trigger iOS installer
        await MainActor.run {
            UIApplication.shared.open(url, options: [:]) { [weak self] success in
                if success {
                    LogManager.shared.log("iOS installer launched successfully")
                } else {
                    LogManager.shared.log("⚠️ Failed to open installer URL. Make sure this is run on a real device.")
                    self?.server.stop()
                    self?.isServing = false
                }
            }
        }
    }

    // MARK: - Stop Server

    func stopServer() {
        server.stop()
        isServing = false
    }

    // MARK: - Manifest Generation

    /// Generate a manifest.plist compatible with Apple's OTA itms-services protocol
    private func generateManifest(
        bundleID: String,
        version: String,
        title: String
    ) throws -> URL {
        let port = server.port == 0 ? 8080 : server.port
        let ipaURL = "http://127.0.0.1:\(port)/app.ipa"

        // Build the manifest plist structure
        let manifest: [String: Any] = [
            "items": [
                [
                    "assets": [
                        [
                            "kind": "software-package",
                            "url": ipaURL
                        ]
                    ],
                    "metadata": [
                        "bundle-identifier": bundleID,
                        "bundle-version": version,
                        "kind": "software",
                        "title": title
                    ]
                ]
            ]
        ]

        let plistData = try PropertyListSerialization.data(
            fromPropertyList: manifest,
            format: .xml,
            options: 0
        )

        let manifestURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("manifest.plist")

        try plistData.write(to: manifestURL)
        LogManager.shared.log("Generated manifest.plist")
        return manifestURL
    }

    // MARK: - Save Signed IPA to Documents

    /// Copy signed IPA to the app's Documents directory for easier access
    func saveToDocuments(ipaURL: URL) throws -> URL {
        let docsDir = try FileManager.default.url(
            for: .documentDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        let destURL = docsDir.appendingPathComponent(ipaURL.lastPathComponent)

        if FileManager.default.fileExists(atPath: destURL.path) {
            try FileManager.default.removeItem(at: destURL)
        }

        try FileManager.default.copyItem(at: ipaURL, to: destURL)
        LogManager.shared.log("Saved signed IPA to Documents: \(destURL.lastPathComponent)")
        return destURL
    }
}

// MARK: - OTA Errors

enum OTAError: LocalizedError {
    case invalidURL(String)
    case serverStartFailed(String)
    case installLaunchFailed

    var errorDescription: String? {
        switch self {
        case .invalidURL(let url): return "Invalid install URL: \(url)"
        case .serverStartFailed(let msg): return "Failed to start local server: \(msg)"
        case .installLaunchFailed: return "Failed to launch iOS installer. Ensure you are on a real device."
        }
    }
}
