import Foundation

// MARK: - IPA Processor

/// Handles IPA extraction, modification, and repackaging using ZIPFoundation
class IPAProcessor {

    // MARK: - Properties

    private let fileManager = FileManager.default
    private let workDir: URL

    init() {
        workDir = fileManager.temporaryDirectory
            .appendingPathComponent("IPASigner_\(UUID().uuidString)")
    }

    deinit {
        cleanup()
    }

    // MARK: - Extract IPA

    /// Extracts a .ipa file into a working directory and returns the .app bundle URL
    /// - Parameter ipaURL: Path to the .ipa file
    /// - Returns: URL to the extracted Payload/*.app bundle
    func extract(ipaURL: URL) throws -> URL {
        try fileManager.createDirectory(at: workDir, withIntermediateDirectories: true)

        LogManager.shared.log("Extracting IPA: \(ipaURL.lastPathComponent)")

        // Use ZIPFoundation to extract
        try fileManager.unzipItem(at: ipaURL, to: workDir)

        // Locate Payload/*.app
        let payloadDir = workDir.appendingPathComponent("Payload")
        guard fileManager.fileExists(atPath: payloadDir.path) else {
            throw IPAError.invalidStructure("No Payload directory found in IPA")
        }

        let contents = try fileManager.contentsOfDirectory(atPath: payloadDir.path)
        guard let appName = contents.first(where: { $0.hasSuffix(".app") }) else {
            throw IPAError.invalidStructure("No .app bundle found in Payload/")
        }

        let appURL = payloadDir.appendingPathComponent(appName)
        LogManager.shared.log("Found app bundle: \(appName)")
        return appURL
    }

    // MARK: - Prepare Bundle for Re-signing

    /// Remove old code signature and replace provisioning profile
    func prepareBundleForSigning(appURL: URL, provisionData: Data) throws {
        LogManager.shared.log("Preparing bundle for signing...")

        // 1. Remove _CodeSignature directory
        let codeSignatureDir = appURL.appendingPathComponent("_CodeSignature")
        if fileManager.fileExists(atPath: codeSignatureDir.path) {
            try fileManager.removeItem(at: codeSignatureDir)
            LogManager.shared.log("Removed _CodeSignature directory")
        }

        // 2. Replace embedded.mobileprovision
        let provisionDest = appURL.appendingPathComponent("embedded.mobileprovision")
        if fileManager.fileExists(atPath: provisionDest.path) {
            try fileManager.removeItem(at: provisionDest)
        }
        try provisionData.write(to: provisionDest)
        LogManager.shared.log("Replaced embedded.mobileprovision")

        // 3. Process nested frameworks
        try processNestedBundles(in: appURL)
    }

    /// Recursively prepare all nested frameworks, plugins, and extensions
    private func processNestedBundles(in appURL: URL) throws {
        let nestedDirs = [
            appURL.appendingPathComponent("Frameworks"),
            appURL.appendingPathComponent("PlugIns"),
            appURL.appendingPathComponent("Extensions"),
            appURL.appendingPathComponent("AppExtensions")
        ]

        for dir in nestedDirs {
            guard fileManager.fileExists(atPath: dir.path) else { continue }

            let contents = try fileManager.contentsOfDirectory(atPath: dir.path)

            for item in contents {
                let itemURL = dir.appendingPathComponent(item)
                let codeSigDir = itemURL.appendingPathComponent("_CodeSignature")
                if fileManager.fileExists(atPath: codeSigDir.path) {
                    try fileManager.removeItem(at: codeSigDir)
                    LogManager.shared.log("Removed _CodeSignature from: \(item)")
                }
            }
        }
    }

    // MARK: - Collect Bundles to Sign (Deepest First)

    /// Returns all bundle URLs that need signing, ordered deepest-first
    /// so nested bundles are signed before their parent
    func allBundlesToSign(in appURL: URL) throws -> [URL] {
        var bundles: [URL] = []

        let nestedDirs = [
            appURL.appendingPathComponent("Frameworks"),
            appURL.appendingPathComponent("PlugIns"),
            appURL.appendingPathComponent("Extensions"),
            appURL.appendingPathComponent("AppExtensions"),
            appURL.appendingPathComponent("Watch")
        ]

        // Add nested bundles first (sign deepest first)
        for dir in nestedDirs {
            guard fileManager.fileExists(atPath: dir.path) else { continue }
            let contents = try fileManager.contentsOfDirectory(atPath: dir.path)
            for item in contents {
                let itemURL = dir.appendingPathComponent(item)
                var isDir = ObjCBool(false)
                if fileManager.fileExists(atPath: itemURL.path, isDirectory: &isDir), isDir.boolValue {
                    bundles.append(itemURL)
                }
            }
        }

        // Add the main .app last
        bundles.append(appURL)

        return bundles
    }

    // MARK: - Repackage IPA

    /// Zip the Payload directory back into a valid .ipa file
    /// - Returns: URL to the newly signed .ipa
    func repackage(outputName: String) throws -> URL {
        let outputURL = fileManager.temporaryDirectory
            .appendingPathComponent(outputName)

        if fileManager.fileExists(atPath: outputURL.path) {
            try fileManager.removeItem(at: outputURL)
        }

        LogManager.shared.log("Repackaging IPA...")

        // ZIPFoundation: zip the workDir (which contains Payload/)
        try fileManager.zipItem(at: workDir, to: outputURL)

        LogManager.shared.log("Repackaged IPA saved to: \(outputURL.lastPathComponent)")
        return outputURL
    }

    // MARK: - Bundle Info.plist

    /// Read Info.plist from a bundle
    func infoPlist(in bundleURL: URL) throws -> [String: Any] {
        let plistURL = bundleURL.appendingPathComponent("Info.plist")
        guard fileManager.fileExists(atPath: plistURL.path) else {
            throw IPAError.missingInfoPlist(bundleURL.lastPathComponent)
        }
        let data = try Data(contentsOf: plistURL)
        guard let plist = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            throw IPAError.invalidInfoPlist(bundleURL.lastPathComponent)
        }
        return plist
    }

    /// Update bundle identifier in Info.plist
    func updateBundleID(_ bundleID: String, in bundleURL: URL) throws {
        let plistURL = bundleURL.appendingPathComponent("Info.plist")
        var plist = try infoPlist(in: bundleURL)
        plist["CFBundleIdentifier"] = bundleID
        let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        try data.write(to: plistURL)
    }

    // MARK: - Cleanup

    func cleanup() {
        try? fileManager.removeItem(at: workDir)
    }

    var extractedWorkDir: URL { workDir }
}

// MARK: - IPA Errors

enum IPAError: LocalizedError {
    case invalidStructure(String)
    case missingInfoPlist(String)
    case invalidInfoPlist(String)
    case zipFailed(String)
    case unzipFailed(String)

    var errorDescription: String? {
        switch self {
        case .invalidStructure(let msg): return "Invalid IPA structure: \(msg)"
        case .missingInfoPlist(let bundle): return "Missing Info.plist in \(bundle)"
        case .invalidInfoPlist(let bundle): return "Invalid Info.plist in \(bundle)"
        case .zipFailed(let msg): return "Failed to create IPA: \(msg)"
        case .unzipFailed(let msg): return "Failed to extract IPA: \(msg)"
        }
    }
}
