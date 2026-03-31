import Foundation
import Security

// MARK: - Provisioning Profile Parser

/// Parses a .mobileprovision file (CMS-signed plist)
struct ProvisioningProfile {
    let name: String
    let bundleIdentifier: String
    let teamIdentifier: String
    let creationDate: Date
    let expirationDate: Date
    let entitlements: [String: Any]
    let rawData: Data

    // MARK: - Parsing

    /// Parse a .mobileprovision file at the given URL
    static func parse(from url: URL) throws -> ProvisioningProfile {
        let data = try Data(contentsOf: url)
        return try parse(from: data)
    }

    /// Parse raw .mobileprovision data
    /// The file is a CMS (PKCS#7) signed message wrapping an XML plist
    static func parse(from data: Data) throws -> ProvisioningProfile {
        // Extract embedded plist from CMS envelope by scanning for plist markers
        guard let plistData = extractPlist(from: data) else {
            throw ProvisioningError.invalidFormat("Could not extract plist from provisioning profile")
        }

        // Parse plist
        guard let plist = try PropertyListSerialization.propertyList(
            from: plistData,
            options: [],
            format: nil
        ) as? [String: Any] else {
            throw ProvisioningError.invalidFormat("Provisioning profile plist has unexpected format")
        }

        // Extract required fields
        guard let name = plist["Name"] as? String else {
            throw ProvisioningError.missingField("Name")
        }

        guard let entitlements = plist["Entitlements"] as? [String: Any] else {
            throw ProvisioningError.missingField("Entitlements")
        }

        guard let bundleID = entitlements["application-identifier"] as? String else {
            throw ProvisioningError.missingField("application-identifier in entitlements")
        }

        // Bundle ID may be prefixed with team ID (e.g. "TEAMID.com.example.app")
        let cleanBundleID = bundleID.contains(".") ? String(bundleID.split(separator: ".", maxSplits: 1).dropFirst().joined(separator: ".")) : bundleID

        // Extract team identifier
        let teamID: String
        if let teamIDs = plist["TeamIdentifier"] as? [String], let first = teamIDs.first {
            teamID = first
        } else {
            teamID = ""
        }

        let creationDate = plist["CreationDate"] as? Date ?? Date()
        let expirationDate = plist["ExpirationDate"] as? Date ?? Date()

        return ProvisioningProfile(
            name: name,
            bundleIdentifier: cleanBundleID,
            teamIdentifier: teamID,
            creationDate: creationDate,
            expirationDate: expirationDate,
            entitlements: entitlements,
            rawData: data
        )
    }

    // MARK: - Entitlements Plist

    /// Serialize entitlements to plist Data for embedding
    func entitlementsPlistData() throws -> Data {
        return try PropertyListSerialization.data(
            fromPropertyList: entitlements,
            format: .xml,
            options: 0
        )
    }

    // MARK: - Helpers

    var isExpired: Bool {
        return expirationDate < Date()
    }

    var fullBundleIdentifier: String {
        // Return the full application-identifier (with team prefix)
        return entitlements["application-identifier"] as? String ?? bundleIdentifier
    }

    // MARK: - Private CMS Extraction

    /// Extract the raw plist bytes from within the CMS envelope
    /// The DER-encoded CMS blob contains the plist as an embedded octet string
    private static func extractPlist(from data: Data) -> Data? {
        // The plist starts with <?xml or the binary plist marker bplist
        let xmlMarker = Data("<?xml".utf8)
        let bplistMarker = Data([0x62, 0x70, 0x6C, 0x69, 0x73, 0x74]) // bplist

        // Search for XML plist start
        if let range = data.range(of: xmlMarker) {
            // Find the closing </plist> tag
            let closingTag = Data("</plist>".utf8)
            if let endRange = data.range(of: closingTag, options: [], in: range.lowerBound..<data.endIndex) {
                let end = endRange.upperBound
                return data.subdata(in: range.lowerBound..<end)
            }
        }

        // Search for binary plist start
        if let range = data.range(of: bplistMarker) {
            // Binary plists are harder to delimit — try from marker to end of data
            return data.subdata(in: range.lowerBound..<data.endIndex)
        }

        return nil
    }
}

// MARK: - Errors

enum ProvisioningError: LocalizedError {
    case invalidFormat(String)
    case missingField(String)
    case expired

    var errorDescription: String? {
        switch self {
        case .invalidFormat(let msg): return "Invalid provisioning profile format: \(msg)"
        case .missingField(let field): return "Missing field in provisioning profile: \(field)"
        case .expired: return "Provisioning profile is expired"
        }
    }
}
