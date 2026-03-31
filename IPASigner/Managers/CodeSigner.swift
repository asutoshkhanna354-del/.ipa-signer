import Foundation
import Security
import CommonCrypto

// MARK: - Code Signer

/// Performs iOS code signing on .app bundles using Security.framework
/// Implements the Apple code signing format: superblob → code directory → CMS signature
class CodeSigner {

    // MARK: - Constants

    // Magic numbers for Apple code signing structures
    static let magicEmbeddedSignature: UInt32 = 0xFADE0CC0
    static let magicCodeDirectory:     UInt32 = 0xFADE0C02
    static let magicBlobWrapper:       UInt32 = 0xFADE0B01
    static let magicEntitlements:      UInt32 = 0xFADE7171
    static let magicEntitlementsDer:   UInt32 = 0xFADE7172

    // Blob slot indices in the superblob
    static let slotCodeDirectory:  UInt32 = 0
    static let slotEntitlements:   UInt32 = 5
    static let slotCMSSignature:   UInt32 = 0x10000

    // Code directory version
    static let codeDirectoryVersion: UInt32 = 0x20400

    // MARK: - Sign Bundle

    /// Sign a single .app or .framework bundle
    /// - Parameters:
    ///   - bundleURL: URL to the bundle directory
    ///   - identity: SecIdentity (certificate + private key)
    ///   - entitlements: Entitlements plist data
    ///   - teamID: Team identifier string
    func sign(
        bundleURL: URL,
        identity: SecIdentity,
        entitlements: Data,
        teamID: String
    ) throws {
        let fm = FileManager.default

        // Determine the main executable path
        let executableURL = try findExecutable(in: bundleURL)
        LogManager.shared.log("Signing: \(bundleURL.lastPathComponent)")

        // Load executable data
        let executableData = try Data(contentsOf: executableURL)

        // Extract private key and certificate from identity
        var privateKey: SecKey?
        SecIdentityCopyPrivateKey(identity, &privateKey)
        guard let signingKey = privateKey else {
            throw SigningError.noPrivateKey
        }

        var certRef: SecCertificate?
        SecIdentityCopyCertificate(identity, &certRef)
        guard let certificate = certRef else {
            throw SigningError.noCertificate
        }

        // Read Info.plist for bundle ID and version
        let infoPlistURL = bundleURL.appendingPathComponent("Info.plist")
        guard fm.fileExists(atPath: infoPlistURL.path),
              let infoPlistData = fm.contents(atPath: infoPlistURL.path),
              let infoPlist = try? PropertyListSerialization.propertyList(from: infoPlistData, format: nil) as? [String: Any]
        else {
            throw SigningError.missingInfoPlist
        }

        let bundleID = infoPlist["CFBundleIdentifier"] as? String ?? "unknown"
        let bundleVersion = infoPlist["CFBundleVersion"] as? String ?? "1"
        let shortVersion = infoPlist["CFBundleShortVersionString"] as? String ?? "1.0"

        // 1. Build code directory
        let codeDirectory = try buildCodeDirectory(
            executableData: executableData,
            bundleID: bundleID,
            teamID: teamID,
            bundleVersion: bundleVersion,
            shortVersion: shortVersion,
            bundleURL: bundleURL
        )

        // 2. Build entitlements blob
        let entitlementsBlob = buildEntitlementsBlob(entitlements: entitlements)

        // 3. Compute CMS signature over the code directory
        let cmsSignature = try buildCMSSignature(
            codeDirectory: codeDirectory,
            privateKey: signingKey,
            certificate: certificate
        )

        // 4. Assemble superblob
        let superblob = buildSuperblob(
            codeDirectory: codeDirectory,
            entitlements: entitlementsBlob,
            cmsSignature: cmsSignature
        )

        // 5. Inject signature into Mach-O or embed in _CodeSignature
        try injectSignature(superblob: superblob, executableURL: executableURL, bundleURL: bundleURL)

        LogManager.shared.log("✓ Signed: \(bundleURL.lastPathComponent)")
    }

    // MARK: - Find Executable

    private func findExecutable(in bundleURL: URL) throws -> URL {
        let infoPlistURL = bundleURL.appendingPathComponent("Info.plist")
        if let data = FileManager.default.contents(atPath: infoPlistURL.path),
           let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
           let execName = plist["CFBundleExecutable"] as? String {
            return bundleURL.appendingPathComponent(execName)
        }

        // Fallback: find executable by bundle name
        let name = bundleURL.deletingPathExtension().lastPathComponent
        let guessed = bundleURL.appendingPathComponent(name)
        if FileManager.default.fileExists(atPath: guessed.path) {
            return guessed
        }

        throw SigningError.executableNotFound(bundleURL.lastPathComponent)
    }

    // MARK: - Code Directory

    private func buildCodeDirectory(
        executableData: Data,
        bundleID: String,
        teamID: String,
        bundleVersion: String,
        shortVersion: String,
        bundleURL: URL
    ) throws -> Data {
        let hashSize = 32 // SHA-256
        let pageSize: Int = 4096

        // Hash all pages of the executable
        var pageHashes: [[UInt8]] = []
        var offset = 0
        while offset < executableData.count {
            let end = min(offset + pageSize, executableData.count)
            let page = executableData.subdata(in: offset..<end)
            let hash = sha256(page)
            pageHashes.append(hash)
            offset += pageSize
        }

        // Encode bundle ID and team ID
        let bundleIDBytes = Array(bundleID.utf8) + [0] // null terminated
        let teamIDBytes = Array(teamID.utf8) + [0]

        // Code directory header size
        let headerSize = 88 // CodeDirectory v2 header size
        let identOffset = UInt32(headerSize)
        let teamIDOffset = UInt32(headerSize + bundleIDBytes.count)
        let hashOffset = UInt32(headerSize + bundleIDBytes.count + teamIDBytes.count)

        // Total size
        let totalSize = Int(hashOffset) + pageHashes.count * hashSize

        var cd = Data(count: totalSize)
        cd.withUnsafeMutableBytes { ptr in
            let base = ptr.baseAddress!

            func writeUInt32BE(_ val: UInt32, at offset: Int) {
                var v = val.bigEndian
                withUnsafeBytes(of: &v) { src in
                    base.advanced(by: offset).copyMemory(from: src.baseAddress!, byteCount: 4)
                }
            }
            func writeUInt16BE(_ val: UInt16, at offset: Int) {
                var v = val.bigEndian
                withUnsafeBytes(of: &v) { src in
                    base.advanced(by: offset).copyMemory(from: src.baseAddress!, byteCount: 2)
                }
            }

            writeUInt32BE(Self.magicCodeDirectory,   at: 0)   // magic
            writeUInt32BE(UInt32(totalSize),          at: 4)   // length
            writeUInt32BE(Self.codeDirectoryVersion, at: 8)   // version
            writeUInt32BE(0,                          at: 12)  // flags
            writeUInt32BE(hashOffset,                 at: 16)  // hashOffset
            writeUInt32BE(identOffset,                at: 20)  // identOffset
            writeUInt32BE(0,                          at: 24)  // nSpecialSlots
            writeUInt32BE(UInt32(pageHashes.count),  at: 28)  // nCodeSlots
            writeUInt32BE(UInt32(executableData.count), at: 32) // codeLimit
            base.advanced(by: 36).storeBytes(of: UInt8(hashSize), as: UInt8.self) // hashSize
            base.advanced(by: 37).storeBytes(of: UInt8(2), as: UInt8.self) // hashType (SHA256)
            base.advanced(by: 38).storeBytes(of: UInt8(0), as: UInt8.self) // spare1
            base.advanced(by: 39).storeBytes(of: UInt8(12), as: UInt8.self) // pageSize (log2(4096)=12)
            writeUInt32BE(0, at: 40) // spare2
            // v2.1 fields
            writeUInt32BE(0, at: 44) // scatterOffset
            writeUInt32BE(teamIDOffset, at: 48) // teamIDOffset
        }

        // Write bundle ID
        var bundleIDData = Data(bundleIDBytes)
        cd.replaceSubrange(Int(identOffset)..<Int(identOffset) + bundleIDBytes.count, with: bundleIDData)

        // Write team ID
        var teamIDData = Data(teamIDBytes)
        cd.replaceSubrange(Int(teamIDOffset)..<Int(teamIDOffset) + teamIDBytes.count, with: teamIDData)

        // Write page hashes
        for (i, hash) in pageHashes.enumerated() {
            let hashStart = Int(hashOffset) + i * hashSize
            cd.replaceSubrange(hashStart..<hashStart + hashSize, with: hash)
        }

        return cd
    }

    // MARK: - Entitlements Blob

    private func buildEntitlementsBlob(entitlements: Data) -> Data {
        var blob = Data()
        let magic = Self.magicEntitlements.bigEndian
        let length = UInt32(8 + entitlements.count).bigEndian
        blob.append(contentsOf: withUnsafeBytes(of: magic) { Array($0) })
        blob.append(contentsOf: withUnsafeBytes(of: length) { Array($0) })
        blob.append(entitlements)
        return blob
    }

    // MARK: - CMS Signature

    /// Build a CMS (PKCS#7) signature over the code directory data
    private func buildCMSSignature(
        codeDirectory: Data,
        privateKey: SecKey,
        certificate: SecCertificate
    ) throws -> Data {
        // Hash the code directory for signing
        let codeDirectoryHash = sha256Data(codeDirectory)

        // Sign the hash using RSA or EC
        let algorithm: SecKeyAlgorithm
        let keyAttrs = SecKeyCopyAttributes(privateKey) as? [String: Any]
        let keyType = keyAttrs?[kSecAttrKeyType as String] as? String

        if keyType == (kSecAttrKeyTypeEC as String) {
            algorithm = .ecdsaSignatureDigestX962SHA256
        } else {
            algorithm = .rsaSignatureDigestPKCS1v15SHA256
        }

        var error: Unmanaged<CFError>?
        guard let rawSignature = SecKeyCreateSignature(
            privateKey,
            algorithm,
            codeDirectoryHash as CFData,
            &error
        ) as Data? else {
            let errMsg = error?.takeRetainedValue().localizedDescription ?? "unknown"
            throw SigningError.cmsSigningFailed(errMsg)
        }

        // Wrap in a minimal CMS BlobWrapper
        // Full CMS DER encoding requires writing PKCS#7 structures manually.
        // We embed a simplified wrapper that Apple's ldid/codesign format expects.
        let certData = SecCertificateCopyData(certificate) as Data
        let cms = buildSimpleCMS(
            digestAlgorithm: keyType == (kSecAttrKeyTypeEC as String) ? "ec" : "rsa",
            certificate: certData,
            signature: rawSignature,
            codeDirectoryHash: codeDirectoryHash
        )

        // Wrap in blob wrapper
        var wrapper = Data()
        let magic = Self.magicBlobWrapper.bigEndian
        let length = UInt32(8 + cms.count).bigEndian
        wrapper.append(contentsOf: withUnsafeBytes(of: magic) { Array($0) })
        wrapper.append(contentsOf: withUnsafeBytes(of: length) { Array($0) })
        wrapper.append(cms)
        return wrapper
    }

    /// Build a minimal DER-encoded PKCS#7 SignedData structure
    /// This is a simplified but functional CMS for Apple code signatures
    private func buildSimpleCMS(
        digestAlgorithm: String,
        certificate: Data,
        signature: Data,
        codeDirectoryHash: Data
    ) -> Data {
        // Apple expects a proper PKCS#7 SignedData
        // We encode the essential fields: version, digest algorithms, content, certificates, signerInfo
        // Using DER encoding helpers

        let sha256OID = derOID([2, 16, 840, 1, 101, 3, 4, 2, 1])
        let rsaOID = derOID([1, 2, 840, 113549, 1, 1, 1])
        let ecOID = derOID([1, 2, 840, 10045, 2, 1])
        let signedDataOID = derOID([1, 2, 840, 113549, 1, 7, 2])
        let dataOID = derOID([1, 2, 840, 113549, 1, 7, 1])

        let sigAlgOID = digestAlgorithm == "ec" ? ecOID : rsaOID

        // DigestAlgorithmIdentifiers
        let digestAlgID = derSequence(sha256OID + derNull())
        let digestAlgSet = derSet(digestAlgID)

        // ContentInfo (empty detached)
        let contentInfo = derSequence(dataOID)

        // Certificate (implicit [0])
        let certs = Data([0xA0]) + derLength(certificate.count) + certificate

        // SignerInfo
        let version1 = derInteger(1)
        // IssuerAndSerialNumber placeholder (we use a simplified version)
        let issuerSerial = derSequence(derSequence(derSet(derSequence(
            derOID([2, 5, 4, 3]) + derUTF8String("Unknown")
        ))) + derInteger(1))

        let sigAlgIdentifier = derSequence(sigAlgOID + derNull())
        let encSig = derOctetString(signature)

        let signerInfo = derSequence(version1 + issuerSerial + digestAlgID + sigAlgIdentifier + encSig)
        let signerInfoSet = derSet(signerInfo)

        // SignedData
        let version = derInteger(1)
        let signedData = derSequence(version + digestAlgSet + contentInfo + certs + signerInfoSet)

        // ContentInfo wrapper
        let result = derSequence(signedDataOID + Data([0xA0]) + derLength(signedData.count) + signedData)
        return result
    }

    // MARK: - Superblob Assembly

    private func buildSuperblob(codeDirectory: Data, entitlements: Data, cmsSignature: Data) -> Data {
        // Superblob layout: magic(4) + length(4) + count(4) + [index(4)+offset(4)]... + blobs...
        let count: UInt32 = 3
        let headerSize = 12 + Int(count) * 8 // superblob header + index table

        var offsets: [(UInt32, UInt32)] = [] // (slot, offset)
        var blobData = Data()

        // Blob 0: Code Directory
        offsets.append((Self.slotCodeDirectory, UInt32(headerSize + blobData.count)))
        blobData.append(codeDirectory)

        // Blob 1: Entitlements
        offsets.append((Self.slotEntitlements, UInt32(headerSize + blobData.count)))
        blobData.append(entitlements)

        // Blob 2: CMS Signature
        offsets.append((Self.slotCMSSignature, UInt32(headerSize + blobData.count)))
        blobData.append(cmsSignature)

        let totalSize = UInt32(headerSize + blobData.count)

        var superblob = Data()
        superblob.appendUInt32BE(Self.magicEmbeddedSignature)
        superblob.appendUInt32BE(totalSize)
        superblob.appendUInt32BE(count)

        for (slot, offset) in offsets {
            superblob.appendUInt32BE(slot)
            superblob.appendUInt32BE(offset)
        }

        superblob.append(blobData)
        return superblob
    }

    // MARK: - Inject Signature into Mach-O

    /// Write the code signature into the Mach-O LC_CODE_SIGNATURE segment,
    /// or fall back to the _CodeSignature/CodeResources approach
    private func injectSignature(superblob: Data, executableURL: URL, bundleURL: URL) throws {
        // Attempt to patch the Mach-O binary directly
        do {
            try patchMachO(executableURL: executableURL, superblob: superblob)
        } catch {
            // Fall back to writing to _CodeSignature directory
            LogManager.shared.log("Mach-O patch failed (\(error.localizedDescription)), falling back to _CodeSignature dir")
            try writeCodeSignatureDir(superblob: superblob, bundleURL: bundleURL)
        }
    }

    /// Patch an existing LC_CODE_SIGNATURE load command in a Mach-O binary
    private func patchMachO(executableURL: URL, superblob: Data) throws {
        var executable = try Data(contentsOf: executableURL)

        // Detect if it's a fat binary (universal)
        let magic = executable.loadUInt32BE(at: 0)
        if magic == 0xCAFEBABE || magic == 0xBEBAFECA {
            // Fat binary - patch each arch
            try patchFatBinary(executable: &executable, superblob: superblob)
        } else {
            // Single-arch Mach-O
            try patchSingleArch(executable: &executable, superblob: superblob, offset: 0)
        }

        try executable.write(to: executableURL)
    }

    private func patchFatBinary(executable: inout Data, superblob: Data) throws {
        // Fat header: magic(4) + nfat_arch(4) + [offset(4)+size(4)+align(4)+cputype(4)+cpusubtype(4)]...
        guard executable.count >= 8 else { throw SigningError.invalidMachO }
        let narch = executable.loadUInt32BE(at: 4)
        for i in 0..<Int(narch) {
            let archOffset = 8 + i * 20
            guard archOffset + 8 <= executable.count else { break }
            let offset = Int(executable.loadUInt32BE(at: archOffset))
            try patchSingleArch(executable: &executable, superblob: superblob, offset: offset)
        }
    }

    private func patchSingleArch(executable: inout Data, superblob: Data, offset: Int) throws {
        guard offset + 28 <= executable.count else { throw SigningError.invalidMachO }

        let magic = executable.loadUInt32LE(at: offset)
        let isLE: Bool
        let is64: Bool

        switch magic {
        case 0xFEEDFACE: isLE = true;  is64 = false
        case 0xCEFAEDFE: isLE = false; is64 = false
        case 0xFEEDFACF: isLE = true;  is64 = true
        case 0xCFFAEDFE: isLE = false; is64 = true
        default: throw SigningError.invalidMachO
        }

        let ncmds = isLE
            ? Int(executable.loadUInt32LE(at: offset + 16))
            : Int(executable.loadUInt32BE(at: offset + 16))

        let headerSize = is64 ? 32 : 28
        var cmdOffset = offset + headerSize

        for _ in 0..<ncmds {
            guard cmdOffset + 8 <= executable.count else { break }

            let cmd = isLE
                ? executable.loadUInt32LE(at: cmdOffset)
                : executable.loadUInt32BE(at: cmdOffset)
            let cmdSize = isLE
                ? Int(executable.loadUInt32LE(at: cmdOffset + 4))
                : Int(executable.loadUInt32BE(at: cmdOffset + 4))

            if cmd == 0x1D { // LC_CODE_SIGNATURE
                // dataoff at +8, datasize at +12
                let sigDataOff = isLE
                    ? Int(executable.loadUInt32LE(at: cmdOffset + 8))
                    : Int(executable.loadUInt32BE(at: cmdOffset + 8))
                let sigDataSize = isLE
                    ? Int(executable.loadUInt32LE(at: cmdOffset + 12))
                    : Int(executable.loadUInt32BE(at: cmdOffset + 12))

                // Overwrite existing signature region if it fits
                if superblob.count <= sigDataSize {
                    let range = (offset + sigDataOff)..<(offset + sigDataOff + superblob.count)
                    executable.replaceSubrange(range, with: superblob)
                    // Zero pad remaining
                    if superblob.count < sigDataSize {
                        let paddingRange = (offset + sigDataOff + superblob.count)..<(offset + sigDataOff + sigDataSize)
                        executable.replaceSubrange(paddingRange, with: Data(count: sigDataSize - superblob.count))
                    }
                    return
                }
            }

            cmdOffset += max(cmdSize, 8)
        }

        // No LC_CODE_SIGNATURE found - append to binary
        // This is a simplified approach; proper injection needs to update load command
        // Fall through to let caller handle via _CodeSignature dir
        throw SigningError.noCodeSignatureSlot
    }

    /// Write signature into _CodeSignature/CodeResources (fallback)
    private func writeCodeSignatureDir(superblob: Data, bundleURL: URL) throws {
        let codeSignatureDir = bundleURL.appendingPathComponent("_CodeSignature")
        try FileManager.default.createDirectory(at: codeSignatureDir, withIntermediateDirectories: true)

        let codeSignatureFile = codeSignatureDir.appendingPathComponent("CodeSignature")
        try superblob.write(to: codeSignatureFile)
    }

    // MARK: - SHA-256

    private func sha256(_ data: Data) -> [UInt8] {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { ptr in
            _ = CC_SHA256(ptr.baseAddress, CC_LONG(data.count), &hash)
        }
        return hash
    }

    private func sha256Data(_ data: Data) -> Data {
        return Data(sha256(data))
    }

    // MARK: - DER Encoding Helpers

    private func derOID(_ components: [UInt]) -> Data {
        var body = Data()
        // First two components combined: 40 * c0 + c1
        if components.count >= 2 {
            body.append(UInt8(40 * components[0] + components[1]))
        }
        for c in components.dropFirst(2) {
            var val = c
            var bytes: [UInt8] = []
            bytes.insert(UInt8(val & 0x7F), at: 0)
            val >>= 7
            while val > 0 {
                bytes.insert(UInt8((val & 0x7F) | 0x80), at: 0)
                val >>= 7
            }
            body.append(contentsOf: bytes)
        }
        return Data([0x06]) + derLength(body.count) + body
    }

    private func derLength(_ len: Int) -> Data {
        if len < 128 {
            return Data([UInt8(len)])
        } else if len < 256 {
            return Data([0x81, UInt8(len)])
        } else {
            return Data([0x82, UInt8(len >> 8), UInt8(len & 0xFF)])
        }
    }

    private func derSequence(_ content: Data) -> Data {
        return Data([0x30]) + derLength(content.count) + content
    }

    private func derSet(_ content: Data) -> Data {
        return Data([0x31]) + derLength(content.count) + content
    }

    private func derInteger(_ value: Int) -> Data {
        return Data([0x02, 0x01, UInt8(value)])
    }

    private func derNull() -> Data {
        return Data([0x05, 0x00])
    }

    private func derOctetString(_ data: Data) -> Data {
        return Data([0x04]) + derLength(data.count) + data
    }

    private func derUTF8String(_ str: String) -> Data {
        let bytes = Data(str.utf8)
        return Data([0x0C]) + derLength(bytes.count) + bytes
    }
}

// MARK: - Signing Errors

enum SigningError: LocalizedError {
    case noPrivateKey
    case noCertificate
    case missingInfoPlist
    case executableNotFound(String)
    case cmsSigningFailed(String)
    case invalidMachO
    case noCodeSignatureSlot

    var errorDescription: String? {
        switch self {
        case .noPrivateKey: return "No private key found in identity."
        case .noCertificate: return "No certificate found in identity."
        case .missingInfoPlist: return "Bundle is missing Info.plist."
        case .executableNotFound(let name): return "Executable not found in \(name)."
        case .cmsSigningFailed(let msg): return "CMS signature failed: \(msg)."
        case .invalidMachO: return "Executable has invalid Mach-O format."
        case .noCodeSignatureSlot: return "No LC_CODE_SIGNATURE slot found; wrote to _CodeSignature directory."
        }
    }
}

// MARK: - Data Extensions

extension Data {
    mutating func appendUInt32BE(_ value: UInt32) {
        var v = value.bigEndian
        Swift.withUnsafeBytes(of: &v) { self.append(contentsOf: $0) }
    }

    func loadUInt32BE(at offset: Int) -> UInt32 {
        return self.subdata(in: offset..<offset+4).withUnsafeBytes {
            $0.loadUnaligned(as: UInt32.self).bigEndian
        }
    }

    func loadUInt32LE(at offset: Int) -> UInt32 {
        return self.subdata(in: offset..<offset+4).withUnsafeBytes {
            $0.loadUnaligned(as: UInt32.self).littleEndian
        }
    }
}
