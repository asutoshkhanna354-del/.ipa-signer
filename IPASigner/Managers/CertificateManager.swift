import Foundation
import Security

// MARK: - Certificate Manager

/// Handles loading and storing P12 certificates using Security.framework
class CertificateManager {

    // MARK: - Types

    struct CertificateInfo {
        let identity: SecIdentity
        let certificate: SecCertificate
        let privateKey: SecKey
        let commonName: String
    }

    // MARK: - Load P12

    /// Load a .p12 file and extract the signing identity
    /// - Parameters:
    ///   - url: URL to the .p12 file
    ///   - password: Password protecting the .p12
    /// - Returns: CertificateInfo with extracted identity and keys
    static func loadP12(from url: URL, password: String) throws -> CertificateInfo {
        let data = try Data(contentsOf: url)
        return try loadP12(data: data, password: password)
    }

    static func loadP12(data: Data, password: String) throws -> CertificateInfo {
        let options: [String: Any] = [
            kSecImportExportPassphrase as String: password
        ]

        var importResult: CFArray?
        let status = SecPKCS12Import(data as CFData, options as CFDictionary, &importResult)

        guard status == errSecSuccess else {
            throw CertificateError.from(status: status)
        }

        guard
            let items = importResult as? [[String: Any]],
            let first = items.first
        else {
            throw CertificateError.noIdentityFound
        }

        guard let identity = first[kSecImportItemIdentity as String] as! SecIdentity? else {
            throw CertificateError.noIdentityFound
        }

        // Extract certificate
        var certRef: SecCertificate?
        let certStatus = SecIdentityCopyCertificate(identity, &certRef)
        guard certStatus == errSecSuccess, let certificate = certRef else {
            throw CertificateError.certificateExtractionFailed
        }

        // Extract private key
        var keyRef: SecKey?
        let keyStatus = SecIdentityCopyPrivateKey(identity, &keyRef)
        guard keyStatus == errSecSuccess, let privateKey = keyRef else {
            throw CertificateError.privateKeyExtractionFailed
        }

        // Get common name
        var commonNameRef: CFString?
        SecCertificateCopyCommonName(certificate, &commonNameRef)
        let commonName = (commonNameRef as String?) ?? "Unknown Certificate"

        return CertificateInfo(
            identity: identity,
            certificate: certificate,
            privateKey: privateKey,
            commonName: commonName
        )
    }

    // MARK: - Sign Data

    /// Sign arbitrary data with a private key (SHA256withRSA or SHA256withEC)
    /// - Parameters:
    ///   - data: Data to sign
    ///   - privateKey: The private key from the certificate
    /// - Returns: Signature bytes
    static func sign(data: Data, with privateKey: SecKey) throws -> Data {
        let algorithm = SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256

        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            // Try ECDSA if RSA is not supported
            return try signWithEC(data: data, privateKey: privateKey)
        }

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            algorithm,
            data as CFData,
            &error
        ) else {
            if let err = error?.takeRetainedValue() {
                throw err as Error
            }
            throw CertificateError.signingFailed("Unknown signing error")
        }

        return signature as Data
    }

    private static func signWithEC(data: Data, privateKey: SecKey) throws -> Data {
        let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            algorithm,
            data as CFData,
            &error
        ) else {
            if let err = error?.takeRetainedValue() {
                throw err as Error
            }
            throw CertificateError.signingFailed("ECDSA signing failed")
        }

        return signature as Data
    }

    // MARK: - Keychain Storage (optional)

    /// Store identity in keychain for persistence between app launches
    static func storeIdentityInKeychain(_ identity: SecIdentity, label: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecValueRef as String: identity,
            kSecAttrLabel as String: label,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked
        ]

        // Remove existing entry if any
        SecItemDelete(query as CFDictionary)

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw CertificateError.from(status: status)
        }
    }

    /// Retrieve identity from keychain
    static func retrieveIdentityFromKeychain(label: String) -> SecIdentity? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrLabel as String: label,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess else { return nil }
        return (result as! SecIdentity)
    }
}

// MARK: - Certificate Errors

enum CertificateError: LocalizedError {
    case wrongPassword
    case noIdentityFound
    case certificateExtractionFailed
    case privateKeyExtractionFailed
    case signingFailed(String)
    case keychainError(OSStatus)
    case unknown(OSStatus)

    static func from(status: OSStatus) -> CertificateError {
        switch status {
        case errSecAuthFailed, errSecPkcs12VerifyFailure:
            return .wrongPassword
        case errSecItemNotFound:
            return .noIdentityFound
        default:
            return .unknown(status)
        }
    }

    var errorDescription: String? {
        switch self {
        case .wrongPassword:
            return "Incorrect .p12 password. Please check and try again."
        case .noIdentityFound:
            return "No signing identity found in the .p12 file."
        case .certificateExtractionFailed:
            return "Failed to extract certificate from identity."
        case .privateKeyExtractionFailed:
            return "Failed to extract private key from identity."
        case .signingFailed(let msg):
            return "Code signing failed: \(msg)"
        case .keychainError(let status):
            return "Keychain error (code \(status))."
        case .unknown(let status):
            return "Security framework error (OSStatus \(status))."
        }
    }
}
