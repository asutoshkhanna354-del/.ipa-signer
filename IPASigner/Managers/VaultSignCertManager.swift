import Foundation
  import Security

  /// Provides the bundled VaultSign self-signed P12 certificate
  class VaultSignCertManager {

      // Self-signed cert generated for VaultSign (CN=VaultSign Signer)
      // Password: vaultsign123
      private static let bundledP12Base64 = """
  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
  """

      static func loadCertificate() throws -> CertificateManager.CertificateInfo {
          let cleaned = bundledP12Base64
              .replacingOccurrences(of: "\\n", with: "")
              .replacingOccurrences(of: "\n", with: "")
              .replacingOccurrences(of: " ", with: "")
          guard let data = Data(base64Encoded: cleaned) else {
              throw CertificateError.noIdentityFound
          }
          return try CertificateManager.loadP12(data: data, password: "vaultsign123")
      }
  }
  