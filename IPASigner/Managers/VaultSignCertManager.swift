import Foundation
  import Security

  /// Loads the bundled Apple Distribution certificate for THE IPA STORE Quick Sign mode.
  /// Certificate: iPhone Distribution: XL AXIATA, PT TBK (Team: Q6SJUT5K5D)
  /// Valid: Feb 2026 – Feb 2029
  class VaultSignCertManager {

      static let certPassword = "AppleP12.com"
      static let teamID       = "Q6SJUT5K5D"

      // MARK: - Certificate

      /// Loads the bundled .p12 and returns a CertificateInfo ready for signing.
      static func loadCertificate() throws -> CertificateManager.CertificateInfo {
          guard let url = Bundle.main.url(forResource: "VaultSignCert", withExtension: "p12"),
                let data = try? Data(contentsOf: url) else {
              throw CertificateError.noIdentityFound
          }
          return try CertificateManager.loadP12(data: data, password: certPassword)
      }

      // MARK: - Provisioning Profile

      /// Returns the raw data of the bundled provisioning profile.
      static func loadProvisionData() throws -> Data {
          guard let url = Bundle.main.url(forResource: "VaultSign", withExtension: "mobileprovision"),
                let data = try? Data(contentsOf: url) else {
              throw IPAError.invalidStructure("Bundled provisioning profile not found")
          }
          return data
      }

      // MARK: - Minimal entitlements fallback (unused when profile is present)

      static func minimalEntitlements(bundleID: String) -> Data {
          let plist = """
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
  <plist version="1.0"><dict>
  <key>application-identifier</key><string>\(teamID).\(bundleID)</string>
  <key>com.apple.developer.team-identifier</key><string>\(teamID)</string>
  <key>get-task-allow</key><false/>
  </dict></plist>
  """
          return plist.data(using: .utf8) ?? Data()
      }
  }
  