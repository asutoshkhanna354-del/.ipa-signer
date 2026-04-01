import Foundation
  import Combine

  class SigningManager: ObservableObject {
      static let shared = SigningManager()
      private init() {}

      @Published var state = SigningState()
      private let processor = IPAProcessor()
      private let signer = CodeSigner()

      func signIPA() async {
          guard state.canSign else {
              await setError("Please select an IPA file first.")
              return
          }
          await setProcessing(true)
          LogManager.shared.log("=== VaultSign Signing Started ===")

          do {
              guard let ipaURL = state.ipaURL else { throw IPAError.invalidStructure("No IPA") }

              // 1. Extract
              await setStep(.extractingIPA)
              let appURL = try processor.extract(ipaURL: ipaURL)

              // 2. Read app metadata
              if let info = try? processor.infoPlist(in: appURL) {
                  let bid = info["CFBundleIdentifier"] as? String ?? "com.unknown"
                  let ver = info["CFBundleShortVersionString"] as? String ?? "1.0"
                  let ttl = info["CFBundleDisplayName"] as? String ?? info["CFBundleName"] as? String ?? "App"
                  await MainActor.run {
                      state.bundleID  = bid
                      state.appVersion = ver
                      state.appTitle  = ttl
                  }
                  LogManager.shared.log("App: \(ttl) (\(bid)) v\(ver)")
              }

              // 3. Load cert (VaultSign bundled or custom)
              await setStep(.loadingCertificate)
              let certInfo: CertificateManager.CertificateInfo
              let teamID: String

              if state.signingMode == .vaultSign {
                  certInfo = try VaultSignCertManager.loadCertificate()
                  teamID = "VAULTSIGN1"
                  LogManager.shared.log("Using VaultSign built-in certificate")
              } else {
                  guard let p12URL = state.p12URL else { throw CertificateError.noIdentityFound }
                  certInfo = try CertificateManager.loadP12(from: p12URL, password: state.p12Password)
                  teamID = "TEAMID"
                  LogManager.shared.log("Certificate: \(certInfo.commonName)")
              }

              // 4. Remove old signature
              await setStep(.removingSignature)
              let entitlementsData: Data

              if state.signingMode == .custom, let provURL = state.provisionURL {
                  await setStep(.parsingProfile)
                  let profile = try ProvisioningProfile.parse(from: provURL)
                  LogManager.shared.log("Profile: \(profile.name)")
                  try processor.prepareBundleForSigning(appURL: appURL, provisionData: profile.rawData)
                  entitlementsData = try profile.entitlementsPlistData()
              } else {
                  // VaultSign mode: remove signature, use minimal entitlements
                  try processor.prepareBundleForSigning(appURL: appURL, provisionData: nil)
                  entitlementsData = minimalEntitlements(bundleID: state.bundleID.isEmpty ? "com.vaultsign.signed" : state.bundleID)
              }

              // 5. Sign bundles
              await setStep(.signingBundles)
              let bundles = try processor.allBundlesToSign(in: appURL)
              LogManager.shared.log("Bundles: \(bundles.count)")
              for bundleURL in bundles.dropLast() {
                  try? signer.sign(bundleURL: bundleURL, identity: certInfo.identity, entitlements: entitlementsData, teamID: teamID)
              }

              // 6. Sign main app
              await setStep(.signingApp)
              if let main = bundles.last {
                  try signer.sign(bundleURL: main, identity: certInfo.identity, entitlements: entitlementsData, teamID: teamID)
              }

              // 7. Repackage
              await setStep(.repackaging)
              let outName = "VaultSign_\(ipaURL.lastPathComponent)"
              let signedURL = try processor.repackage(outputName: outName)

              await MainActor.run {
                  state.signedIPAURL = signedURL
                  state.currentStep = .done
                  state.isProcessing = false
              }
              LogManager.shared.log("=== Signing Complete ===")
              LogManager.shared.log("Output: \(signedURL.lastPathComponent)")

          } catch {
              LogManager.shared.log("✗ \(error.localizedDescription)")
              await setError(error.localizedDescription)
          }
      }

      // Minimal entitlements for VaultSign mode
      private func minimalEntitlements(bundleID: String) -> Data {
          let plist = """
  <?xml version=\"1.0\" encoding=\"UTF-8\"?>
  <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
  <plist version=\"1.0\"><dict>
  <key>application-identifier</key><string>VAULTSIGN1.\(bundleID)</string>
  <key>get-task-allow</key><false/>
  </dict></plist>
  """
          return plist.data(using: .utf8) ?? Data()
      }

      private func setProcessing(_ v: Bool) async { await MainActor.run { state.isProcessing = v } }
      private func setStep(_ s: SigningStep) async {
          await MainActor.run {
              state.currentStep = s
              LogManager.shared.log("→ \(s.rawValue)")
          }
      }
      private func setError(_ msg: String) async {
          await MainActor.run {
              state.errorMessage = msg
              state.currentStep = .error
              state.isProcessing = false
          }
      }
  }
  