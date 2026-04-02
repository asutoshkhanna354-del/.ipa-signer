import Foundation
  import Combine

  class SigningManager: ObservableObject {
      static let shared = SigningManager()
      private init() {}

      @Published var state = SigningState()
      private let processor = IPAProcessor()
      private let signer    = CodeSigner()

      func signIPA() async {
          guard state.canSign else {
              await setError("Please select an IPA file first.")
              return
          }
          await setProcessing(true)
          LogManager.shared.log("=== THE IPA STORE Signing Started ===")

          do {
              guard let ipaURL = state.ipaURL else { throw IPAError.invalidStructure("No IPA") }

              // 1. Extract
              await setStep(.extractingIPA)
              let appURL = try processor.extract(ipaURL: ipaURL)

              // 2. Read app metadata
              if let info = try? processor.infoPlist(in: appURL) {
                  let bid = info["CFBundleIdentifier"] as? String ?? "com.unknown"
                  let ver = info["CFBundleShortVersionString"] as? String ?? "1.0"
                  let ttl = info["CFBundleDisplayName"] as? String
                      ?? info["CFBundleName"] as? String
                      ?? "App"
                  await MainActor.run {
                      state.bundleID   = bid
                      state.appVersion = ver
                      state.appTitle   = ttl
                  }
                  LogManager.shared.log("App: \(ttl) (\(bid)) v\(ver)")
              }

              // 3. Load cert & profile
              await setStep(.loadingCertificate)
              let certInfo: CertificateManager.CertificateInfo
              let entitlementsData: Data
              let teamID: String

              if state.signingMode == .vaultSign {
                  // Quick Sign: use bundled Apple Distribution cert + provisioning profile
                  certInfo = try VaultSignCertManager.loadCertificate()
                  teamID   = VaultSignCertManager.teamID
                  LogManager.shared.log("Certificate: \(certInfo.commonName)")

                  await setStep(.parsingProfile)
                  let provisionData = try VaultSignCertManager.loadProvisionData()

                  await setStep(.removingSignature)
                  try processor.prepareBundleForSigning(appURL: appURL, provisionData: provisionData)

                  // Parse profile to extract entitlements
                  let tmpProfile = FileManager.default.temporaryDirectory
                      .appendingPathComponent("vs_provision_\(UUID().uuidString).mobileprovision")
                  try provisionData.write(to: tmpProfile)
                  defer { try? FileManager.default.removeItem(at: tmpProfile) }

                  let profile = try ProvisioningProfile.parse(from: tmpProfile)
                  LogManager.shared.log("Profile: \(profile.name) [\(profile.teamIdentifier)]")
                  entitlementsData = try profile.entitlementsPlistData()

              } else {
                  // Custom Sign: user-provided cert + profile
                  guard let p12URL    = state.p12URL,
                        let provURL   = state.provisionURL else {
                      throw CertificateError.noIdentityFound
                  }
                  certInfo = try CertificateManager.loadP12(from: p12URL, password: state.p12Password)
                  teamID   = "TEAMID"
                  LogManager.shared.log("Certificate: \(certInfo.commonName)")

                  await setStep(.parsingProfile)
                  let profile = try ProvisioningProfile.parse(from: provURL)
                  LogManager.shared.log("Profile: \(profile.name)")

                  await setStep(.removingSignature)
                  try processor.prepareBundleForSigning(appURL: appURL, provisionData: profile.rawData)
                  entitlementsData = try profile.entitlementsPlistData()
              }

              // 4. Sign frameworks & bundles
              await setStep(.signingBundles)
              let bundles = try processor.allBundlesToSign(in: appURL)
              LogManager.shared.log("Bundles to sign: \(bundles.count)")
              for bundleURL in bundles.dropLast() {
                  try? signer.sign(bundleURL: bundleURL,
                                   identity: certInfo.identity,
                                   entitlements: entitlementsData,
                                   teamID: teamID)
              }

              // 5. Sign main app bundle
              await setStep(.signingApp)
              if let main = bundles.last {
                  try signer.sign(bundleURL: main,
                                  identity: certInfo.identity,
                                  entitlements: entitlementsData,
                                  teamID: teamID)
              }

              // 6. Repackage
              await setStep(.repackaging)
              let outName  = "IPAStore_\(ipaURL.lastPathComponent)"
              let signedURL = try processor.repackage(outputName: outName)

              await MainActor.run {
                  state.signedIPAURL = signedURL
                  state.currentStep  = .done
                  state.isProcessing = false
              }
              LogManager.shared.log("=== Signing Complete: \(signedURL.lastPathComponent) ===")

          } catch {
              LogManager.shared.log("✗ \(error.localizedDescription)")
              await setError(error.localizedDescription)
          }
      }

      // MARK: - Helpers
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
              state.currentStep  = .error
              state.isProcessing = false
          }
      }
  }
  