import Foundation
import Combine

// MARK: - Signing Manager

/// Orchestrates the full IPA signing pipeline
class SigningManager: ObservableObject {

    static let shared = SigningManager()
    private init() {}

    @Published var state = SigningState()

    private let processor = IPAProcessor()
    private let signer = CodeSigner()

    // MARK: - Sign IPA

    /// Full signing pipeline:
    /// 1. Extract IPA
    /// 2. Parse provisioning profile
    /// 3. Load certificate
    /// 4. Remove old signature + replace profile
    /// 5. Sign all nested bundles
    /// 6. Sign main .app bundle
    /// 7. Repackage IPA
    func signIPA() async {
        guard state.isReadyToSign else {
            await setError("Please import an IPA, certificate, and provisioning profile first.")
            return
        }

        await setProcessing(true)
        await setStep(.extractingIPA)
        LogManager.shared.log("=== IPA Signing Started ===")

        do {
            // 1. Extract IPA
            guard let ipaURL = state.ipaURL else { throw IPAError.invalidStructure("No IPA URL") }
            let appURL = try processor.extract(ipaURL: ipaURL)

            // 2. Parse provisioning profile
            await setStep(.parsingProfile)
            guard let provisionURL = state.provisionURL else {
                throw ProvisioningError.invalidFormat("No provision URL")
            }
            let profile = try ProvisioningProfile.parse(from: provisionURL)
            LogManager.shared.log("Profile: \(profile.name)")
            LogManager.shared.log("Bundle ID: \(profile.bundleIdentifier)")
            LogManager.shared.log("Team ID: \(profile.teamIdentifier)")

            if profile.isExpired {
                LogManager.shared.log("⚠️ Warning: Provisioning profile is expired!")
            }

            // 3. Load certificate
            await setStep(.loadingCertificate)
            guard let p12URL = state.p12URL else {
                throw CertificateError.noIdentityFound
            }
            let certInfo = try CertificateManager.loadP12(from: p12URL, password: state.p12Password)
            LogManager.shared.log("Certificate: \(certInfo.commonName)")

            // 4. Prepare bundle (remove old signature, replace profile)
            await setStep(.removingSignature)
            try processor.prepareBundleForSigning(
                appURL: appURL,
                provisionData: profile.rawData
            )

            // Update Info.plist bundle ID if needed
            // (You can optionally force-match the profile's bundle ID here)
            // try processor.updateBundleID(profile.bundleIdentifier, in: appURL)

            // Read app metadata for OTA manifest
            if let infoPlist = try? processor.infoPlist(in: appURL) {
                let bundleID = infoPlist["CFBundleIdentifier"] as? String ?? profile.bundleIdentifier
                let version = infoPlist["CFBundleShortVersionString"] as? String ?? "1.0"
                let title = infoPlist["CFBundleDisplayName"] as? String
                    ?? infoPlist["CFBundleName"] as? String
                    ?? "App"

                await MainActor.run {
                    state.bundleID = bundleID
                    state.appVersion = version
                    state.appTitle = title
                }

                LogManager.shared.log("App: \(title) (\(bundleID)) v\(version)")
            }

            // Entitlements data
            let entitlementsData = try profile.entitlementsPlistData()

            // 5. Sign nested bundles (frameworks, plugins)
            await setStep(.signingBundles)
            let bundles = try processor.allBundlesToSign(in: appURL)
            LogManager.shared.log("Bundles to sign: \(bundles.count)")

            for bundleURL in bundles.dropLast() { // all except main .app
                do {
                    try signer.sign(
                        bundleURL: bundleURL,
                        identity: certInfo.identity,
                        entitlements: entitlementsData,
                        teamID: profile.teamIdentifier
                    )
                } catch {
                    // Non-fatal: log and continue for nested bundles
                    LogManager.shared.log("⚠️ Warning signing \(bundleURL.lastPathComponent): \(error.localizedDescription)")
                }
            }

            // 6. Sign the main .app bundle
            await setStep(.signingApp)
            if let mainApp = bundles.last {
                try signer.sign(
                    bundleURL: mainApp,
                    identity: certInfo.identity,
                    entitlements: entitlementsData,
                    teamID: profile.teamIdentifier
                )
            }

            // 7. Repackage IPA
            await setStep(.repackaging)
            let outputName = "signed_\(ipaURL.lastPathComponent)"
            let signedIPAURL = try processor.repackage(outputName: outputName)

            await MainActor.run {
                state.signedIPAURL = signedIPAURL
                state.currentStep = .done
                state.isProcessing = false
            }

            LogManager.shared.log("=== Signing Complete ===")
            LogManager.shared.log("Output: \(signedIPAURL.path)")

        } catch {
            LogManager.shared.log("✗ Error: \(error.localizedDescription)")
            await setError(error.localizedDescription)
        }
    }

    // MARK: - Helpers

    private func setProcessing(_ value: Bool) async {
        await MainActor.run { state.isProcessing = value }
    }

    private func setStep(_ step: SigningStep) async {
        await MainActor.run {
            state.currentStep = step
            LogManager.shared.log("Step: \(step.rawValue)")
        }
    }

    private func setError(_ message: String) async {
        await MainActor.run {
            state.errorMessage = message
            state.currentStep = .error
            state.isProcessing = false
        }
    }
}
