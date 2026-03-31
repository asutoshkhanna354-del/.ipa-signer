import Foundation
import UIKit

// MARK: - Signing State

/// Tracks all imported files and current signing status
class SigningState: ObservableObject {
    @Published var ipaURL: URL?
    @Published var p12URL: URL?
    @Published var provisionURL: URL?
    @Published var p12Password: String = ""
    @Published var signedIPAURL: URL?

    @Published var isProcessing: Bool = false
    @Published var currentStep: SigningStep = .idle
    @Published var errorMessage: String?

    @Published var bundleID: String = ""
    @Published var appVersion: String = "1.0"
    @Published var appTitle: String = "App"

    var ipaName: String { ipaURL?.lastPathComponent ?? "No IPA selected" }
    var p12Name: String { p12URL?.lastPathComponent ?? "No certificate selected" }
    var provisionName: String { provisionURL?.lastPathComponent ?? "No profile selected" }

    var isReadyToSign: Bool {
        ipaURL != nil && p12URL != nil && provisionURL != nil && !p12Password.isEmpty
    }

    var isReadyToInstall: Bool {
        signedIPAURL != nil
    }

    func reset() {
        ipaURL = nil
        p12URL = nil
        provisionURL = nil
        p12Password = ""
        signedIPAURL = nil
        isProcessing = false
        currentStep = .idle
        errorMessage = nil
    }
}

// MARK: - Signing Steps

enum SigningStep: String, CaseIterable {
    case idle = "Ready"
    case extractingIPA = "Extracting IPA..."
    case parsingProfile = "Parsing provisioning profile..."
    case loadingCertificate = "Loading certificate..."
    case removingSignature = "Removing old signature..."
    case replacingProfile = "Replacing provisioning profile..."
    case signingBundles = "Signing frameworks & bundles..."
    case signingApp = "Signing main app bundle..."
    case repackaging = "Repackaging IPA..."
    case done = "Signing complete"
    case error = "Error"

    var isActive: Bool { self != .idle && self != .done && self != .error }
}

// MARK: - File Import Type

enum ImportType {
    case ipa
    case p12
    case mobileprovision
}
