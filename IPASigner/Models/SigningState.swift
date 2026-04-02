import Foundation
  import UIKit

  enum SigningMode { case vaultSign, custom }

  struct SigningState {
      var signingMode: SigningMode = .vaultSign
      var ipaURL: URL?
      var p12URL: URL?
      var provisionURL: URL?
      var p12Password: String = ""
      var signedIPAURL: URL?
      var isProcessing: Bool = false
      var currentStep: SigningStep = .idle
      var errorMessage: String?
      var bundleID: String = ""
      var appVersion: String = "1.0"
      var appTitle: String = "App"

      var ipaName: String       { ipaURL?.lastPathComponent       ?? "Tap to select IPA" }
      var p12Name: String       { p12URL?.lastPathComponent       ?? "Tap to select .p12" }
      var provisionName: String { provisionURL?.lastPathComponent ?? "Tap to select .mobileprovision" }

      var canSign: Bool {
          guard ipaURL != nil else { return false }
          if signingMode == .vaultSign { return true }
          return p12URL != nil && provisionURL != nil && !p12Password.isEmpty
      }

      var isReadyToInstall: Bool { signedIPAURL != nil }

      mutating func reset() {
          ipaURL = nil; p12URL = nil; provisionURL = nil
          p12Password = ""; signedIPAURL = nil
          isProcessing = false; currentStep = .idle; errorMessage = nil
          bundleID = ""; appVersion = "1.0"; appTitle = "App"
      }
  }

  enum SigningStep: String, CaseIterable {
      case idle               = "Ready"
      case extractingIPA      = "Extracting IPA…"
      case parsingProfile     = "Parsing profile…"
      case loadingCertificate = "Loading certificate…"
      case removingSignature  = "Removing old signature…"
      case replacingProfile   = "Replacing profile…"
      case signingBundles     = "Signing frameworks…"
      case signingApp         = "Signing app bundle…"
      case repackaging        = "Repackaging…"
      case done               = "Done ✓"
      case error              = "Error"
      var isActive: Bool { self != .idle && self != .done && self != .error }
  }

  enum ImportType { case ipa, p12, mobileprovision }
  