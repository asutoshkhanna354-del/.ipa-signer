import Foundation
  import UIKit

  // Handles installation of a signed IPA via UIDocumentInteractionController.
  // This shows an "Open In…" menu so the user can pick their sideloader (Scarlet,
  // AltStore, TrollStore, etc.) directly — no local HTTP server or HTTPS needed.
  class OTAInstaller: NSObject, ObservableObject, UIDocumentInteractionControllerDelegate {

      static let shared = OTAInstaller()
      private override init() { super.init() }

      // Retain the controller for the duration of the presentation
      private var documentController: UIDocumentInteractionController?

      func install(
          ipaURL: URL,
          bundleID: String,
          version: String,
          title: String
      ) async throws {
          LogManager.shared.log("Preparing to open \(title).ipa in sideloader…")

          let presented = await MainActor.run { () -> Bool in
              let dc = UIDocumentInteractionController(url: ipaURL)
              dc.name = "\(title).ipa"
              dc.delegate = self
              self.documentController = dc          // keep alive during presentation

              guard
                  let scene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
                  let window = scene.windows.first,
                  let root  = window.rootViewController
              else { return false }

              // "Open In…" focuses on apps that can handle the file (sideloaders).
              // Fall back to the full options sheet if no app registers for .ipa.
              if dc.presentOpenInMenu(from: .zero, in: root.view, animated: true) {
                  LogManager.shared.log("Open In menu presented — pick your sideloader")
                  return true
              }
              if dc.presentOptionsMenu(from: .zero, in: root.view, animated: true) {
                  LogManager.shared.log("Options menu presented")
                  return true
              }
              return false
          }

          if !presented {
              throw OTAError.noAppAvailable
          }
      }
  }

  // MARK: - UIDocumentInteractionControllerDelegate

  extension OTAInstaller {
      func documentInteractionControllerDidDismissOpenInMenu(_ controller: UIDocumentInteractionController) {
          documentController = nil
      }
      func documentInteractionControllerDidDismissOptionsMenu(_ controller: UIDocumentInteractionController) {
          documentController = nil
      }
  }

  // MARK: - Errors

  enum OTAError: LocalizedError {
      case noAppAvailable

      var errorDescription: String? {
          "No app found to open this IPA. Use \"Share Signed IPA\" to send it to your sideloader via AirDrop or Files."
      }
  }
  