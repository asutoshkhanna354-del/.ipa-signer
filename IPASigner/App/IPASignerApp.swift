import SwiftUI

  @main
  struct IPA StoreApp: App {
      @StateObject private var signingManager = SigningManager.shared
      @StateObject private var logManager    = LogManager.shared

      var body: some Scene {
          WindowGroup {
              ContentView()
                  .environmentObject(signingManager)
                  .environmentObject(logManager)
                  .preferredColorScheme(.dark)
          }
      }
  }
  