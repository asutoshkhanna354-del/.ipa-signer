import SwiftUI

@main
struct IPASignerApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(SigningManager.shared)
                .environmentObject(LogManager.shared)
        }
    }
}
