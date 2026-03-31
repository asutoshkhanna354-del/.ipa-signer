import Foundation
import Combine

// MARK: - Log Manager

/// Singleton for collecting log output displayed in the UI
class LogManager: ObservableObject {

    static let shared = LogManager()
    private init() {}

    @Published var logs: [LogEntry] = []
    private let queue = DispatchQueue(label: "com.ipasigner.logmanager", qos: .utility)

    func log(_ message: String) {
        let entry = LogEntry(message: message)
        queue.async { [weak self] in
            DispatchQueue.main.async {
                self?.logs.append(entry)
                // Keep last 500 entries to avoid memory bloat
                if let count = self?.logs.count, count > 500 {
                    self?.logs.removeFirst(count - 500)
                }
            }
        }
        // Also print to Xcode console
        print("[IPASigner] \(message)")
    }

    func clear() {
        DispatchQueue.main.async {
            self.logs.removeAll()
        }
    }
}

// MARK: - Log Entry

struct LogEntry: Identifiable {
    let id = UUID()
    let timestamp: Date = Date()
    let message: String

    var formattedTime: String {
        let fmt = DateFormatter()
        fmt.dateFormat = "HH:mm:ss"
        return fmt.string(from: timestamp)
    }

    var isError: Bool { message.contains("✗") || message.lowercased().contains("error") || message.lowercased().contains("failed") }
    var isSuccess: Bool { message.contains("✓") || message.contains("complete") || message.contains("Complete") }
    var isWarning: Bool { message.contains("⚠️") || message.lowercased().contains("warning") }
}
