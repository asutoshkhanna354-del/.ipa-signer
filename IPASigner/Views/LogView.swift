import SwiftUI

// MARK: - Log View

struct LogView: View {
    @EnvironmentObject var logManager: LogManager
    @State private var autoScroll = true

    var body: some View {
        VStack(spacing: 0) {
            // Toolbar
            HStack {
                Text("\(logManager.logs.count) entries")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Spacer()
                Toggle("Auto-scroll", isOn: $autoScroll)
                    .font(.caption)
                    .toggleStyle(.button)
                Button(action: { logManager.clear() }) {
                    Image(systemName: "trash")
                        .font(.caption)
                }
                .foregroundColor(.red)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(Color(.tertiarySystemBackground))

            Divider()

            // Log entries
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(logManager.logs) { entry in
                            LogEntryRow(entry: entry)
                                .id(entry.id)
                        }
                    }
                    .padding(8)
                }
                .background(Color.black)
                .onChange(of: logManager.logs.count, perform: { _ in
                    if autoScroll, let lastID = logManager.logs.last?.id {
                        withAnimation {
                            proxy.scrollTo(lastID, anchor: .bottom)
                        }
                    }
                })
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }
}

// MARK: - Log Entry Row

struct LogEntryRow: View {
    let entry: LogEntry

    var textColor: Color {
        if entry.isError   { return .red }
        if entry.isSuccess { return .green }
        if entry.isWarning { return .yellow }
        return .white
    }

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Text(entry.formattedTime)
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(Color.gray)
                .fixedSize()

            Text(entry.message)
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(textColor)
                .fixedSize(horizontal: false, vertical: true)

            Spacer()
        }
    }
}
