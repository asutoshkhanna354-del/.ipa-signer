import SwiftUI
import UniformTypeIdentifiers

// MARK: - Content View

struct ContentView: View {
    @EnvironmentObject var signingManager: SigningManager
    @EnvironmentObject var logManager: LogManager
    @StateObject private var otaInstaller = OTAInstaller.shared

    @State private var showingImporter = false
    @State private var importType: ImportType = .ipa
    @State private var showingError = false
    @State private var showingLogs = false
    @State private var showingShareSheet = false

    var state: SigningState { signingManager.state }

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 20) {

                    // MARK: Header
                    headerSection

                    // MARK: Import Section
                    importSection

                    // MARK: Password Field
                    if state.p12URL != nil {
                        passwordSection
                    }

                    // MARK: Status / Progress
                    if state.isProcessing {
                        progressSection
                    }

                    // MARK: Sign Button
                    signButton

                    // MARK: Install Section
                    if state.isReadyToInstall {
                        installSection
                    }

                    // MARK: Logs Toggle
                    logsSection

                    Spacer(minLength: 40)
                }
                .padding()
            }
            .navigationTitle("IPA Signer")
            .navigationBarTitleDisplayMode(.large)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: { signingManager.state.reset() }) {
                        Image(systemName: "arrow.counterclockwise")
                    }
                }
            }
            .fileImporter(
                isPresented: $showingImporter,
                allowedContentTypes: contentTypesForImport,
                allowsMultipleSelection: false
            ) { result in
                handleImport(result: result)
            }
            .alert("Error", isPresented: $showingError, presenting: state.errorMessage) { _ in
                Button("OK") {}
            } message: { msg in
                Text(msg)
            }
            .onChange(of: state.errorMessage) { _, msg in
                showingError = msg != nil
            }
        }
    }

    // MARK: - Header Section

    private var headerSection: some View {
        VStack(spacing: 6) {
            Image(systemName: "signature")
                .font(.system(size: 50))
                .foregroundColor(.blue)
            Text("IPA Signer")
                .font(.title2.bold())
            Text("Sign and install iOS apps")
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding(.top)
    }

    // MARK: - Import Section

    private var importSection: some View {
        VStack(spacing: 12) {
            SectionHeader(title: "Files", icon: "folder")

            ImportRowView(
                label: "IPA File",
                icon: "app.gift",
                filename: state.ipaName,
                isSelected: state.ipaURL != nil,
                action: { importFile(.ipa) }
            )

            ImportRowView(
                label: "Certificate (.p12)",
                icon: "person.badge.key",
                filename: state.p12Name,
                isSelected: state.p12URL != nil,
                action: { importFile(.p12) }
            )

            ImportRowView(
                label: "Provisioning Profile",
                icon: "doc.badge.gearshape",
                filename: state.provisionName,
                isSelected: state.provisionURL != nil,
                action: { importFile(.mobileprovision) }
            )
        }
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(16)
    }

    // MARK: - Password Section

    private var passwordSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeader(title: "Certificate Password", icon: "lock")

            SecureField("Enter .p12 password", text: signingManager.$state.p12Password)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .autocapitalization(.none)
                .disableAutocorrection(true)
        }
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(16)
    }

    // MARK: - Progress Section

    private var progressSection: some View {
        VStack(spacing: 10) {
            ProgressView()
                .progressViewStyle(CircularProgressViewStyle())
                .scaleEffect(1.2)
            Text(state.currentStep.rawValue)
                .font(.subheadline)
                .foregroundColor(.secondary)
        }
        .padding()
        .frame(maxWidth: .infinity)
        .background(Color(.secondarySystemBackground))
        .cornerRadius(16)
    }

    // MARK: - Sign Button

    private var signButton: some View {
        Button(action: {
            Task {
                await signingManager.signIPA()
            }
        }) {
            HStack {
                if state.isProcessing {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: .white))
                        .scaleEffect(0.8)
                } else {
                    Image(systemName: "signature")
                }
                Text(state.isProcessing ? "Signing..." : "Sign IPA")
                    .fontWeight(.semibold)
            }
            .frame(maxWidth: .infinity)
            .padding()
            .background(state.isReadyToSign && !state.isProcessing ? Color.blue : Color.gray)
            .foregroundColor(.white)
            .cornerRadius(14)
        }
        .disabled(!state.isReadyToSign || state.isProcessing)
    }

    // MARK: - Install Section

    private var installSection: some View {
        VStack(spacing: 12) {
            SectionHeader(title: "Install", icon: "arrow.down.app")

            // Status badge
            HStack {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundColor(.green)
                Text("IPA signed successfully!")
                    .font(.subheadline)
                    .foregroundColor(.green)
                Spacer()
            }

            // App info
            if !state.bundleID.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    InfoRow(label: "App", value: state.appTitle)
                    InfoRow(label: "Bundle ID", value: state.bundleID)
                    InfoRow(label: "Version", value: state.appVersion)
                }
                .padding()
                .background(Color(.tertiarySystemBackground))
                .cornerRadius(10)
            }

            // Install button
            Button(action: {
                Task {
                    await triggerInstall()
                }
            }) {
                HStack {
                    Image(systemName: "arrow.down.app.fill")
                    Text("Install via OTA")
                        .fontWeight(.semibold)
                }
                .frame(maxWidth: .infinity)
                .padding()
                .background(Color.green)
                .foregroundColor(.white)
                .cornerRadius(14)
            }

            // Share button
            Button(action: { showingShareSheet = true }) {
                HStack {
                    Image(systemName: "square.and.arrow.up")
                    Text("Share Signed IPA")
                }
                .frame(maxWidth: .infinity)
                .padding()
                .background(Color(.secondarySystemBackground))
                .foregroundColor(.blue)
                .cornerRadius(14)
                .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.blue, lineWidth: 1))
            }
            .sheet(isPresented: $showingShareSheet) {
                if let url = state.signedIPAURL {
                    ShareSheet(items: [url])
                }
            }

            // OTA note
            Text("⚠️ OTA installation requires a trusted certificate and HTTPS in production. For local testing, ensure the device trusts the signing certificate.")
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(16)
    }

    // MARK: - Logs Section

    private var logsSection: some View {
        VStack(spacing: 8) {
            Button(action: { showingLogs.toggle() }) {
                HStack {
                    SectionHeader(title: "Logs", icon: "terminal")
                    Spacer()
                    Image(systemName: showingLogs ? "chevron.up" : "chevron.down")
                        .foregroundColor(.secondary)
                }
            }
            .buttonStyle(PlainButtonStyle())

            if showingLogs {
                LogView()
                    .frame(height: 250)
            }
        }
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(16)
    }

    // MARK: - Actions

    private func importFile(_ type: ImportType) {
        importType = type
        showingImporter = true
    }

    private func handleImport(result: Result<[URL], Error>) {
        switch result {
        case .success(let urls):
            guard let url = urls.first else { return }

            // Access security-scoped resource
            _ = url.startAccessingSecurityScopedResource()

            // Copy to app's temp directory to avoid permission loss
            let destURL = FileManager.default.temporaryDirectory
                .appendingPathComponent(url.lastPathComponent)
            try? FileManager.default.removeItem(at: destURL)
            try? FileManager.default.copyItem(at: url, to: destURL)

            url.stopAccessingSecurityScopedResource()

            let capturedImportType = importType
            let capturedManager = signingManager
            Task { @MainActor in
                switch capturedImportType {
                case .ipa:
                    capturedManager.state.ipaURL = destURL
                    LogManager.shared.log("Imported IPA: \(destURL.lastPathComponent)")
                case .p12:
                    capturedManager.state.p12URL = destURL
                    LogManager.shared.log("Imported certificate: \(destURL.lastPathComponent)")
                case .mobileprovision:
                    capturedManager.state.provisionURL = destURL
                    LogManager.shared.log("Imported provisioning profile: \(destURL.lastPathComponent)")

                    // Auto-parse profile info
                    if let profile = try? ProvisioningProfile.parse(from: destURL) {
                        capturedManager.state.bundleID = profile.bundleIdentifier
                        LogManager.shared.log("Profile bundle ID: \(profile.bundleIdentifier)")
                        if profile.isExpired {
                            LogManager.shared.log("⚠️ Warning: Provisioning profile is expired!")
                        }
                    }
                }
            }

        case .failure(let error):
            LogManager.shared.log("✗ Import failed: \(error.localizedDescription)")
        }
    }

    private func triggerInstall() async {
        guard let ipaURL = state.signedIPAURL else { return }
        do {
            try await OTAInstaller.shared.install(
                ipaURL: ipaURL,
                bundleID: state.bundleID,
                version: state.appVersion,
                title: state.appTitle
            )
        } catch {
            LogManager.shared.log("✗ Install error: \(error.localizedDescription)")
            await MainActor.run {
                signingManager.state.errorMessage = error.localizedDescription
            }
        }
    }

    // MARK: - File Types

    private var contentTypesForImport: [UTType] {
        switch importType {
        case .ipa:
            return [
                UTType(filenameExtension: "ipa") ?? .data,
                .data
            ]
        case .p12:
            return [
                UTType(filenameExtension: "p12") ?? .data,
                UTType(filenameExtension: "pfx") ?? .data,
                .data
            ]
        case .mobileprovision:
            return [
                UTType(filenameExtension: "mobileprovision") ?? .data,
                .data
            ]
        }
    }
}

// MARK: - Supporting Views

struct SectionHeader: View {
    let title: String
    let icon: String

    var body: some View {
        HStack {
            Image(systemName: icon)
                .foregroundColor(.blue)
            Text(title)
                .font(.headline)
            Spacer()
        }
    }
}

struct ImportRowView: View {
    let label: String
    let icon: String
    let filename: String
    let isSelected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Image(systemName: icon)
                    .font(.title3)
                    .foregroundColor(isSelected ? .green : .blue)
                    .frame(width: 30)

                VStack(alignment: .leading, spacing: 2) {
                    Text(label)
                        .font(.subheadline.weight(.medium))
                        .foregroundColor(.primary)
                    Text(filename)
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }

                Spacer()

                Image(systemName: isSelected ? "checkmark.circle.fill" : "plus.circle")
                    .foregroundColor(isSelected ? .green : .blue)
            }
            .padding(12)
            .background(Color(.tertiarySystemBackground))
            .cornerRadius(12)
        }
        .buttonStyle(PlainButtonStyle())
    }
}

struct InfoRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack {
            Text(label)
                .font(.caption)
                .foregroundColor(.secondary)
                .frame(width: 80, alignment: .leading)
            Text(value)
                .font(.caption.weight(.medium))
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer()
        }
    }
}

// MARK: - Share Sheet

struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

