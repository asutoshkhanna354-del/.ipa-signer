import SwiftUI
  import UniformTypeIdentifiers
  import UIKit

  struct ContentView: View {
      @EnvironmentObject var signingManager: SigningManager
      @EnvironmentObject var logManager: LogManager

      @State private var showingImporter = false
      @State private var importType: ImportType = .ipa
      @State private var showingError = false
      @State private var showingLogs = false
      @State private var showingShareSheet = false

      private let blue = Color(red: 10/255, green: 132/255, blue: 255/255)
      var state: SigningState { signingManager.state }

      var body: some View {
          ZStack(alignment: .top) {
              Color.black.ignoresSafeArea()
              ScrollView {
                  VStack(spacing: 16) {
                      headerView
                      modePicker
                      filesSection
                      if state.signingMode == .custom && state.p12URL != nil {
                          passwordSection
                      }
                      if state.isProcessing { progressRow }
                      signBtn
                      if state.isReadyToInstall { installSection }
                      logsRow
                      Spacer(minLength: 40)
                  }
                  .padding(.horizontal, 16)
                  .padding(.top, 16)
              }
          }
          .fileImporter(
              isPresented: $showingImporter,
              allowedContentTypes: fileTypes,
              allowsMultipleSelection: false
          ) { handleImport($0) }
          .alert("Error", isPresented: $showingError, presenting: state.errorMessage) { _ in
              Button("OK") {}
          } message: { Text($0) }
          .onChange(of: state.errorMessage) { showingError = $0 != nil }
      }

      // MARK: Header
      private var headerView: some View {
          HStack(spacing: 12) {
              Image(systemName: "lock.shield.fill")
                  .font(.system(size: 30, weight: .bold))
                  .foregroundColor(blue)
              VStack(alignment: .leading, spacing: 1) {
                  Text("VaultSign")
                      .font(.system(size: 26, weight: .black))
                      .foregroundColor(.white)
                  Text("iOS App Signer")
                      .font(.system(size: 12, weight: .semibold))
                      .foregroundColor(blue)
              }
              Spacer()
              Button(action: { signingManager.state.reset() }) {
                  Image(systemName: "arrow.counterclockwise")
                      .foregroundColor(.gray)
                      .font(.system(size: 18, weight: .medium))
                      .padding(8)
                      .background(Color.white.opacity(0.07))
                      .clipShape(Circle())
              }
          }
          .padding(16)
          .background(Color.white.opacity(0.04))
          .cornerRadius(16)
      }

      // MARK: Mode Picker
      private var modePicker: some View {
          VStack(spacing: 10) {
              HStack(spacing: 0) {
                  modeTab(title: "VaultSign", icon: "lock.shield.fill", mode: .vaultSign)
                  modeTab(title: "Custom", icon: "person.badge.key.fill", mode: .custom)
              }
              .background(Color.white.opacity(0.06))
              .cornerRadius(12)

              if state.signingMode == .vaultSign {
                  HStack(spacing: 6) {
                      Image(systemName: "info.circle.fill")
                          .foregroundColor(blue)
                          .font(.system(size: 12))
                      Text("Signs with VaultSign's built-in certificate. Select your IPA and tap Sign.")
                          .font(.system(size: 12))
                          .foregroundColor(Color.gray)
                  }
                  .padding(.horizontal, 4)
                  .frame(maxWidth: .infinity, alignment: .leading)
              } else {
                  HStack(spacing: 6) {
                      Image(systemName: "info.circle.fill")
                          .foregroundColor(Color.orange)
                          .font(.system(size: 12))
                      Text("Provide your own .p12 certificate and provisioning profile.")
                          .font(.system(size: 12))
                          .foregroundColor(Color.gray)
                  }
                  .padding(.horizontal, 4)
                  .frame(maxWidth: .infinity, alignment: .leading)
              }
          }
      }

      private func modeTab(title: String, icon: String, mode: SigningMode) -> some View {
          let active = state.signingMode == mode
          return Button(action: { withAnimation(.easeInOut(duration: 0.2)) { signingManager.state.signingMode = mode } }) {
              HStack(spacing: 6) {
                  Image(systemName: icon).font(.system(size: 13, weight: .semibold))
                  Text(title).font(.system(size: 14, weight: .bold))
              }
              .frame(maxWidth: .infinity)
              .padding(.vertical, 12)
              .background(active ? blue : Color.clear)
              .foregroundColor(active ? .white : .gray)
              .cornerRadius(10)
              .padding(4)
          }
      }

      // MARK: Files
      private var filesSection: some View {
          VStack(spacing: 10) {
              sectionHeader("Files", icon: "folder.fill")
              fileRow(label: "IPA File", icon: "app.gift.fill", name: state.ipaName, selected: state.ipaURL != nil) { triggerImport(.ipa) }
              if state.signingMode == .custom {
                  fileRow(label: "Certificate (.p12)", icon: "person.badge.key.fill", name: state.p12Name, selected: state.p12URL != nil) { triggerImport(.p12) }
                  fileRow(label: "Provisioning Profile", icon: "doc.badge.gearshape.fill", name: state.provisionName, selected: state.provisionURL != nil) { triggerImport(.mobileprovision) }
              }
          }
          .padding(16)
          .background(Color.white.opacity(0.04))
          .cornerRadius(16)
      }

      private func fileRow(label: String, icon: String, name: String, selected: Bool, action: @escaping () -> Void) -> some View {
          Button(action: action) {
              HStack(spacing: 12) {
                  Image(systemName: icon)
                      .font(.system(size: 20, weight: .medium))
                      .foregroundColor(selected ? Color.green : blue)
                      .frame(width: 32)
                  VStack(alignment: .leading, spacing: 2) {
                      Text(label)
                          .font(.system(size: 14, weight: .semibold))
                          .foregroundColor(.white)
                      Text(name)
                          .font(.system(size: 12))
                          .foregroundColor(.gray)
                          .lineLimit(1)
                          .truncationMode(.middle)
                  }
                  Spacer()
                  Image(systemName: selected ? "checkmark.circle.fill" : "plus.circle.fill")
                      .foregroundColor(selected ? Color.green : blue)
                      .font(.system(size: 18))
              }
              .padding(12)
              .background(Color.white.opacity(0.06))
              .cornerRadius(12)
          }
      }

      // MARK: Password
      private var passwordSection: some View {
          VStack(spacing: 10) {
              sectionHeader("Certificate Password", icon: "lock.fill")
              SecureField("Enter .p12 password", text: $signingManager.state.p12Password)
                  .foregroundColor(.white)
                  .padding(14)
                  .background(Color.white.opacity(0.07))
                  .cornerRadius(12)
                  .autocapitalization(.none)
                  .disableAutocorrection(true)
          }
          .padding(16)
          .background(Color.white.opacity(0.04))
          .cornerRadius(16)
      }

      // MARK: Progress
      private var progressRow: some View {
          HStack(spacing: 12) {
              ProgressView().progressViewStyle(CircularProgressViewStyle(tint: blue))
              Text(state.currentStep.rawValue)
                  .font(.system(size: 14))
                  .foregroundColor(.gray)
              Spacer()
          }
          .padding(16)
          .background(Color.white.opacity(0.04))
          .cornerRadius(16)
      }

      // MARK: Sign Button
      private var signBtn: some View {
          Button(action: { Task { await signingManager.signIPA() } }) {
              HStack(spacing: 10) {
                  if state.isProcessing {
                      ProgressView().progressViewStyle(CircularProgressViewStyle(tint: .white)).scaleEffect(0.85)
                  } else {
                      Image(systemName: "signature").font(.system(size: 16, weight: .semibold))
                  }
                  Text(state.isProcessing ? "Signing…" : (state.signingMode == .vaultSign ? "Sign with VaultSign" : "Sign IPA"))
                      .font(.system(size: 17, weight: .bold))
              }
              .frame(maxWidth: .infinity)
              .padding(.vertical, 16)
              .background(state.canSign && !state.isProcessing ? blue : Color.white.opacity(0.12))
              .foregroundColor(state.canSign && !state.isProcessing ? .white : .gray)
              .cornerRadius(14)
          }
          .disabled(!state.canSign || state.isProcessing)
      }

      // MARK: Install
      private var installSection: some View {
          VStack(spacing: 12) {
              HStack {
                  Image(systemName: "checkmark.seal.fill").foregroundColor(.green)
                  Text("Signed successfully!").font(.system(size: 15, weight: .bold)).foregroundColor(.green)
                  Spacer()
              }
              if !state.bundleID.isEmpty {
                  VStack(spacing: 6) {
                      infoRow("App", value: state.appTitle)
                      infoRow("Bundle ID", value: state.bundleID)
                      infoRow("Version", value: state.appVersion)
                  }
                  .padding(12)
                  .background(Color.white.opacity(0.05))
                  .cornerRadius(12)
              }
              Button(action: { Task { await triggerInstall() } }) {
                  Label("Install via OTA", systemImage: "arrow.down.app.fill")
                      .font(.system(size: 16, weight: .bold))
                      .frame(maxWidth: .infinity)
                      .padding(.vertical, 15)
                      .background(Color.green)
                      .foregroundColor(.white)
                      .cornerRadius(14)
              }
              Button(action: { showingShareSheet = true }) {
                  Label("Share Signed IPA", systemImage: "square.and.arrow.up")
                      .font(.system(size: 15, weight: .semibold))
                      .frame(maxWidth: .infinity)
                      .padding(.vertical, 13)
                      .background(Color.white.opacity(0.08))
                      .foregroundColor(blue)
                      .cornerRadius(14)
                      .overlay(RoundedRectangle(cornerRadius: 14).stroke(blue, lineWidth: 1))
              }
              .sheet(isPresented: $showingShareSheet) {
                  if let url = state.signedIPAURL { ShareSheet(items: [url]) }
              }
          }
          .padding(16)
          .background(Color.white.opacity(0.04))
          .cornerRadius(16)
      }

      // MARK: Logs
      private var logsRow: some View {
          VStack(spacing: 0) {
              Button(action: { withAnimation { showingLogs.toggle() } }) {
                  HStack {
                      Image(systemName: "terminal.fill").foregroundColor(blue)
                      Text("Logs").font(.system(size: 15, weight: .bold)).foregroundColor(.white)
                      Spacer()
                      Image(systemName: showingLogs ? "chevron.up" : "chevron.down").foregroundColor(.gray)
                  }
                  .padding(16)
              }
              if showingLogs {
                  LogView().frame(height: 200)
              }
          }
          .background(Color.white.opacity(0.04))
          .cornerRadius(16)
      }

      // MARK: Helpers
      private func sectionHeader(_ title: String, icon: String) -> some View {
          HStack(spacing: 8) {
              Image(systemName: icon).foregroundColor(blue).font(.system(size: 14))
              Text(title).font(.system(size: 15, weight: .bold)).foregroundColor(.white)
              Spacer()
          }
      }

      private func infoRow(_ label: String, value: String) -> some View {
          HStack {
              Text(label).font(.system(size: 12)).foregroundColor(.gray)
              Spacer()
              Text(value).font(.system(size: 12, weight: .semibold)).foregroundColor(.white).lineLimit(1).truncationMode(.middle)
          }
      }

      private func triggerImport(_ type: ImportType) {
          importType = type
          showingImporter = true
      }

      private func handleImport(_ result: Result<[URL], Error>) {
          switch result {
          case .success(let urls):
              guard let url = urls.first else { return }
              let granted = url.startAccessingSecurityScopedResource()
              let dest = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + "_" + url.lastPathComponent)
              do {
                  try FileManager.default.copyItem(at: url, to: dest)
              } catch {
                  LogManager.shared.log("✗ Copy failed: \(error.localizedDescription)")
                  if granted { url.stopAccessingSecurityScopedResource() }
                  return
              }
              if granted { url.stopAccessingSecurityScopedResource() }
              let t = importType
              Task { @MainActor in
                  switch t {
                  case .ipa:
                      signingManager.state.ipaURL = dest
                      LogManager.shared.log("📦 IPA: \(dest.lastPathComponent)")
                  case .p12:
                      signingManager.state.p12URL = dest
                      LogManager.shared.log("🔑 Cert: \(dest.lastPathComponent)")
                  case .mobileprovision:
                      signingManager.state.provisionURL = dest
                      LogManager.shared.log("📋 Profile: \(dest.lastPathComponent)")
                      if let profile = try? ProvisioningProfile.parse(from: dest) {
                          signingManager.state.bundleID = profile.bundleIdentifier
                      }
                  }
              }
          case .failure(let error):
              LogManager.shared.log("✗ Import error: \(error.localizedDescription)")
          }
      }

      private func triggerInstall() async {
          guard let url = state.signedIPAURL else { return }
          do {
              try await OTAInstaller.shared.install(ipaURL: url, bundleID: state.bundleID, version: state.appVersion, title: state.appTitle)
          } catch {
              await MainActor.run { signingManager.state.errorMessage = error.localizedDescription }
          }
      }

      private var fileTypes: [UTType] {
          switch importType {
          case .ipa:            return [UTType(filenameExtension: "ipa") ?? .data, .zip, .data]
          case .p12:            return [UTType(filenameExtension: "p12") ?? .data, .data]
          case .mobileprovision: return [UTType(filenameExtension: "mobileprovision") ?? .data, .data]
          }
      }
  }

  // MARK: - ShareSheet
  struct ShareSheet: UIViewControllerRepresentable {
      let items: [Any]
      func makeUIViewController(context: Context) -> UIActivityViewController {
          UIActivityViewController(activityItems: items, applicationActivities: nil)
      }
      func updateUIViewController(_ vc: UIActivityViewController, context: Context) {}
  }
  