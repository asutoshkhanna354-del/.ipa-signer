import SwiftUI
  import UIKit
  import UniformTypeIdentifiers

  // MARK: - Root
  struct ContentView: View {
      @EnvironmentObject var signingManager: SigningManager
      @EnvironmentObject var logManager: LogManager
      @State private var selectedTab = 0

      var body: some View {
          TabView(selection: $selectedTab) {
              SignView()
                  .environmentObject(signingManager)
                  .environmentObject(logManager)
                  .tabItem {
                      Label("Sign", systemImage: "signature")
                  }
                  .tag(0)

              HistoryView()
                  .environmentObject(signingManager)
                  .tabItem {
                      Label("History", systemImage: "clock.fill")
                  }
                  .tag(1)

              SettingsView()
                  .tabItem {
                      Label("Settings", systemImage: "gearshape.fill")
                  }
                  .tag(2)
          }
          .tint(Color(hex: "0A84FF"))
          .preferredColorScheme(.dark)
      }
  }

  // MARK: - Sign Tab
  struct SignView: View {
      @EnvironmentObject var signingManager: SigningManager
      @EnvironmentObject var logManager: LogManager
      @State private var showPicker = false
      @State private var pickerFor: ImportType = .ipa
      @State private var showShare = false
      @State private var showLogs = false
      @State private var showError = false

      private let blue = Color(hex: "0A84FF")
      var state: SigningState { signingManager.state }

      var body: some View {
          NavigationView {
              ZStack {
                  Color.black.ignoresSafeArea()
                  ScrollView(showsIndicators: false) {
                      VStack(spacing: 16) {
                          headerCard
                          modePicker
                          fileCards
                          if state.signingMode == .custom && state.p12URL != nil {
                              passwordCard
                          }
                          if state.isProcessing { progressCard }
                          signButton
                          if state.isReadyToInstall { resultCard }
                          if showLogs { logsCard }
                          Spacer(minLength: 30)
                      }
                      .padding(.horizontal, 16)
                      .padding(.top, 8)
                  }
              }
              .navigationBarHidden(true)
          }
          .navigationViewStyle(StackNavigationViewStyle())
          .sheet(isPresented: $showPicker) {
              DocumentPicker { url in
                  handleFile(url: url, type: pickerFor)
              }
          }
          .sheet(isPresented: $showShare) {
              if let url = state.signedIPAURL { ShareSheet(items: [url]) }
          }
          .alert("Error", isPresented: $showError, presenting: state.errorMessage) { _ in
              Button("OK") { signingManager.state.errorMessage = nil }
          } message: { Text($0) }
          .onChange(of: state.errorMessage) { showError = $0 != nil }
      }

      // MARK: Header
      private var headerCard: some View {
          HStack(spacing: 14) {
              ZStack {
                  RoundedRectangle(cornerRadius: 14)
                      .fill(blue.opacity(0.18))
                      .frame(width: 52, height: 52)
                  Image(systemName: "lock.shield.fill")
                      .font(.system(size: 26, weight: .bold))
                      .foregroundColor(blue)
              }
              VStack(alignment: .leading, spacing: 3) {
                  Text("VaultSign")
                      .font(.system(size: 26, weight: .black))
                      .foregroundColor(.white)
                  Text("iOS App Signer")
                      .font(.system(size: 12, weight: .semibold))
                      .foregroundColor(blue)
              }
              Spacer()
              Button(action: {
                  withAnimation { signingManager.state.reset() }
              }) {
                  Image(systemName: "arrow.counterclockwise")
                      .font(.system(size: 16, weight: .semibold))
                      .foregroundColor(.gray)
                      .frame(width: 36, height: 36)
                      .background(Color.white.opacity(0.08))
                      .clipShape(Circle())
              }
          }
          .padding(16)
          .background(cardBg)
          .cornerRadius(18)
      }

      // MARK: Mode Picker
      private var modePicker: some View {
          VStack(spacing: 10) {
              HStack(spacing: 0) {
                  modeBtn(title: "Quick Sign", icon: "bolt.shield.fill", mode: .vaultSign)
                  modeBtn(title: "Custom Sign", icon: "person.badge.key.fill", mode: .custom)
              }
              .background(Color.white.opacity(0.07))
              .cornerRadius(13)

              Text(state.signingMode == .vaultSign
                   ? "Uses built-in Apple Distribution certificate. Just pick your IPA and sign."
                   : "Use your own .p12 certificate and provisioning profile.")
                  .font(.system(size: 12))
                  .foregroundColor(Color.gray)
                  .multilineTextAlignment(.leading)
                  .frame(maxWidth: .infinity, alignment: .leading)
                  .padding(.horizontal, 4)
          }
      }

      private func modeBtn(title: String, icon: String, mode: SigningMode) -> some View {
          let active = state.signingMode == mode
          return Button(action: {
              withAnimation(.easeInOut(duration: 0.18)) { signingManager.state.signingMode = mode }
          }) {
              HStack(spacing: 6) {
                  Image(systemName: icon).font(.system(size: 12, weight: .bold))
                  Text(title).font(.system(size: 13, weight: .bold))
              }
              .frame(maxWidth: .infinity)
              .padding(.vertical, 11)
              .background(active ? blue : Color.clear)
              .foregroundColor(active ? .white : .gray)
              .cornerRadius(10)
              .padding(4)
          }
      }

      // MARK: File Cards
      private var fileCards: some View {
          VStack(spacing: 10) {
              sectionLabel("Files", icon: "folder.fill")
              fileRow(
                  label: "IPA File",
                  sub: state.ipaURL?.lastPathComponent ?? "Tap to select .ipa file",
                  icon: "app.gift.fill",
                  selected: state.ipaURL != nil
              ) { open(.ipa) }

              if state.signingMode == .custom {
                  fileRow(
                      label: "Certificate (.p12)",
                      sub: state.p12URL?.lastPathComponent ?? "Tap to select .p12 file",
                      icon: "person.badge.key.fill",
                      selected: state.p12URL != nil
                  ) { open(.p12) }

                  fileRow(
                      label: "Provisioning Profile",
                      sub: state.provisionURL?.lastPathComponent ?? "Tap to select .mobileprovision",
                      icon: "doc.badge.gearshape.fill",
                      selected: state.provisionURL != nil
                  ) { open(.mobileprovision) }
              }
          }
          .padding(14)
          .background(cardBg)
          .cornerRadius(18)
      }

      private func fileRow(label: String, sub: String, icon: String, selected: Bool, action: @escaping () -> Void) -> some View {
          Button(action: action) {
              HStack(spacing: 14) {
                  ZStack {
                      RoundedRectangle(cornerRadius: 10)
                          .fill(selected ? Color.green.opacity(0.15) : blue.opacity(0.12))
                          .frame(width: 42, height: 42)
                      Image(systemName: selected ? "checkmark" : icon)
                          .font(.system(size: 18, weight: .semibold))
                          .foregroundColor(selected ? .green : blue)
                  }
                  VStack(alignment: .leading, spacing: 3) {
                      Text(label)
                          .font(.system(size: 14, weight: .semibold))
                          .foregroundColor(.white)
                      Text(sub)
                          .font(.system(size: 11))
                          .foregroundColor(selected ? Color.green.opacity(0.9) : .gray)
                          .lineLimit(1)
                          .truncationMode(.middle)
                  }
                  Spacer()
                  Image(systemName: selected ? "checkmark.circle.fill" : "chevron.right")
                      .font(.system(size: 16))
                      .foregroundColor(selected ? .green : .gray)
              }
              .padding(12)
              .background(Color.white.opacity(0.05))
              .cornerRadius(12)
          }
          .buttonStyle(PlainButtonStyle())
      }

      // MARK: Password
      private var passwordCard: some View {
          VStack(spacing: 10) {
              sectionLabel("Certificate Password", icon: "lock.fill")
              HStack {
                  Image(systemName: "key.fill").foregroundColor(blue).font(.system(size: 15))
                  SecureField("Enter .p12 password", text: $signingManager.state.p12Password)
                      .foregroundColor(.white)
                      .autocapitalization(.none)
                      .disableAutocorrection(true)
              }
              .padding(14)
              .background(Color.white.opacity(0.07))
              .cornerRadius(12)
          }
          .padding(14)
          .background(cardBg)
          .cornerRadius(18)
      }

      // MARK: Progress
      private var progressCard: some View {
          HStack(spacing: 12) {
              ProgressView()
                  .progressViewStyle(CircularProgressViewStyle(tint: blue))
                  .scaleEffect(0.9)
              Text(state.currentStep.rawValue)
                  .font(.system(size: 14))
                  .foregroundColor(.gray)
              Spacer()
          }
          .padding(16)
          .background(cardBg)
          .cornerRadius(16)
      }

      // MARK: Sign Button
      private var signButton: some View {
          Button(action: { Task { await signingManager.signIPA() } }) {
              HStack(spacing: 10) {
                  if state.isProcessing {
                      ProgressView().progressViewStyle(CircularProgressViewStyle(tint: .white)).scaleEffect(0.85)
                  } else {
                      Image(systemName: "bolt.fill").font(.system(size: 16, weight: .bold))
                  }
                  Text(state.isProcessing ? "Signing…"
                       : state.signingMode == .vaultSign ? "Sign with VaultSign"
                       : "Sign IPA")
                      .font(.system(size: 17, weight: .black))
              }
              .frame(maxWidth: .infinity)
              .padding(.vertical, 17)
              .background(
                  Group {
                      if state.canSign && !state.isProcessing {
                          LinearGradient(colors: [Color(hex: "0A84FF"), Color(hex: "0055CC")],
                                         startPoint: .leading, endPoint: .trailing)
                      } else {
                          Color.white.opacity(0.1)
                      }
                  }
              )
              .foregroundColor(state.canSign && !state.isProcessing ? .white : Color.gray)
              .cornerRadius(16)
              .shadow(color: state.canSign ? Color(hex: "0A84FF").opacity(0.4) : .clear, radius: 12, y: 4)
          }
          .disabled(!state.canSign || state.isProcessing)
      }

      // MARK: Result
      private var resultCard: some View {
          VStack(spacing: 12) {
              HStack(spacing: 8) {
                  Image(systemName: "checkmark.seal.fill").foregroundColor(.green).font(.title3)
                  Text("Signed Successfully!").font(.system(size: 16, weight: .bold)).foregroundColor(.green)
                  Spacer()
              }

              if !state.bundleID.isEmpty {
                  VStack(spacing: 6) {
                      resultRow("App", value: state.appTitle)
                      resultRow("Bundle ID", value: state.bundleID)
                      resultRow("Version", value: state.appVersion)
                  }
                  .padding(12)
                  .background(Color.white.opacity(0.04))
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

              Button(action: { showShare = true }) {
                  Label("Share Signed IPA", systemImage: "square.and.arrow.up")
                      .font(.system(size: 15, weight: .semibold))
                      .frame(maxWidth: .infinity)
                      .padding(.vertical, 13)
                      .background(Color.white.opacity(0.07))
                      .foregroundColor(blue)
                      .cornerRadius(14)
                      .overlay(RoundedRectangle(cornerRadius: 14).stroke(blue.opacity(0.5), lineWidth: 1))
              }

              Button(action: { showLogs.toggle() }) {
                  HStack {
                      Image(systemName: "terminal").font(.caption).foregroundColor(.gray)
                      Text(showLogs ? "Hide Logs" : "View Logs")
                          .font(.system(size: 12)).foregroundColor(.gray)
                  }
              }
          }
          .padding(16)
          .background(cardBg)
          .cornerRadius(18)
      }

      // MARK: Logs
      private var logsCard: some View {
          LogView()
              .frame(height: 220)
              .cornerRadius(16)
      }

      // MARK: Helpers
      private var cardBg: some View { Color.white.opacity(0.06) }

      private func sectionLabel(_ title: String, icon: String) -> some View {
          HStack(spacing: 7) {
              Image(systemName: icon).foregroundColor(blue).font(.system(size: 13))
              Text(title).font(.system(size: 14, weight: .bold)).foregroundColor(.white)
              Spacer()
          }
      }

      private func resultRow(_ label: String, value: String) -> some View {
          HStack {
              Text(label).font(.system(size: 12)).foregroundColor(.gray)
              Spacer()
              Text(value).font(.system(size: 12, weight: .semibold)).foregroundColor(.white)
                  .lineLimit(1).truncationMode(.middle)
          }
      }

      private func open(_ type: ImportType) {
          pickerFor = type
          showPicker = true
      }

      private func handleFile(url: URL, type: ImportType) {
          LogManager.shared.log("Selected: \(url.lastPathComponent)")
          Task { @MainActor in
              switch type {
              case .ipa:
                  signingManager.state.ipaURL = url
                  LogManager.shared.log("📦 IPA: \(url.lastPathComponent)")
              case .p12:
                  signingManager.state.p12URL = url
                  LogManager.shared.log("🔑 Cert: \(url.lastPathComponent)")
              case .mobileprovision:
                  signingManager.state.provisionURL = url
                  LogManager.shared.log("📋 Profile: \(url.lastPathComponent)")
                  if let profile = try? ProvisioningProfile.parse(from: url) {
                      signingManager.state.bundleID = profile.bundleIdentifier
                  }
              }
          }
      }

      private func triggerInstall() async {
          guard let url = state.signedIPAURL else { return }
          do {
              try await OTAInstaller.shared.install(
                  ipaURL: url, bundleID: state.bundleID,
                  version: state.appVersion, title: state.appTitle)
          } catch {
              await MainActor.run { signingManager.state.errorMessage = error.localizedDescription }
          }
      }
  }

  // MARK: - History Tab
  struct HistoryView: View {
      @EnvironmentObject var signingManager: SigningManager
      private let blue = Color(hex: "0A84FF")

      var body: some View {
          NavigationView {
              ZStack {
                  Color.black.ignoresSafeArea()
                  VStack(spacing: 20) {
                      if let url = signingManager.state.signedIPAURL {
                          VStack(spacing: 12) {
                              HStack(spacing: 14) {
                                  ZStack {
                                      RoundedRectangle(cornerRadius: 12)
                                          .fill(blue.opacity(0.15))
                                          .frame(width: 48, height: 48)
                                      Image(systemName: "app.gift.fill")
                                          .font(.system(size: 22))
                                          .foregroundColor(blue)
                                  }
                                  VStack(alignment: .leading, spacing: 3) {
                                      Text(signingManager.state.appTitle)
                                          .font(.system(size: 15, weight: .bold)).foregroundColor(.white)
                                      Text(url.lastPathComponent)
                                          .font(.system(size: 11)).foregroundColor(.gray)
                                          .lineLimit(1).truncationMode(.middle)
                                  }
                                  Spacer()
                                  Image(systemName: "checkmark.seal.fill")
                                      .foregroundColor(.green).font(.system(size: 20))
                              }
                              .padding(14)
                              .background(Color.white.opacity(0.06))
                              .cornerRadius(16)
                          }
                          .padding(.horizontal, 16)
                      } else {
                          Spacer()
                          VStack(spacing: 12) {
                              Image(systemName: "clock.badge.xmark")
                                  .font(.system(size: 48))
                                  .foregroundColor(Color.gray.opacity(0.4))
                              Text("No signed apps yet").font(.system(size: 16, weight: .semibold)).foregroundColor(.gray)
                              Text("Sign an IPA from the Sign tab").font(.system(size: 13)).foregroundColor(Color.gray.opacity(0.7))
                          }
                          Spacer()
                      }
                  }
                  .padding(.top, 8)
              }
              .navigationTitle("History")
              .navigationBarTitleDisplayMode(.large)
          }
          .navigationViewStyle(StackNavigationViewStyle())
      }
  }

  // MARK: - Settings Tab
  struct SettingsView: View {
      private let blue = Color(hex: "0A84FF")

      var body: some View {
          NavigationView {
              ZStack {
                  Color.black.ignoresSafeArea()
                  List {
                      Section {
                          settingRow(icon: "lock.shield.fill", color: blue, title: "VaultSign", sub: "iOS IPA Signer v1.0")
                      }
                      .listRowBackground(Color.white.opacity(0.06))

                      Section(header: Text("Certificate").foregroundColor(.gray)) {
                          settingRow(icon: "person.badge.key.fill", color: .orange, title: "Quick Sign Cert", sub: "iPhone Distribution: XL AXIATA, PT TBK")
                          settingRow(icon: "calendar.badge.checkmark", color: .green, title: "Valid Until", sub: "Feb 17, 2029")
                          settingRow(icon: "building.2.fill", color: .purple, title: "Team ID", sub: "Q6SJUT5K5D")
                      }
                      .listRowBackground(Color.white.opacity(0.06))

                      Section(header: Text("About").foregroundColor(.gray)) {
                          settingRow(icon: "globe", color: blue, title: "Website", sub: "vaultsign.app")
                          settingRow(icon: "info.circle.fill", color: .gray, title: "Version", sub: "1.0 (Build 140)")
                      }
                      .listRowBackground(Color.white.opacity(0.06))
                  }
                  .scrollContentBackground(.hidden)
              }
              .navigationTitle("Settings")
              .navigationBarTitleDisplayMode(.large)
          }
          .navigationViewStyle(StackNavigationViewStyle())
      }

      private func settingRow(icon: String, color: Color, title: String, sub: String) -> some View {
          HStack(spacing: 12) {
              ZStack {
                  RoundedRectangle(cornerRadius: 8).fill(color.opacity(0.18)).frame(width: 34, height: 34)
                  Image(systemName: icon).font(.system(size: 15, weight: .semibold)).foregroundColor(color)
              }
              VStack(alignment: .leading, spacing: 2) {
                  Text(title).font(.system(size: 14, weight: .semibold)).foregroundColor(.white)
                  Text(sub).font(.system(size: 11)).foregroundColor(.gray)
              }
              Spacer()
          }
          .padding(.vertical, 4)
      }
  }

  // MARK: - Document Picker (uses asCopy: true — no security scope needed)
  struct DocumentPicker: UIViewControllerRepresentable {
      let completion: (URL) -> Void

      func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
          let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.data], asCopy: true)
          picker.allowsMultipleSelection = false
          picker.shouldShowFileExtensions = true
          picker.delegate = context.coordinator
          return picker
      }

      func makeCoordinator() -> Coordinator { Coordinator(completion: completion) }
      func updateUIViewController(_ vc: UIDocumentPickerViewController, context: Context) {}

      class Coordinator: NSObject, UIDocumentPickerDelegate {
          let completion: (URL) -> Void
          init(completion: @escaping (URL) -> Void) { self.completion = completion }

          func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
              guard let url = urls.first else { return }
              completion(url)
          }
          func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {}
      }
  }

  // MARK: - Share Sheet
  struct ShareSheet: UIViewControllerRepresentable {
      let items: [Any]
      func makeUIViewController(context: Context) -> UIActivityViewController {
          UIActivityViewController(activityItems: items, applicationActivities: nil)
      }
      func updateUIViewController(_ vc: UIActivityViewController, context: Context) {}
  }

  // MARK: - Color Extension
  extension Color {
      init(hex: String) {
          var h = hex.trimmingCharacters(in: .alphanumerics.inverted)
          if h.count == 6 { h = h }
          var val: UInt64 = 0
          Scanner(string: h).scanHexInt64(&val)
          let r = Double((val & 0xFF0000) >> 16) / 255
          let g = Double((val & 0x00FF00) >> 8) / 255
          let b = Double(val & 0x0000FF) / 255
          self.init(red: r, green: g, blue: b)
      }
  }
  