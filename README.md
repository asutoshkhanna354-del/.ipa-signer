# IPA Signer — iOS App

A complete iOS app for signing IPA files with your own certificate and installing them via OTA.

---

## Requirements

- **Xcode 15+** on macOS
- **iOS 16+ deployment target**
- A real iOS device (OTA installation doesn't work on Simulator)
- An Apple Developer account (free or paid)
- A valid `.p12` certificate + `.mobileprovision` provisioning profile

---

## Project Setup in Xcode

### Step 1 — Create the Xcode Project

1. Open Xcode → **File → New → Project**
2. Choose **iOS → App**
3. Settings:
   - **Product Name**: `IPASigner`
   - **Interface**: `SwiftUI`
   - **Language**: `Swift`
   - **Bundle Identifier**: `com.yourname.ipasigner`
4. Click **Next** and save to any folder

---

### Step 2 — Add Swift Package Dependency

1. In Xcode, go to **File → Add Package Dependencies**
2. Enter: `https://github.com/weichsel/ZIPFoundation.git`
3. Choose **"Up to Next Major Version"** starting from `0.9.19`
4. Click **Add Package** → Select the `ZIPFoundation` library → **Add to Target**

---

### Step 3 — Add Source Files

Delete the default `ContentView.swift` that Xcode created, then add all the files from this project:

**App/**
- `App/IPASignerApp.swift`

**Models/**
- `Models/SigningState.swift`
- `Models/ProvisioningProfile.swift`

**Managers/**
- `Managers/CertificateManager.swift`
- `Managers/IPAProcessor.swift`
- `Managers/CodeSigner.swift`
- `Managers/SigningManager.swift`
- `Managers/OTAInstaller.swift`
- `Managers/LogManager.swift`

**Views/**
- `Views/ContentView.swift`
- `Views/LogView.swift`

**Server/**
- `Server/LocalHTTPServer.swift`

To add files: Right-click the IPASigner group in the navigator → **Add Files to "IPASigner"**

---

### Step 4 — Replace Info.plist

Replace the generated `Info.plist` contents with the one from `Resources/Info.plist`, or manually add these keys in the **Info** tab of your target:

| Key | Value |
|-----|-------|
| `NSLocalNetworkUsageDescription` | Used to host the signed IPA file for local OTA installation. |
| `UIFileSharingEnabled` | YES |
| `LSSupportsOpeningDocumentsInPlace` | YES |
| `NSBonjourServices` | `_ipasigner._tcp` (array) |

---

### Step 5 — Build & Run on Device

1. Plug in your iPhone/iPad
2. Select your device in the top toolbar
3. Set signing: **Target → Signing & Capabilities → Team** (your Apple ID)
4. Press **⌘R** to build and run

---

## How to Use

1. **Import IPA** — Tap the IPA row, pick your `.ipa` file from Files app
2. **Import Certificate** — Tap the certificate row, pick your `.p12` file
3. **Import Provisioning Profile** — Tap the profile row, pick your `.mobileprovision`
4. **Enter Password** — Type the `.p12` password
5. **Tap "Sign IPA"** — The app will:
   - Extract the IPA
   - Parse the provisioning profile
   - Load your certificate
   - Remove the old signature
   - Replace the embedded provisioning profile
   - Sign all frameworks and the main app bundle
   - Repackage into a signed `.ipa`
6. **Tap "Install via OTA"** — Starts a local HTTP server and opens the iOS installer

---

## OTA Installation Notes

iOS OTA installation via `itms-services://` has strict requirements:

- **For Enterprise certificates**: Works directly over HTTPS from any server
- **For Development/Ad Hoc certificates**:
  - The installing device must be listed in the provisioning profile
  - Requires HTTPS — the local HTTP server may not work without TLS
  - **Workaround**: Use the **Share** button to AirDrop/export the signed IPA, then use a tool like **AltStore** or **Sideloadly** on your Mac to install it

### Getting HTTPS for Local Server
To make OTA work with the local server, you need HTTPS. Options:
1. Use [ngrok](https://ngrok.com): `ngrok http 8080` — replace the URL in `OTAInstaller.swift`
2. Export the IPA and host it on any HTTPS server

---

## Architecture

```
IPASigner/
├── App/
│   └── IPASignerApp.swift          # @main entry point
├── Models/
│   ├── SigningState.swift           # Observable state (selected files, progress)
│   └── ProvisioningProfile.swift   # .mobileprovision CMS parser
├── Managers/
│   ├── CertificateManager.swift    # P12 → SecIdentity via Security.framework
│   ├── IPAProcessor.swift          # ZIP extract/repackage via ZIPFoundation
│   ├── CodeSigner.swift            # Mach-O code signing (superblob assembly)
│   ├── SigningManager.swift        # Pipeline orchestrator
│   ├── OTAInstaller.swift          # manifest.plist + itms-services:// trigger
│   └── LogManager.swift            # Observable log collector
├── Server/
│   └── LocalHTTPServer.swift       # Network.framework TCP server (no 3rd party)
├── Views/
│   ├── ContentView.swift           # Main SwiftUI UI
│   └── LogView.swift               # Terminal-style log display
└── Resources/
    └── Info.plist
```

---

## Frameworks Used

| Framework | Purpose |
|-----------|---------|
| `Security.framework` | P12 import, identity extraction, code signing |
| `Network.framework` | Built-in TCP HTTP server |
| `CommonCrypto` | SHA-256 page hashing for code directory |
| `ZIPFoundation` (SPM) | IPA extraction and repackaging |
| `SwiftUI` | UI |
| `Combine` | Reactive state |

---

## Known Limitations

1. **Mach-O patching**: The code signer writes signatures to `_CodeSignature/` when the existing `LC_CODE_SIGNATURE` slot is too small. Full production signers resize the binary segment — this is complex and may require a libimobiledevice-style approach for 100% compatibility.

2. **CMS/PKCS#7**: The CMS signature builder is functional but simplified. Apple's `codesign` tool produces a richer DER structure. If you encounter verification failures, the IssuerAndSerialNumber in the SignerInfo may need to match the actual certificate issuer.

3. **HTTP vs HTTPS**: iOS 14+ blocks plain HTTP for OTA by default. Use HTTPS in production via ngrok or a proper server.

4. **Fat binaries**: Universal (fat) binary support is implemented but tested only on arm64 slices.

---

## Troubleshooting

| Error | Fix |
|-------|-----|
| "Wrong password" | Check .p12 password, try empty string if none was set |
| "No .app in Payload" | IPA may be corrupt or have non-standard structure |
| Install button does nothing | Must be on a real device, not Simulator |
| OTA install fails | Check HTTPS requirement; try Share → AltStore instead |
| Build error: `unzipItem` not found | ZIPFoundation SPM package not added correctly |
| `CC_SHA256` not found | Add `import CommonCrypto` and link `libcommonCrypto` |

---

## License

For personal development and testing use only. Code signing without the app owner's authorization may violate App Store terms and applicable laws.
