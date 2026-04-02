import Foundation
  import Security
  import CommonCrypto

  class CodeSigner {

      static let magicEmbeddedSignature: UInt32 = 0xFADE0CC0
      static let magicCodeDirectory:     UInt32 = 0xFADE0C02
      static let magicBlobWrapper:       UInt32 = 0xFADE0B01
      static let magicEntitlements:      UInt32 = 0xFADE7171
      static let magicRequirements:      UInt32 = 0xFADE0C01

      static let slotCodeDirectory:  UInt32 = 0
      static let slotRequirements:   UInt32 = 2
      static let slotEntitlements:   UInt32 = 5
      static let slotCMSSignature:   UInt32 = 0x10000

      static let cdVersion: UInt32 = 0x20400
      static let hashSize = 32
      static let pageShift: UInt8 = 12
      static let pageSize  = 4096

      func sign(
          bundleURL: URL,
          identity: SecIdentity,
          entitlements: Data,
          teamID: String
      ) throws {
          let fm = FileManager.default
          let execURL = try findExecutable(in: bundleURL)
          LogManager.shared.log("Signing: \(bundleURL.lastPathComponent)")

          var privKey: SecKey?
          SecIdentityCopyPrivateKey(identity, &privKey)
          guard let signingKey = privKey else { throw SigningError.noPrivateKey }

          var certRef: SecCertificate?
          SecIdentityCopyCertificate(identity, &certRef)
          guard let cert = certRef else { throw SigningError.noCertificate }

          let infoPlistURL = bundleURL.appendingPathComponent("Info.plist")
          guard let infoPlistData = fm.contents(atPath: infoPlistURL.path),
                let info = try? PropertyListSerialization.propertyList(from: infoPlistData, format: nil) as? [String: Any]
          else { throw SigningError.missingInfoPlist }

          let bundleID = info["CFBundleIdentifier"] as? String ?? "unknown"
          let execName = info["CFBundleExecutable"] as? String ?? bundleURL.deletingPathExtension().lastPathComponent

          let codeResData = try generateCodeResources(bundleURL: bundleURL, executableName: execName)
          let csDir = bundleURL.appendingPathComponent("_CodeSignature")
          try fm.createDirectory(at: csDir, withIntermediateDirectories: true)
          try codeResData.write(to: csDir.appendingPathComponent("CodeResources"))
          LogManager.shared.log("Generated CodeResources")

          var execData = try Data(contentsOf: execURL)
          stripSignature(&execData)
          let padded = (execData.count + Self.pageSize - 1) & ~(Self.pageSize - 1)
          if execData.count < padded { execData.append(Data(count: padded - execData.count)) }
          let sigOff = execData.count

          let entBlob = buildEntitlementsBlob(entitlements)
          let reqBlob = buildEmptyRequirements()

          let infoPlistHash  = sha256(infoPlistData)
          let reqHash        = sha256(reqBlob)
          let codeResHash    = sha256(codeResData)
          let entHash        = sha256(entBlob)

          let nSpecial: UInt32 = 5
          var specials = [[UInt8]](repeating: [UInt8](repeating: 0, count: Self.hashSize), count: Int(nSpecial))
          specials[4] = infoPlistHash
          specials[3] = reqHash
          specials[2] = codeResHash
          specials[0] = entHash

          addOrUpdateLCCodeSignature(&execData, dataoff: UInt32(sigOff), datasize: UInt32(65536))

          let cd = buildCodeDirectory(
              execData: execData,
              codeLimit: UInt32(sigOff),
              bundleID: bundleID,
              teamID: teamID,
              specials: specials,
              nSpecial: nSpecial
          )

          let cms = try buildCMSSignature(codeDirectory: cd, privateKey: signingKey, certificate: cert)

          let superblob = buildSuperblob(cd: cd, req: reqBlob, ent: entBlob, cms: cms)

          let finalOff = UInt32(sigOff)
          let finalSize = UInt32(superblob.count)
          addOrUpdateLCCodeSignature(&execData, dataoff: finalOff, datasize: finalSize)

          if execData.count > sigOff { execData.removeSubrange(sigOff..<execData.count) }
          execData.append(superblob)

          try execData.write(to: execURL)
          LogManager.shared.log("\u{2713} Signed: \(bundleURL.lastPathComponent)")
      }

      private func findExecutable(in b: URL) throws -> URL {
          let ip = b.appendingPathComponent("Info.plist")
          if let d = FileManager.default.contents(atPath: ip.path),
             let p = try? PropertyListSerialization.propertyList(from: d, format: nil) as? [String: Any],
             let n = p["CFBundleExecutable"] as? String {
              let u = b.appendingPathComponent(n)
              if FileManager.default.fileExists(atPath: u.path) { return u }
          }
          let n = b.deletingPathExtension().lastPathComponent
          let u = b.appendingPathComponent(n)
          if FileManager.default.fileExists(atPath: u.path) { return u }
          throw SigningError.executableNotFound(b.lastPathComponent)
      }

      func generateCodeResources(bundleURL: URL, executableName: String) throws -> Data {
          let fm = FileManager.default
          let basePath = bundleURL.path
          let enumerator = fm.enumerator(atPath: basePath)
          var files1 = [String: Any]()
          var files2 = [String: Any]()

          let excludeExact: Set<String> = [
              executableName,
              "_CodeSignature/CodeResources",
              "Info.plist"
          ]
          let excludePrefix = ["_CodeSignature/"]

          while let rel = enumerator?.nextObject() as? String {
              if excludeExact.contains(rel) { continue }
              if excludePrefix.contains(where: { rel.hasPrefix($0) }) { continue }

              let full = (basePath as NSString).appendingPathComponent(rel)
              var isDir: ObjCBool = false
              guard fm.fileExists(atPath: full, isDirectory: &isDir), !isDir.boolValue else { continue }

              let data = try Data(contentsOf: URL(fileURLWithPath: full))
              let h1 = sha1(data)
              let h2 = sha256(data)

              files1[rel] = Data(h1)

              var entry = [String: Any]()
              entry["hash"]  = Data(h1)
              entry["hash2"] = Data(h2)

              if rel.hasSuffix(".lproj/") || rel.contains(".lproj/") {
                  entry["optional"] = true
              }

              files2[rel] = entry
          }

          let infoPlistData = try Data(contentsOf: bundleURL.appendingPathComponent("Info.plist"))
          let h1i = sha1(infoPlistData)
          let h2i = sha256(infoPlistData)
          files1["Info.plist"] = Data(h1i)
          files2["Info.plist"] = ["hash": Data(h1i), "hash2": Data(h2i)] as [String: Any]

          let rules: [String: Any] = [
              "^.*": true,
              "^.*\\.lproj/": ["optional": true, "weight": 1000] as [String: Any],
              "^.*\\.lproj/locversion.plist$": ["omit": true, "weight": 1100] as [String: Any],
              "^Base\\.lproj/": ["weight": 1010] as [String: Any],
              "^version.plist$": true
          ]

          let rules2: [String: Any] = [
              "^.*": true,
              "^.*\\.lproj/": ["optional": true, "weight": 1000] as [String: Any],
              "^.*\\.lproj/locversion.plist$": ["omit": true, "weight": 1100] as [String: Any],
              "^Base\\.lproj/": ["weight": 1010] as [String: Any],
              "^Info\\.plist$": ["omit": true, "weight": 20] as [String: Any],
              "^PkgInfo$": ["omit": true, "weight": 20] as [String: Any],
              "^embedded\\.mobileprovision$": ["weight": 20] as [String: Any],
              "^version.plist$": true
          ]

          let plist: [String: Any] = [
              "files": files1,
              "files2": files2,
              "rules": rules,
              "rules2": rules2
          ]

          return try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
      }

      private func buildCodeDirectory(
          execData: Data,
          codeLimit: UInt32,
          bundleID: String,
          teamID: String,
          specials: [[UInt8]],
          nSpecial: UInt32
      ) -> Data {
          let hs = Self.hashSize
          var pageHashes = [[UInt8]]()
          var off = 0
          while off < Int(codeLimit) {
              let end = min(off + Self.pageSize, Int(codeLimit))
              let page = execData.subdata(in: off..<end)
              pageHashes.append(sha256(page))
              off += Self.pageSize
          }

          let idBytes  = Array(bundleID.utf8) + [0]
          let tidBytes = Array(teamID.utf8) + [0]

          let headerSize = 88
          let identOff   = UInt32(headerSize)
          let teamIDOff  = UInt32(headerSize + idBytes.count)
          let hashOff    = UInt32(headerSize + idBytes.count + tidBytes.count + Int(nSpecial) * hs)
          let totalSize  = Int(hashOff) + pageHashes.count * hs
          let specialStart = Int(teamIDOff) + tidBytes.count

          var cd = Data(count: totalSize)
          cd.withUnsafeMutableBytes { ptr in
              let b = ptr.baseAddress!
              func w32(_ v: UInt32, _ o: Int) { var x = v.bigEndian; Swift.withUnsafeBytes(of: &x) { b.advanced(by: o).copyMemory(from: $0.baseAddress!, byteCount: 4) } }
              w32(Self.magicCodeDirectory, 0)
              w32(UInt32(totalSize), 4)
              w32(Self.cdVersion, 8)
              w32(0, 12)
              w32(hashOff, 16)
              w32(identOff, 20)
              w32(nSpecial, 24)
              w32(UInt32(pageHashes.count), 28)
              w32(codeLimit, 32)
              b.advanced(by: 36).storeBytes(of: UInt8(hs), as: UInt8.self)
              b.advanced(by: 37).storeBytes(of: UInt8(2), as: UInt8.self)
              b.advanced(by: 38).storeBytes(of: UInt8(0), as: UInt8.self)
              b.advanced(by: 39).storeBytes(of: Self.pageShift, as: UInt8.self)
              w32(0, 40)
              w32(0, 44)
              w32(teamIDOff, 48)
          }

          cd.replaceSubrange(Int(identOff)..<Int(identOff)+idBytes.count, with: idBytes)
          cd.replaceSubrange(Int(teamIDOff)..<Int(teamIDOff)+tidBytes.count, with: tidBytes)

          for (i, h) in specials.enumerated() {
              let off = specialStart + i * hs
              cd.replaceSubrange(off..<off+hs, with: h)
          }

          for (i, h) in pageHashes.enumerated() {
              let off = Int(hashOff) + i * hs
              cd.replaceSubrange(off..<off+hs, with: h)
          }

          return cd
      }

      private func buildEntitlementsBlob(_ ent: Data) -> Data {
          var d = Data()
          d.appendU32BE(Self.magicEntitlements)
          d.appendU32BE(UInt32(8 + ent.count))
          d.append(ent)
          return d
      }

      private func buildEmptyRequirements() -> Data {
          var d = Data()
          d.appendU32BE(Self.magicRequirements)
          d.appendU32BE(12)
          d.appendU32BE(0)
          return d
      }

      private func buildCMSSignature(
          codeDirectory: Data,
          privateKey: SecKey,
          certificate: SecCertificate
      ) throws -> Data {
          let cdHash = sha256Data(codeDirectory)
          let keyAttrs = SecKeyCopyAttributes(privateKey) as? [String: Any]
          let keyType = keyAttrs?[kSecAttrKeyType as String] as? String
          let isEC = keyType == (kSecAttrKeyTypeEC as String)

          let algorithm: SecKeyAlgorithm = isEC ? .ecdsaSignatureDigestX962SHA256 : .rsaSignatureDigestPKCS1v15SHA256

          var error: Unmanaged<CFError>?
          guard let rawSig = SecKeyCreateSignature(privateKey, algorithm, cdHash as CFData, &error) as Data? else {
              throw SigningError.cmsSigningFailed(error?.takeRetainedValue().localizedDescription ?? "unknown")
          }

          let certData = SecCertificateCopyData(certificate) as Data
          let issuerData: Data
          let serialData: Data
          if let idn = SecCertificateCopyNormalizedIssuerSequence(certificate) {
              issuerData = idn as Data
          } else {
              issuerData = derSequence(derSet(derSequence(derOID([2,5,4,3]) + derUTF8String("Apple"))))
          }
          if let sn = SecCertificateCopySerialNumberData(certificate, nil) {
              serialData = sn as Data
          } else {
              serialData = Data([0x01])
          }

          let sha256OID     = derOID([2,16,840,1,101,3,4,2,1])
          let rsaOID        = derOID([1,2,840,113549,1,1,1])
          let rsaSHA256OID  = derOID([1,2,840,113549,1,1,11])
          let ecOID         = derOID([1,2,840,10045,4,3,2])
          let signedDataOID = derOID([1,2,840,113549,1,7,2])
          let dataOID       = derOID([1,2,840,113549,1,7,1])

          let digestAlgID = derSequence(sha256OID + derNull())
          let digestAlgSet = derSet(digestAlgID)
          let contentInfo = derSequence(dataOID)
          let certs = Data([0xA0]) + derLength(certData.count) + certData

          let issuerSerial = derSequence(issuerData + derRawInteger(serialData))
          let sigAlgOID = isEC ? ecOID : rsaSHA256OID
          let sigAlgIdentifier = isEC ? derSequence(sigAlgOID) : derSequence(sigAlgOID + derNull())
          let encSig = derOctetString(rawSig)

          let signerInfo = derSequence(
              derInteger(1) + issuerSerial + digestAlgID + sigAlgIdentifier + encSig
          )
          let signerInfoSet = derSet(signerInfo)
          let signedData = derSequence(derInteger(1) + digestAlgSet + contentInfo + certs + signerInfoSet)
          let result = derSequence(signedDataOID + Data([0xA0]) + derLength(signedData.count) + signedData)

          var wrapper = Data()
          wrapper.appendU32BE(Self.magicBlobWrapper)
          wrapper.appendU32BE(UInt32(8 + result.count))
          wrapper.append(result)
          return wrapper
      }

      private func buildSuperblob(cd: Data, req: Data, ent: Data, cms: Data) -> Data {
          let count: UInt32 = 4
          let headerSize = 12 + Int(count) * 8
          var blobs = Data()
          var idx = [(UInt32, UInt32)]()

          idx.append((Self.slotCodeDirectory, UInt32(headerSize + blobs.count)))
          blobs.append(cd)
          idx.append((Self.slotRequirements, UInt32(headerSize + blobs.count)))
          blobs.append(req)
          idx.append((Self.slotEntitlements, UInt32(headerSize + blobs.count)))
          blobs.append(ent)
          idx.append((Self.slotCMSSignature, UInt32(headerSize + blobs.count)))
          blobs.append(cms)

          var sb = Data()
          sb.appendU32BE(Self.magicEmbeddedSignature)
          sb.appendU32BE(UInt32(headerSize + blobs.count))
          sb.appendU32BE(count)
          for (s, o) in idx { sb.appendU32BE(s); sb.appendU32BE(o) }
          sb.append(blobs)
          return sb
      }

      private func stripSignature(_ data: inout Data) {
          guard data.count >= 4 else { return }
          let magic = data.loadU32LE(at: 0)
          let is64: Bool
          switch magic {
          case 0xFEEDFACF: is64 = true
          case 0xFEEDFACE: is64 = false
          default: return
          }
          let ncmds = Int(data.loadU32LE(at: 16))
          let hdrSize = is64 ? 32 : 28
          var off = hdrSize
          for _ in 0..<ncmds {
              guard off + 8 <= data.count else { break }
              let cmd = data.loadU32LE(at: off)
              let cmdSize = Int(data.loadU32LE(at: off + 4))
              if cmd == 29 && cmdSize >= 16 {
                  let dataoff  = Int(data.loadU32LE(at: off + 8))
                  if dataoff > 0 && dataoff < data.count {
                      data.removeSubrange(dataoff..<data.count)
                  }
                  data.writeU32LE(0, at: off + 8)
                  data.writeU32LE(0, at: off + 12)
                  return
              }
              off += cmdSize
          }
      }

      private func addOrUpdateLCCodeSignature(_ data: inout Data, dataoff: UInt32, datasize: UInt32) {
          guard data.count >= 4 else { return }
          let magic = data.loadU32LE(at: 0)
          let is64: Bool
          switch magic {
          case 0xFEEDFACF: is64 = true
          case 0xFEEDFACE: is64 = false
          default: return
          }
          let ncmds = Int(data.loadU32LE(at: 16))
          let hdrSize = is64 ? 32 : 28
          var off = hdrSize
          for _ in 0..<ncmds {
              guard off + 8 <= data.count else { break }
              let cmd = data.loadU32LE(at: off)
              let cmdSize = Int(data.loadU32LE(at: off + 4))
              if cmd == 29 && cmdSize >= 16 {
                  data.writeU32LE(dataoff, at: off + 8)
                  data.writeU32LE(datasize, at: off + 12)
                  return
              }
              off += cmdSize
          }
          let sizeofcmds = Int(data.loadU32LE(at: 20))
          let endOfCmds = hdrSize + sizeofcmds
          let firstSectionOff = findFirstSectionOffset(data, is64: is64, ncmds: ncmds)
          if endOfCmds + 16 <= (firstSectionOff ?? data.count) {
              data.writeU32LE(UInt32(ncmds + 1), at: 16)
              data.writeU32LE(UInt32(sizeofcmds + 16), at: 20)
              var lc = Data(count: 16)
              lc.writeU32LE(29, at: 0)
              lc.writeU32LE(16, at: 4)
              lc.writeU32LE(dataoff, at: 8)
              lc.writeU32LE(datasize, at: 12)
              data.replaceSubrange(endOfCmds..<endOfCmds+16, with: lc)
          }
      }

      private func findFirstSectionOffset(_ data: Data, is64: Bool, ncmds: Int) -> Int? {
          let hdrSize = is64 ? 32 : 28
          var off = hdrSize
          var minOff = data.count
          for _ in 0..<ncmds {
              guard off + 8 <= data.count else { break }
              let cmd = data.loadU32LE(at: off)
              let cmdSize = Int(data.loadU32LE(at: off + 4))
              if cmd == 0x19 || cmd == 0x1 {
                  let nsects = is64 ? Int(data.loadU32LE(at: off + 64)) : Int(data.loadU32LE(at: off + 48))
                  let sectStart = is64 ? off + 72 : off + 56
                  let sectSize  = is64 ? 80 : 68
                  for s in 0..<nsects {
                      let so = sectStart + s * sectSize
                      let fileOff = is64 ? Int(data.loadU32LE(at: so + 48)) : Int(data.loadU32LE(at: so + 40))
                      if fileOff > 0 && fileOff < minOff { minOff = fileOff }
                  }
              }
              off += cmdSize
          }
          return minOff < data.count ? minOff : nil
      }

      func sha256(_ data: Data) -> [UInt8] {
          var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
          data.withUnsafeBytes { CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash) }
          return hash
      }

      func sha256Data(_ data: Data) -> Data { Data(sha256(data)) }

      func sha1(_ data: Data) -> [UInt8] {
          var hash = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
          data.withUnsafeBytes { CC_SHA1($0.baseAddress, CC_LONG(data.count), &hash) }
          return hash
      }

      func derOID(_ components: [Int]) -> Data {
          var bytes = [UInt8]()
          guard components.count >= 2 else { return Data([0x06, 0x00]) }
          bytes.append(UInt8(components[0] * 40 + components[1]))
          for i in 2..<components.count {
              var val = components[i]
              if val < 128 { bytes.append(UInt8(val)) }
              else {
                  var enc = [UInt8]()
                  enc.append(UInt8(val & 0x7F))
                  val >>= 7
                  while val > 0 { enc.append(UInt8((val & 0x7F) | 0x80)); val >>= 7 }
                  bytes.append(contentsOf: enc.reversed())
              }
          }
          return Data([0x06]) + derLength(bytes.count) + Data(bytes)
      }

      func derLength(_ len: Int) -> Data {
          if len < 128 { return Data([UInt8(len)]) }
          var l = len; var b = [UInt8]()
          while l > 0 { b.insert(UInt8(l & 0xFF), at: 0); l >>= 8 }
          return Data([0x80 | UInt8(b.count)]) + Data(b)
      }

      func derSequence(_ content: Data) -> Data { Data([0x30]) + derLength(content.count) + content }
      func derSet(_ content: Data) -> Data { Data([0x31]) + derLength(content.count) + content }
      func derOctetString(_ content: Data) -> Data { Data([0x04]) + derLength(content.count) + content }
      func derNull() -> Data { Data([0x05, 0x00]) }
      func derUTF8String(_ s: String) -> Data {
          let b = Array(s.utf8)
          return Data([0x0C]) + derLength(b.count) + Data(b)
      }
      func derInteger(_ val: Int) -> Data {
          if val < 128 { return Data([0x02, 0x01, UInt8(val)]) }
          var v = val; var b = [UInt8]()
          while v > 0 { b.insert(UInt8(v & 0xFF), at: 0); v >>= 8 }
          if b.first! & 0x80 != 0 { b.insert(0, at: 0) }
          return Data([0x02]) + derLength(b.count) + Data(b)
      }
      func derRawInteger(_ raw: Data) -> Data {
          var bytes = Array(raw)
          if bytes.first.map({ $0 & 0x80 != 0 }) == true { bytes.insert(0, at: 0) }
          return Data([0x02]) + derLength(bytes.count) + Data(bytes)
      }
  }

  enum SigningError: LocalizedError {
      case noPrivateKey
      case noCertificate
      case missingInfoPlist
      case executableNotFound(String)
      case invalidMachO
      case cmsSigningFailed(String)
      case signatureInjectionFailed(String)

      var errorDescription: String? {
          switch self {
          case .noPrivateKey: return "No private key found in certificate."
          case .noCertificate: return "No certificate found in identity."
          case .missingInfoPlist: return "Missing Info.plist in bundle."
          case .executableNotFound(let b): return "Executable not found in \(b)."
          case .invalidMachO: return "Invalid Mach-O binary format."
          case .cmsSigningFailed(let m): return "CMS signing failed: \(m)"
          case .signatureInjectionFailed(let m): return "Signature injection failed: \(m)"
          }
      }
  }

  extension Data {
      func loadU32LE(at off: Int) -> UInt32 {
          guard off + 4 <= count else { return 0 }
          return withUnsafeBytes { $0.load(fromByteOffset: off, as: UInt32.self) }
      }
      func loadU32BE(at off: Int) -> UInt32 { loadU32LE(at: off).byteSwapped }
      mutating func writeU32LE(_ val: UInt32, at off: Int) {
          guard off + 4 <= count else { return }
          withUnsafeMutableBytes { $0.storeBytes(of: val, toByteOffset: off, as: UInt32.self) }
      }
      mutating func appendU32BE(_ val: UInt32) {
          var v = val.bigEndian
          let bytes = Swift.withUnsafeBytes(of: &v) { Array($0) }; append(contentsOf: bytes)
      }
  }
  