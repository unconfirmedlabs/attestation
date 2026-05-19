import SwiftUI

struct ContentView: View {
    @StateObject private var vm = AttestViewModel()

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    header
                    appInfo
                    activeKeyBox
                    actionRow
                    if let error = vm.errorMessage {
                        errorView(error)
                    }
                    if let capture = vm.lastAttestation {
                        attestationResult(capture)
                    }
                    if let capture = vm.lastAssertion {
                        assertionResult(capture)
                    }
                    Spacer(minLength: 24)
                }
                .padding()
            }
            .navigationTitle("App Attest")
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("attest-apple fixture capture")
                .font(.headline)
            Text("Drive both Apple App Attest paths — attestation (one-time hardware proof) and assertion (per-payload signature) — and write fixtures the host can pull and verify on-chain.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
    }

    private var appInfo: some View {
        VStack(alignment: .leading, spacing: 4) {
            row("Bundle ID", vm.bundleId ?? "n/a")
            row("App Attest environment", vm.isProduction ? "production" : "development")
            row("App Attest supported", vm.isSupported ? "yes" : "no — run on a real device")
        }
        .font(.callout)
        .padding(12)
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 12))
    }

    @ViewBuilder
    private var activeKeyBox: some View {
        if let active = vm.activeKey {
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text("Active SE key").font(.headline)
                    Spacer()
                    Button(role: .destructive) { vm.clearActiveKey() } label: {
                        Label("Forget", systemImage: "trash")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
                row("attested_key (X9.63 hex)", String(active.attestedKeyHex.prefix(32)) + "…")
                row("keyId (base64)", String(active.keyId.prefix(20)) + "…")
                row("app_id", active.appId)
            }
            .padding(12)
            .background(.green.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
        } else {
            Text("No active key. Tap **Attest new key** to bind one.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 12))
        }
    }

    private var actionRow: some View {
        HStack(spacing: 12) {
            Button {
                Task { await vm.attest() }
            } label: {
                if vm.isAttesting {
                    ProgressView().controlSize(.small)
                } else {
                    Label("Attest new key", systemImage: "key.viewfinder")
                        .fontWeight(.semibold)
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(!vm.isSupported || vm.isAttesting)

            Button {
                Task { await vm.assert() }
            } label: {
                if vm.isAsserting {
                    ProgressView().controlSize(.small)
                } else {
                    Label("Generate assertion", systemImage: "signature")
                        .fontWeight(.semibold)
                }
            }
            .buttonStyle(.bordered)
            .disabled(!vm.isSupported || vm.isAsserting || vm.activeKey == nil)

            Spacer()
        }
    }

    private func errorView(_ text: String) -> some View {
        Text(text)
            .font(.callout.monospaced())
            .foregroundStyle(.red)
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.red.opacity(0.1), in: RoundedRectangle(cornerRadius: 12))
    }

    private func attestationResult(_ c: AttestationCapture) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Captured attestation").font(.headline)

            field("attested_value (hex)", c.attestedPublicKey.hex)
            field("key_id (hex)", c.keyIdBytes.hex)
            field("challenge (hex)", c.challenge.hex)
            field("attestation_object (hex, truncated)",
                  "\(c.attestationObject.hex.prefix(120))…")
            field("app_id", c.appId)
            field("production", String(c.production))
            if let name = vm.savedAttestationFile {
                field("saved to sandbox", "Documents/\(name)")
            }

            Button {
                UIPasteboard.general.string = vm.attestationFixtureJSON(c)
            } label: {
                Label("Copy attestation fixture", systemImage: "doc.on.doc")
                    .fontWeight(.semibold)
            }
            .buttonStyle(.bordered)
            .padding(.top, 4)
        }
        .padding(12)
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 12))
    }

    private func assertionResult(_ c: AssertionCapture) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Captured assertion").font(.headline)

            field("assertion_object (hex, truncated)",
                  "\(c.assertionObject.hex.prefix(120))…")
            field("client_data (hex)", c.clientData.hex)
            field("attested_key (hex)", c.attestedPublicKey.hex)
            field("app_id", c.appId)
            if let name = vm.savedAssertionFile {
                field("saved to sandbox", "Documents/\(name)")
            }

            Button {
                UIPasteboard.general.string = vm.assertionFixtureJSON(c)
            } label: {
                Label("Copy assertion fixture", systemImage: "doc.on.doc")
                    .fontWeight(.semibold)
            }
            .buttonStyle(.bordered)
            .padding(.top, 4)
        }
        .padding(12)
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 12))
    }

    private func row(_ label: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label).foregroundStyle(.secondary)
            Spacer()
            Text(value).fontDesign(.monospaced).multilineTextAlignment(.trailing)
        }
    }

    private func field(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.caption.monospaced()).textSelection(.enabled)
        }
    }
}

@MainActor
final class AttestViewModel: ObservableObject {
    private let service = AttestService()

    @Published var lastAttestation: AttestationCapture?
    @Published var lastAssertion: AssertionCapture?
    @Published var savedAttestationFile: String?
    @Published var savedAssertionFile: String?
    @Published var errorMessage: String?
    @Published var isAttesting = false
    @Published var isAsserting = false

    let isProduction: Bool = false
    var isSupported: Bool { service.isSupported }
    var bundleId: String? { Bundle.main.bundleIdentifier }

    var activeKey: (keyId: String, attestedKeyHex: String, appId: String)? {
        guard let a = service.activeKey else { return nil }
        return (a.keyId, a.attestedKey.hex, a.appId)
    }

    /// `app_id = "<TEAMID>.<BUNDLE_ID>"`.
    private let teamId: String = "5354N269JS"

    func attest() async {
        guard let bundleId else { errorMessage = "No bundle identifier."; return }
        let appId = "\(teamId).\(bundleId)"

        isAttesting = true
        defer { isAttesting = false }

        var challenge = Data(count: 32)
        let s = challenge.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
        }
        guard s == errSecSuccess else {
            errorMessage = "SecRandomCopyBytes failed: \(s)"
            return
        }

        do {
            let cap = try await service.attest(challenge: challenge, appId: appId, production: isProduction)
            lastAttestation = cap
            errorMessage = nil
            savedAttestationFile = try saveAttestationFixture(cap)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func assert() async {
        isAsserting = true
        defer { isAsserting = false }

        // Sample client_data — for the demo, just a JSON blob with a fresh nonce.
        // Consumers in production would substitute their own payload (e.g., a
        // BCS-encoded ListenBatch summary).
        var nonce = Data(count: 16)
        _ = nonce.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!)
        }
        let stamp = ISO8601DateFormatter().string(from: Date())
        let json = "{\"demo\":\"AttestKitDemo\",\"timestamp\":\"\(stamp)\",\"nonce\":\"\(nonce.hex)\"}"
        let clientData = Data(json.utf8)

        do {
            let cap = try await service.assert(clientData: clientData)
            lastAssertion = cap
            errorMessage = nil
            savedAssertionFile = try saveAssertionFixture(cap)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func clearActiveKey() {
        service.clearActiveKey()
        lastAttestation = nil
        lastAssertion = nil
        savedAttestationFile = nil
        savedAssertionFile = nil
        // SwiftUI refresh: nudge a published property
        objectWillChange.send()
    }

    func attestationFixtureJSON(_ c: AttestationCapture) -> String {
        """
        {
          "attestation_object_hex": "\(c.attestationObject.hex)",
          "attested_value_hex": "\(c.attestedPublicKey.hex)",
          "key_id_hex": "\(c.keyIdBytes.hex)",
          "challenge_hex": "\(c.challenge.hex)",
          "app_id": "\(c.appId)",
          "production": \(c.production)
        }
        """
    }

    func assertionFixtureJSON(_ c: AssertionCapture) -> String {
        """
        {
          "assertion_object_hex": "\(c.assertionObject.hex)",
          "client_data_hex": "\(c.clientData.hex)",
          "attested_key_hex": "\(c.attestedPublicKey.hex)",
          "app_id": "\(c.appId)"
        }
        """
    }

    // MARK: - Sandbox persistence

    private func saveAttestationFixture(_ c: AttestationCapture) throws -> String {
        return try writeFixture(
            prefix: "attestation",
            json: attestationFixtureJSON(c),
        )
    }

    private func saveAssertionFixture(_ c: AssertionCapture) throws -> String {
        return try writeFixture(
            prefix: "assertion",
            json: assertionFixtureJSON(c),
        )
    }

    private func writeFixture(prefix: String, json: String) throws -> String {
        let docs = try FileManager.default.url(
            for: .documentDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true,
        )
        let existing = (try? FileManager.default.contentsOfDirectory(atPath: docs.path)) ?? []
        let next = existing
            .compactMap { name -> Int? in
                guard name.hasPrefix("\(prefix)_") && name.hasSuffix(".json") else { return nil }
                return Int(name.dropFirst(prefix.count + 1).dropLast(".json".count))
            }
            .max()
            .map { $0 + 1 } ?? 1
        let name = String(format: "%@_%03d.json", prefix, next)
        let url = docs.appendingPathComponent(name)
        try json.data(using: .utf8)!.write(to: url, options: .atomic)
        return name
    }
}

#Preview {
    ContentView()
}
