import SwiftUI

struct ContentView: View {
    @StateObject private var vm = AttestViewModel()
    @State private var infoSheetVisible = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                ScrollView {
                    VStack(spacing: 16) {
                        intro
                        environmentCard
                        activeKeyCard
                        if let err = vm.errorMessage { errorBanner(err) }
                        if let cap = vm.lastAttestation { attestationCard(cap) }
                        if let cap = vm.lastAssertion { assertionCard(cap) }
                        Spacer(minLength: 16)
                    }
                    .padding(.horizontal, 16)
                    .padding(.top, 4)
                    .padding(.bottom, 12)
                }
                actionStack
                    .padding(.horizontal, 16)
                    .padding(.top, 12)
                    .padding(.bottom, 8)
                    .background(.bar)
            }
            .background(Color(.systemGroupedBackground))
            .navigationTitle("App Attest")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        infoSheetVisible = true
                    } label: {
                        Image(systemName: "info.circle")
                    }
                }
            }
            .sheet(isPresented: $infoSheetVisible) { InfoSheet() }
        }
    }

    // MARK: - Sections

    private var intro: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Fixture capture")
                .font(.title3.weight(.semibold))
            Text("Drive both Apple App Attest verbs from your iPhone's Secure Enclave. Captures land in the app sandbox; the host pulls them via `xcrun devicectl`.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.top, 4)
    }

    private var environmentCard: some View {
        Card(title: "Environment", icon: "iphone.gen3", accent: .secondary) {
            VStack(spacing: 8) {
                LabeledRow("Bundle ID", vm.bundleId ?? "n/a", mono: true)
                LabeledRow("Environment", vm.isProduction ? "production" : "development")
                LabeledRow(
                    "App Attest",
                    vm.isSupported ? "supported" : "unsupported — run on a real device",
                    accent: vm.isSupported ? .green : .red,
                )
            }
        }
    }

    @ViewBuilder
    private var activeKeyCard: some View {
        if let active = vm.activeKey {
            Card(title: "Active SE key", icon: "key.fill", accent: .green) {
                VStack(spacing: 8) {
                    StatusPill(text: "Bound", systemImage: "checkmark.seal.fill", tint: .green)
                    LabeledRow("attested_key", "\(prefix(active.attestedKeyHex, 24))…\(suffix(active.attestedKeyHex, 8))", mono: true)
                    LabeledRow("key_id (base64)", "\(prefix(active.keyId, 20))…", mono: true)
                    LabeledRow("app_id", active.appId, mono: true)
                    Button(role: .destructive) { vm.clearActiveKey() } label: {
                        Label("Forget this key", systemImage: "trash")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.top, 4)
                }
            }
        } else {
            Card(title: "Active SE key", icon: "key.slash", accent: .secondary) {
                VStack(spacing: 6) {
                    StatusPill(text: "No active key", systemImage: "circle.dashed", tint: .secondary)
                    Text("Tap **Attest new key** to generate a hardware-bound P-256 key and capture its Apple attestation.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
    }

    private var actionStack: some View {
        VStack(spacing: 10) {
            Button {
                Task { await vm.attest() }
            } label: {
                ZStack {
                    if vm.isAttesting {
                        ProgressView()
                            .progressViewStyle(.circular)
                            .tint(.white)
                    } else {
                        Text("Attest New Key")
                            .fontWeight(.semibold)
                    }
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background(vm.isSupported ? Color.accentColor : Color.gray, in: RoundedRectangle(cornerRadius: 14))
                .foregroundStyle(.white)
            }
            .disabled(!vm.isSupported || vm.isAttesting)
            .buttonStyle(.plain)

            Button {
                Task { await vm.assert() }
            } label: {
                ZStack {
                    if vm.isAsserting {
                        ProgressView()
                            .progressViewStyle(.circular)
                            .tint(.white)
                    } else {
                        Text("Generate Assertion")
                            .fontWeight(.semibold)
                    }
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background(
                    (vm.isSupported && vm.activeKey != nil) ? Color.accentColor : Color.gray,
                    in: RoundedRectangle(cornerRadius: 14),
                )
                .foregroundStyle(.white)
            }
            .disabled(!vm.isSupported || vm.isAsserting || vm.activeKey == nil)
            .buttonStyle(.plain)
        }
    }

    private func errorBanner(_ text: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
                .imageScale(.large)
            VStack(alignment: .leading, spacing: 2) {
                Text("Error")
                    .font(.subheadline.weight(.semibold))
                Text(text)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(12)
        .background(.red.opacity(0.10), in: RoundedRectangle(cornerRadius: 12))
    }

    private func attestationCard(_ c: AttestationCapture) -> some View {
        ResultCard(
            title: "Attestation captured",
            subtitle: "One-time hardware proof from Apple's PKI",
            icon: "checkmark.seal.fill",
            accent: .green,
            file: vm.savedAttestationFile,
            copyAction: { UIPasteboard.general.string = vm.attestationFixtureJSON(c) },
        ) {
            VStack(spacing: 6) {
                LabeledRow("attested_value", short(c.attestedPublicKey.hex), mono: true)
                LabeledRow("key_id", short(c.keyIdBytes.hex), mono: true)
                LabeledRow("challenge", short(c.challenge.hex), mono: true)
                LabeledRow("app_id", c.appId, mono: true)
                LabeledRow("production", String(c.production))
            }
            DisclosureGroup("Raw attestationObject (\(c.attestationObject.count) bytes)") {
                Text(c.attestationObject.hex)
                    .font(.caption2.monospaced())
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .padding(.top, 6)
            }
            .font(.caption.weight(.medium))
            .padding(.top, 4)
        }
    }

    private func assertionCard(_ c: AssertionCapture) -> some View {
        ResultCard(
            title: "Assertion captured",
            subtitle: "Per-payload signature by the active SE key",
            icon: "signature",
            accent: .blue,
            file: vm.savedAssertionFile,
            copyAction: { UIPasteboard.general.string = vm.assertionFixtureJSON(c) },
        ) {
            VStack(spacing: 6) {
                LabeledRow("attested_key", short(c.attestedPublicKey.hex), mono: true)
                LabeledRow("client_data", short(c.clientData.hex), mono: true)
                LabeledRow("app_id", c.appId, mono: true)
            }
            DisclosureGroup("client_data (\(c.clientData.count) bytes)") {
                Text(String(data: c.clientData, encoding: .utf8) ?? c.clientData.hex)
                    .font(.caption2.monospaced())
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .padding(.top, 6)
            }
            .font(.caption.weight(.medium))
            DisclosureGroup("Raw assertion (\(c.assertionObject.count) bytes)") {
                Text(c.assertionObject.hex)
                    .font(.caption2.monospaced())
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .padding(.top, 6)
            }
            .font(.caption.weight(.medium))
            .padding(.top, 2)
        }
    }

    // MARK: - Helpers

    private func short(_ s: String, head: Int = 12, tail: Int = 8) -> String {
        if s.count <= head + tail + 1 { return s }
        return "\(prefix(s, head))…\(suffix(s, tail))"
    }

    private func prefix(_ s: String, _ n: Int) -> String { String(s.prefix(n)) }
    private func suffix(_ s: String, _ n: Int) -> String { String(s.suffix(n)) }
}

// MARK: - Reusable views

private struct Card<Content: View>: View {
    let title: String
    let icon: String
    let accent: Color
    @ViewBuilder var content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Image(systemName: icon)
                    .foregroundStyle(accent)
                Text(title)
                    .font(.subheadline.weight(.semibold))
                Spacer()
            }
            content()
        }
        .padding(14)
        .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 14))
    }
}

private struct ResultCard<Content: View>: View {
    let title: String
    let subtitle: String
    let icon: String
    let accent: Color
    let file: String?
    let copyAction: () -> Void
    @ViewBuilder var content: () -> Content

    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: icon)
                    .foregroundStyle(accent)
                    .imageScale(.large)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.subheadline.weight(.semibold))
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            content()
            if let file {
                Label("Saved to Documents/\(file)", systemImage: "doc.text")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Button {
                copyAction()
                copied = true
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
            } label: {
                HStack {
                    Image(systemName: copied ? "checkmark" : "doc.on.doc")
                    Text(copied ? "Copied" : "Copy fixture JSON")
                        .fontWeight(.medium)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 10)
                .background(.tertiary.opacity(0.4), in: RoundedRectangle(cornerRadius: 10))
            }
            .buttonStyle(.plain)
        }
        .padding(14)
        .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 14))
    }
}

private struct LabeledRow: View {
    let label: String
    let value: String
    var mono: Bool = false
    var accent: Color? = nil

    init(_ label: String, _ value: String, mono: Bool = false, accent: Color? = nil) {
        self.label = label
        self.value = value
        self.mono = mono
        self.accent = accent
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .font(mono ? .caption.monospaced() : .caption)
                .foregroundStyle(accent ?? .primary)
                .multilineTextAlignment(.trailing)
                .lineLimit(1)
        }
    }
}

private struct StatusPill: View {
    let text: String
    let systemImage: String
    let tint: Color

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: systemImage)
            Text(text).fontWeight(.medium)
        }
        .font(.caption)
        .padding(.horizontal, 10)
        .padding(.vertical, 4)
        .foregroundStyle(tint)
        .background(tint.opacity(0.12), in: Capsule())
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct InfoSheet: View {
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    section(
                        title: "What is App Attest?",
                        body: "Apple's API for proving that a public key was generated inside the Secure Enclave on a real iOS device running your specific app.",
                    )
                    section(
                        title: "Attestation",
                        body: "One-time, per app install. Apple's PKI signs a chain that bottoms out at the Apple App Attestation Root CA. Use the captured fixture with `attest_apple::attestation::verify` on Sui.",
                    )
                    section(
                        title: "Assertion",
                        body: "Per-action. Once a key is attested, you can use `generateAssertion` repeatedly to sign arbitrary payloads. Use the captured fixture with `attest_apple::assertion::verify` on Sui.",
                    )
                    section(
                        title: "Why this demo exists",
                        body: "It's the cleanest way to capture real-device fixtures for the verifier crates. Every button generates real, on-chain-verifiable bytes — no mocks, no fakes.",
                    )
                }
                .padding(20)
            }
            .navigationTitle("About")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    private func section(title: String, body: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.headline)
            Text(body)
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
    }
}

// MARK: - View Model

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
            lastAssertion = nil
            savedAssertionFile = nil
            errorMessage = nil
            savedAttestationFile = try saveAttestationFixture(cap)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func assert() async {
        isAsserting = true
        defer { isAsserting = false }

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
        try writeFixture(prefix: "attestation", json: attestationFixtureJSON(c))
    }

    private func saveAssertionFixture(_ c: AssertionCapture) throws -> String {
        try writeFixture(prefix: "assertion", json: assertionFixtureJSON(c))
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
