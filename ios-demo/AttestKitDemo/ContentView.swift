import SwiftUI

struct ContentView: View {
    @StateObject private var vm = AttestViewModel()

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    header
                    appInfo
                    actionRow
                    if let error = vm.errorMessage {
                        errorView(error)
                    }
                    if let capture = vm.lastCapture {
                        resultView(capture)
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
            Text("Generate a Secure Enclave key, attest it against a fresh challenge, and copy the result as a Rust test fixture.")
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

    private var actionRow: some View {
        HStack {
            Button {
                Task { await vm.attest() }
            } label: {
                if vm.isWorking {
                    ProgressView().controlSize(.small)
                } else {
                    Label("Attest new key", systemImage: "key.viewfinder")
                        .fontWeight(.semibold)
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(!vm.isSupported || vm.isWorking)

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

    private func resultView(_ capture: AttestationCapture) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Captured attestation").font(.headline)

            field("key_id (hex)", capture.keyIdBytes.hex)
            field("challenge (hex)", capture.challenge.hex)
            field("attestation_object (hex, truncated)",
                  "\(capture.attestationObject.hex.prefix(120))…")
            field("app_id", capture.appId)
            field("production", String(capture.production))

            Button {
                UIPasteboard.general.string = vm.fixtureJSON(capture)
            } label: {
                Label("Copy as Rust fixture JSON", systemImage: "doc.on.doc")
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
    private let attest = AttestService()

    @Published var lastCapture: AttestationCapture?
    @Published var errorMessage: String?
    @Published var isWorking = false

    /// Toggle this when the app is signed for production App Attest (TestFlight
    /// or App Store) instead of the development sandbox. Default false.
    let isProduction: Bool = false

    var isSupported: Bool { attest.isSupported }

    var bundleId: String? { Bundle.main.bundleIdentifier }

    /// `app_id = "<TEAMID>.<BUNDLE_ID>"`. The team id is hardcoded here for
    /// dev convenience — update it (or read from a build setting) before
    /// running on a fresh signing identity.
    private let teamId: String = "5354N269JS"

    func attest() async {
        guard let bundleId else {
            errorMessage = "No bundle identifier."
            return
        }
        let appId = "\(teamId).\(bundleId)"

        isWorking = true
        defer { isWorking = false }

        // Fresh 32-byte challenge.
        var challenge = Data(count: 32)
        let result = challenge.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, 32, ptr.baseAddress!)
        }
        guard result == errSecSuccess else {
            errorMessage = "SecRandomCopyBytes failed: \(result)"
            return
        }

        do {
            let capture = try await attest.attest(
                challenge: challenge,
                appId: appId,
                production: isProduction
            )
            lastCapture = capture
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func fixtureJSON(_ c: AttestationCapture) -> String {
        """
        {
          "attestation_object_hex": "\(c.attestationObject.hex)",
          "key_id_hex": "\(c.keyIdBytes.hex)",
          "challenge_hex": "\(c.challenge.hex)",
          "app_id": "\(c.appId)",
          "production": \(c.production)
        }
        """
    }
}

#Preview {
    ContentView()
}
