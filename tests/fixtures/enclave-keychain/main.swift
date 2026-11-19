// Hosted native fixture. Its protected installation root is derived from the
// test binary's location. The release uses its fixed /Library root and exact
// Developer ID requirement; these overrides never enter the release build.
import Foundation
import Security
do {
    let input = try signerInput()
    let op = CommandLine.arguments[1]
    guard ["standalone-v1-status", "standalone-v1-create", "standalone-v1-sign"].contains(op)
    else { throw SignerFailure.invalidRequest }
    var code: SecCode?
    try checkStatus(SecCodeCopySelf([], &code))
    guard let code else { throw SignerFailure.accessControl }
    let executable = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL
    let root = (0..<4).reduce(executable) { path, _ in path.deletingLastPathComponent() }
    let installation = StandaloneInstallation(library: root.path, owner: 0, group: 0,
        inventory: MachineInstallationProbe(prefixes: [root.appendingPathComponent("test-prefix").path], rolePins: [], verify: { _ in false }))
    _ = try installation.authorized(role: dedicatedHQIdentity, runningPath: executable.path, perform: {
        try matchingRunningCode(code, path: executable)
        return try signerReply(operation: String(op.dropFirst("standalone-v1-".count)), input: input)
    }, publish: { try publishSignerReply($0) })
} catch {
    FileHandle.standardError.write(Data("fixture signer refused\n".utf8))
    exit(1)
}
