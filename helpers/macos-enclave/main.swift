import Foundation
import Security

do {
    // Read the one-shot request before taking the installation lock. A caller
    // holding stdin open cannot delay administrative retirement.
    let input = try signerInput()
    let op = CommandLine.arguments[1]
    guard ["standalone-v1-status", "standalone-v1-create", "standalone-v1-sign"].contains(op)
    else { throw SignerFailure.invalidRequest }
    var code: SecCode?
    var requirement: SecRequirement?
    let expression = #"anchor apple generic and identifier "ai.true-line.hq.signer" and certificate leaf[subject.OU] = "Z5DM34QS5U" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"#
    try checkStatus(SecCodeCopySelf(SecCSFlags(), &code))
    try checkStatus(SecRequirementCreateWithString(expression as CFString, SecCSFlags(), &requirement))
    guard let code, let requirement else { throw SignerFailure.accessControl }
    try checkStatus(SecCodeCheckValidity(code, SecCSFlags(), requirement))
    var staticCode: SecStaticCode?
    try checkStatus(SecCodeCopyStaticCode(code, [], &staticCode))
    var url: CFURL?
    guard let staticCode else { throw SignerFailure.accessControl }
    try checkStatus(SecCodeCopyPath(staticCode, [], &url))
    guard let url else { throw SignerFailure.accessControl }
    _ = try StandaloneInstallation.standard.authorized(role: dedicatedHQIdentity, runningPath: (url as URL).path, perform: {
        try matchingRunningCode(code, path: url as URL)
        return try signerReply(operation: String(op.dropFirst("standalone-v1-".count)), input: input)
    }, publish: { try publishSignerReply($0) })
} catch let evidence as MachineInstallationEvidence {
    FileHandle.standardError.write(Data((evidence.refusal + "\n").utf8))
    exit(1)
} catch {
    FileHandle.standardError.write(Data("HQ Secure Enclave signer unavailable\n".utf8))
    exit(1)
}
