import Foundation
import Security

// A signed executable and the dedicated role authenticate the signer. Neither
// establishes that Machine is absent or that this host has no pairing history.
enum StandaloneInstallationFailure: Error {
    case unverified
}

func requireStandaloneInstallation() throws {
    // No product installer currently supplies this evidence to the native
    // helper. A config flag, stopped daemon or missing path cannot supply it.
    throw StandaloneInstallationFailure.unverified
}

do {
    try requireStandaloneInstallation()
    var code: SecCode?
    var requirement: SecRequirement?
    let expression = #"anchor apple generic and identifier "ai.true-line.hq.signer" and certificate leaf[subject.OU] = "Z5DM34QS5U" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"#
    try checkStatus(SecCodeCopySelf(SecCSFlags(), &code))
    try checkStatus(SecRequirementCreateWithString(expression as CFString, SecCSFlags(), &requirement))
    guard let code, let requirement else { throw SignerFailure.accessControl }
    try checkStatus(SecCodeCheckValidity(code, SecCSFlags(), requirement))
    guard let task = SecTaskCreateFromSelf(nil),
          let app = SecTaskCopyValueForEntitlement(task, "com.apple.application-identifier" as CFString, nil) as? String,
          app.hasSuffix(".ai.true-line.hq.signer"),
          let groups = SecTaskCopyValueForEntitlement(task, "keychain-access-groups" as CFString, nil) as? [String],
          groups.contains(app) else { throw SignerFailure.accessControl }
    try runSigner()
} catch StandaloneInstallationFailure.unverified {
    FileHandle.standardError.write(Data("HQ standalone installation is unverified\n".utf8))
    exit(1)
} catch {
    FileHandle.standardError.write(Data("HQ Secure Enclave signer unavailable\n".utf8))
    exit(1)
}
