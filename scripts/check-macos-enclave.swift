// HQ #107 / PDR-0085. This one-shot probe creates a disposable key. It never
// accesses an enrolled key or serializes its wrapped reference outside memory.
import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import Security

enum CheckError: Error {
    case invalidArguments, invalidPublicKey, invalidSignature, accessControl
}

extension Data {
    var base64url: String {
        base64EncodedString()
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "=", with: "")
    }
}

struct PublicJWK: Encodable {
    let kty = "EC"
    let crv = "P-256"
    let x: String
    let y: String

    init(_ publicKey: P256.Signing.PublicKey) throws {
        let point = publicKey.x963Representation
        guard point.count == 65, point.first == 4 else { throw CheckError.invalidPublicKey }
        x = point.subdata(in: 1..<33).base64url
        y = point.subdata(in: 33..<65).base64url
    }
}

struct Observation: Encodable {
    let source: String
    let uid: uid_t
    let jwk: PublicJWK
    let signature: String
}

func check(source: String, message: Data) throws -> Observation {
    let publicKey: P256.Signing.PublicKey
    let signature: P256.Signing.ECDSASignature
    switch source {
    case "software-fixture":
        let key = P256.Signing.PrivateKey()
        publicKey = key.publicKey
        signature = try key.signature(for: message)
    case "secure-enclave":
        guard SecureEnclave.isAvailable else {
            FileHandle.standardError.write(Data("Secure Enclave unavailable\n".utf8))
            exit(77)
        }
        let context = LAContext()
        context.interactionNotAllowed = true
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, [], nil) else {
            throw CheckError.accessControl
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(
            compactRepresentable: true, accessControl: access, authenticationContext: context
        )
        publicKey = key.publicKey
        let reopened = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: key.dataRepresentation, authenticationContext: context
        )
        signature = try reopened.signature(for: message)
    default:
        throw CheckError.invalidArguments
    }
    guard publicKey.isValidSignature(signature, for: message), signature.rawRepresentation.count == 64 else {
        throw CheckError.invalidSignature
    }
    return try Observation(source: source, uid: geteuid(), jwk: PublicJWK(publicKey), signature: signature.rawRepresentation.base64url)
}

do {
    let args = CommandLine.arguments
    guard args.count == 3, let message = Data(base64Encoded: args[2]), message.count == 32,
          message.base64EncodedString() == args[2] else { throw CheckError.invalidArguments }
    let result = try check(source: args[1], message: message)
    FileHandle.standardOutput.write(try JSONEncoder().encode(result))
} catch {
    FileHandle.standardError.write(Data("macOS signer check failed: \(error)\n".utf8))
    exit(1)
}
