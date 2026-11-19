// HQ hardware signer protocol. CryptoKit never exports the private scalar.
import Darwin
import CryptoKit
import Foundation
import LocalAuthentication
import Security

enum SignerFailure: Error {
    case invalidRequest, keyMissing, keyExists, enclaveUnavailable, accessControl, invalidKey
    case keychain(OSStatus)
}

struct ReferenceStore {
    let keychain: SecKeychain
    let item: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword, kSecAttrService: "ai.true-line.hq.device-signer", kSecAttrAccount: "P-256"
    ]
    var search: [CFString: Any] {
        var query = item
        query[kSecMatchSearchList] = [keychain]
        return query
    }

    func load() throws -> Data? {
        var query = search
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw SignerFailure.keychain(status) }
        guard let data = result as? Data else { throw SignerFailure.invalidKey }
        return data
    }

    func save(_ reference: Data, replace: Bool) throws {
        var insert = item
        insert[kSecUseKeychain] = keychain
        insert[kSecValueData] = reference
        var selfApp: SecTrustedApplication?
        try checkStatus(SecTrustedApplicationCreateFromPath(nil, &selfApp))
        guard let selfApp else { throw SignerFailure.accessControl }
        var access: SecAccess?
        try checkStatus(SecAccessCreate("HQ device-bound key reference" as CFString, [selfApp] as CFArray, &access))
        guard let access else { throw SignerFailure.accessControl }
        insert[kSecAttrAccess] = access
        let result = SecItemAdd(insert as CFDictionary, nil)
        if result == errSecDuplicateItem {
            guard replace else { throw SignerFailure.keyExists }
            // A replacement commits with one Keychain update. A failed write
            // cannot leave the previous device key reference missing.
            let status = SecItemUpdate(search as CFDictionary, [kSecValueData: reference] as CFDictionary)
            guard status == errSecSuccess else { throw SignerFailure.keychain(status) }
        } else if result != errSecSuccess {
            throw SignerFailure.keychain(result)
        }
    }
}

private func encodeURL(_ data: Data) -> String {
    data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}

private func messageBytes(_ text: String) throws -> Data {
    guard text.utf8.count <= 43_691 else { throw SignerFailure.invalidRequest }
    var padded = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    padded += String(repeating: "=", count: (4 - padded.utf8.count % 4) % 4)
    guard let bytes = Data(base64Encoded: padded), bytes.count <= 32_768,
          encodeURL(bytes) == text else { throw SignerFailure.invalidRequest }
    return bytes
}

private func jwk(_ key: SecureEnclave.P256.Signing.PrivateKey) throws -> [String: String] {
    let point = key.publicKey.x963Representation
    guard point.count == 65, point.first == 4 else { throw SignerFailure.invalidKey }
    return ["kty": "EC", "crv": "P-256", "x": encodeURL(point.subdata(in: 1..<33)),
            "y": encodeURL(point.subdata(in: 33..<65))]
}

private struct Request: Decodable {
    let replace: Bool?
    let message: String?
}

func signerInput() throws -> Data {
    guard CommandLine.arguments.count == 2 else { throw SignerFailure.invalidRequest }
    // The host provides exactly one bounded JSON object and closes stdin.
    let input = FileHandle.standardInput.readData(ofLength: 48 * 1024 + 1)
    guard input.count <= 48 * 1024 else { throw SignerFailure.invalidRequest }
    return input
}

func signerReply(operation: String, input: Data) throws -> Data {
    let request = try JSONDecoder().decode(Request.self, from: input)
    guard SecureEnclave.isAvailable else { throw SignerFailure.enclaveUnavailable }
    let store = try roleStore(create: operation == "create")
    let context = LAContext()
    context.interactionNotAllowed = true
    var reply: [String: Any] = ["protocol": "agent-bot-hq-signer/1"]
    switch operation {
    case "status":
        reply["key_storage"] = "hardware"
        if let reference = try store?.load() {
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: reference, authenticationContext: context)
            reply["present"] = true
            reply["jwk"] = try jwk(key)
        } else {
            reply["present"] = false
        }
    case "create":
        guard let replace = request.replace else { throw SignerFailure.invalidRequest }
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                                            [.privateKeyUsage], nil) else { throw SignerFailure.accessControl }
        let key = try SecureEnclave.P256.Signing.PrivateKey(compactRepresentable: true,
                    accessControl: access, authenticationContext: context)
        reply["key_storage"] = "hardware"
        reply["jwk"] = try jwk(key)
        guard let store else { throw SignerFailure.keyMissing }
        try store.save(key.dataRepresentation, replace: replace)
    case "sign":
        guard let message = request.message else { throw SignerFailure.invalidRequest }
        let bytes = try messageBytes(message)
        guard let reference = try store?.load() else { throw SignerFailure.keyMissing }
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: reference, authenticationContext: context)
        reply["signature"] = encodeURL(try key.signature(for: bytes).rawRepresentation)
    default:
        throw SignerFailure.invalidRequest
    }
    return try JSONSerialization.data(withJSONObject: reply)
}
