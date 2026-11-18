// A system LaunchDaemon does not have an interactive user's data-protection
// Keychain. Keep CryptoKit's device-bound reference in a dedicated file
// Keychain under the role's private home, following Machine's daemon store.
import Darwin
import Foundation
import Security

func checkStatus(_ result: OSStatus) throws {
    guard result == errSecSuccess else { throw SignerFailure.keychain(result) }
}

private func privateEntry(_ path: String, uid: uid_t, directory: Bool) throws -> Bool {
    var info = stat()
    if lstat(path, &info) != 0 {
        if errno == ENOENT { return false }
        throw SignerFailure.accessControl
    }
    let kind = info.st_mode & S_IFMT
    guard info.st_uid == uid, info.st_mode & 0o077 == 0,
          directory ? kind == S_IFDIR : (kind == S_IFREG && info.st_nlink == 1) else {
        throw SignerFailure.accessControl
    }
    // POSIX bits do not reflect macOS extended ACLs. Refuse any extra ACE
    // rather than trying to interpret a principal or inherited permission.
    if let acl = acl_get_link_np(path, ACL_TYPE_EXTENDED) {
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        guard acl_get_entry(acl, ACL_FIRST_ENTRY.rawValue, &entry) == -1, errno == EINVAL else {
            throw SignerFailure.accessControl
        }
    } else if errno != ENOENT {
        throw SignerFailure.accessControl
    }
    return true
}

func roleStore(create: Bool) throws -> ReferenceStore? {
    guard let role = getpwnam("_agent-bot-hq"), role.pointee.pw_uid != 0,
          role.pointee.pw_uid == getuid(), geteuid() == getuid() else { throw SignerFailure.accessControl }
    let home = String(cString: role.pointee.pw_dir)
    guard home.hasPrefix("/"), try privateEntry(home, uid: getuid(), directory: true) else {
        throw SignerFailure.accessControl
    }
    let path = home + "/hq-device-signer.keychain-db"
    try checkStatus(SecKeychainSetUserInteractionAllowed(false))
    var db: SecKeychain?
    if try privateEntry(path, uid: getuid(), directory: false) {
        try checkStatus(SecKeychainOpen(path, &db))
    } else {
        guard create else { return nil }
        umask(0o077)
        // The account and self-only item ACL are the access boundaries. An
        // explicit empty password avoids prompting in the system domain.
        var original: SecKeychain?
        let restoreDefault = SecKeychainCopyDefault(&original) == errSecSuccess
        defer { if restoreDefault, let original { _ = SecKeychainSetDefault(original) } }
        let status = "".withCString { SecKeychainCreate(path, 0, $0, false, nil, &db) }
        if status == errSecDuplicateKeychain {
            guard try privateEntry(path, uid: getuid(), directory: false) else { throw SignerFailure.accessControl }
            try checkStatus(SecKeychainOpen(path, &db))
        } else {
            try checkStatus(status)
        }
    }
    guard let db, try privateEntry(path, uid: getuid(), directory: false) else { throw SignerFailure.accessControl }
    try checkStatus("".withCString { SecKeychainUnlock(db, 0, $0, true) })
    return ReferenceStore(keychain: db)
}
