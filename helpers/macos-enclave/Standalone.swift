import CryptoKit
import Darwin
import Foundation
import OpenDirectory
import Security

enum StandaloneFailure: Error {
    case unavailable
}

func dedicatedHQIdentity() throws -> (uid_t, gid_t, UUID) {
    let uid = getuid()
    guard uid == geteuid(), (300...399).contains(uid),
          let role = getpwnam("_agent-bot-hq"), role.pointee.pw_uid == uid,
          role.pointee.pw_gid == uid, ["/var/agent-bot-hq", "/private/var/agent-bot-hq"].contains(String(cString: role.pointee.pw_dir))
    else { throw StandaloneFailure.unavailable }
    let node = try ODNode(session: ODSession.default(), name: "/Local/Default")
    let record = try node.record(withRecordType: kODRecordTypeUsers, name: "_agent-bot-hq",
                                 attributes: [kODAttributeTypeUniqueID, kODAttributeTypeGUID])
    let ids = try record.values(forAttribute: kODAttributeTypeUniqueID) as? [String]
    let uuids = try record.values(forAttribute: kODAttributeTypeGUID) as? [String]
    guard ids == [String(uid)], let uuids, uuids.count == 1, let id = UUID(uuidString: uuids[0])
    else { throw StandaloneFailure.unavailable }
    return (uid, uid, id)
}

struct StandaloneInstallation {
    let library: String
    let owner: uid_t
    let group: gid_t
    let inventory: MachineInstallationProbe

    static let standard = StandaloneInstallation(library: "/Library", owner: 0, group: 0, inventory: .standard)

    private func metadata(_ fd: Int32, directory: Bool, mode: mode_t? = nil, expectedGroup: gid_t? = nil) throws -> stat {
        var s = stat()
        guard fstat(fd, &s) == 0, s.st_uid == owner, s.st_mode & S_IFMT == (directory ? S_IFDIR : S_IFREG),
              s.st_mode & 0o7022 == 0, directory || s.st_nlink == 1,
              mode.map({ s.st_gid == (expectedGroup ?? group) && s.st_mode & 0o7777 == $0 }) ?? true
        else { throw StandaloneFailure.unavailable }
        guard let acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED) else {
            guard errno == ENOENT else { throw StandaloneFailure.unavailable }
            return s
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        guard acl_get_entry(acl, ACL_FIRST_ENTRY.rawValue, &entry) == -1, errno == EINVAL
        else { throw StandaloneFailure.unavailable }
        return s
    }

    // Keep the shared lock across the custody operation. The administrator
    // retires this installation and drains operations on the same dedicated inode.
    func authorized<T>(role: () throws -> (uid_t, gid_t, UUID), runningPath: String,
                       perform: () throws -> T, publish: (T) throws -> Void = { _ in }) throws -> T {
        let flags = O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | O_RDONLY
        let libraryFD = open(library, flags | O_DIRECTORY)
        guard libraryFD >= 0 else { throw StandaloneFailure.unavailable }
        defer { close(libraryFD) }
        _ = try metadata(libraryFD, directory: true)
        var fds = [Int32]()
        defer { for fd in fds.reversed() { close(fd) } }
        var parent = libraryFD
        for component in ["Application Support", "ai.true-line.agent-bot-hq", "standalone"] {
            let fd = openat(parent, component, flags | O_DIRECTORY)
            guard fd >= 0 else { throw StandaloneFailure.unavailable }
            fds.append(fd)
            _ = try metadata(fd, directory: true, mode: component == "Application Support" ? nil : 0o755)
            parent = fd
        }
        func active() throws {
            for name in ["machine-retired-v1", "declaration-pending-v1"] {
                var info = stat()
                guard fstatat(parent, name, &info, AT_SYMLINK_NOFOLLOW) == -1, errno == ENOENT
                else { throw StandaloneFailure.unavailable }
            }
        }
        func readFile(_ fd: Int32, _ mode: mode_t, _ maximum: Int, expectedGroup: gid_t? = nil) throws -> Data {
            let s = try metadata(fd, directory: false, mode: mode, expectedGroup: expectedGroup)
            guard s.st_size > 0, s.st_size <= maximum else { throw StandaloneFailure.unavailable }
            let file = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
            let data = try file.read(upToCount: maximum + 1) ?? Data()
            guard data.count == s.st_size else { throw StandaloneFailure.unavailable }
            return data
        }
        func contents(_ name: String, _ mode: mode_t, _ maximum: Int) throws -> Data {
            let fd = openat(parent, name, flags)
            guard fd >= 0 else { throw StandaloneFailure.unavailable }
            defer { close(fd) }
            return try readFile(fd, mode, maximum)
        }
        let (uid, gid, uuid) = try role()
        let lock = openat(parent, "transition-v1", flags)
        guard lock >= 0 else { throw StandaloneFailure.unavailable }
        defer { close(lock) }
        let transition = try readFile(lock, 0o640, 64, expectedGroup: gid)
        guard transition == Data("agent-bot-hq/standalone-transition/v1\n".utf8) else { throw StandaloneFailure.unavailable }
        var region = flock()
        region.l_type = Int16(F_RDLCK)
        region.l_whence = Int16(SEEK_SET)
        guard fcntl(lock, F_SETLK, &region) == 0 else { throw StandaloneFailure.unavailable }
        try active()
        let evidence = inventory.inspect()
        guard evidence == .noStandardEvidence else { throw evidence }
        let path = library + "/Application Support/ai.true-line.agent-bot-hq/standalone/hq-signer"
        guard runningPath == path else { throw StandaloneFailure.unavailable }
        let declaration = try contents("declaration-v1", 0o644, 512)
        let binary = try contents("hq-signer", 0o555, 32 * 1024 * 1024)
        let digest = SHA256.hash(data: binary).map { String(format: "%02x", $0) }.joined()
        let expected = "agent-bot-hq/standalone-signing/v1\nrole=_agent-bot-hq\nuid=\(uid)\nuuid=\(uuid.uuidString)\nno-custom-machine-installation=true\nhelper-sha256=\(digest)\n"
        guard declaration == Data(expected.utf8) else { throw StandaloneFailure.unavailable }
        let result = try perform()
        try active()
        try publish(result)
        return result
    }
}

func matchingRunningCode(_ running: SecCode, path: URL) throws {
    // A process can have started before a privileged replacement of the file.
    // Require its signing hash to match the release bytes verified under lock.
    func requireSuccess(_ status: OSStatus) throws {
        guard status == errSecSuccess else { throw StandaloneFailure.unavailable }
    }
    var disk: SecStaticCode?
    try requireSuccess(SecStaticCodeCreateWithPath(path as CFURL, [], &disk))
    var staged: CFDictionary?
    guard let disk else { throw StandaloneFailure.unavailable }
    try requireSuccess(SecCodeCopySigningInformation(disk, [], &staged))
    guard let hash = (staged as NSDictionary?)?[kSecCodeInfoUnique] as? Data, hash.count == 20
    else { throw StandaloneFailure.unavailable }
    let hex = hash.map { String(format: "%02x", $0) }.joined()
    var exact: SecRequirement?
    try requireSuccess(SecRequirementCreateWithString(("cdhash H\"" + hex + "\"") as CFString, [], &exact))
    guard let exact else { throw StandaloneFailure.unavailable }
    try requireSuccess(SecCodeCheckValidity(running, [], exact))
}


// A slow reader must not hold retirement open. HQ uses a pipe or socket for
// this one-shot protocol. A complete public reply fits in POSIX's minimum
// atomic pipe write; a partial/closed socket cannot yield a valid reply.
func publishSignerReply(_ data: Data, fd: Int32 = STDOUT_FILENO) throws {
    var s = stat()
    let flags = fcntl(fd, F_GETFL)
    guard !data.isEmpty, data.count <= 512, flags >= 0, fstat(fd, &s) == 0,
          [S_IFIFO, S_IFSOCK].contains(s.st_mode & S_IFMT) || isatty(fd) == 1,
          fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else { throw StandaloneFailure.unavailable }
    defer { _ = fcntl(fd, F_SETFL, flags) }
    let written = data.withUnsafeBytes { raw in Darwin.write(fd, raw.baseAddress, raw.count) }
    guard written == data.count else { throw StandaloneFailure.unavailable }
}
