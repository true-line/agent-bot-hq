import Darwin
import Foundation
import Security

enum MachineInstallationEvidence: Error, Equatable {
    case verifiedExecutable, priorIdentity, indeterminate, noStandardEvidence

    var refusal: String {
        switch self {
        case .verifiedExecutable: return "HQ standalone signing is unavailable because a verified Agent Machine executable is installed"
        case .priorIdentity: return "HQ standalone signing is unavailable because prior Machine identity evidence exists"
        case .indeterminate: return "HQ standalone signing is unavailable because Machine installation evidence could not be verified"
        case .noStandardEvidence: return "No standard Machine installation evidence was found. HQ standalone installation remains unverified"
        }
    }
}

let machineReleaseRequirement = #"anchor apple generic and identifier "ai.true-line.agent-bot-machine" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[subject.OU] = "Z5DM34QS5U" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"#

// Static validation never starts the candidate. The trust evaluation is local.
func validStaticExecutable(_ path: String, requirement expression: String) -> Bool {
    var requirement: SecRequirement?
    var code: SecStaticCode?
    guard SecRequirementCreateWithString(expression as CFString, [], &requirement) == errSecSuccess,
          let requirement,
          SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
          let code else { return false }
    let flags = SecCSFlags(rawValue: UInt32(kSecCSStrictValidate | kSecCSCheckAllArchitectures)).union(.noNetworkAccess)
    return SecStaticCodeCheckValidity(code, flags, requirement) == errSecSuccess
}

private enum PathObservation {
    case missing, invalid, present(stat)
}

// An absent child below a dangling link or a non-directory is indeterminate.
// Normal Homebrew bin/opt links can lead to the Cellar. A disappearing target
// or an unsearchable component is never proof that the product is absent.
private func observePath(_ path: String, followLeaf: Bool = true) -> PathObservation {
    var current = ""
    for part in path.split(separator: "/") {
        current += "/" + part
        var entry = stat()
        guard lstat(current, &entry) == 0 else { return errno == ENOENT ? .missing : .invalid }
        if entry.st_mode & S_IFMT == S_IFLNK && (current != path || followLeaf) {
            guard stat(current, &entry) == 0 else { return .invalid }
        }
        if current == path { return .present(entry) }
        if entry.st_mode & S_IFMT != S_IFDIR { return .invalid }
    }
    return .invalid
}

private func kegNames(_ path: String) -> [String]? {
    guard let directory = opendir(path) else { return nil }
    defer { closedir(directory) }
    var names = [String]()
    while true {
        errno = 0
        guard let entry = readdir(directory) else { return errno == 0 ? names.sorted() : nil }
        let name = withUnsafePointer(to: &entry.pointee.d_name) {
            String(validatingCString: UnsafeRawPointer($0).assumingMemoryBound(to: CChar.self))
        }
        guard let component = name else { return nil }
        if component == "." || component == ".." { continue }
        guard names.count < 128 else { return nil }
        names.append(component)
    }
}

struct MachineInstallationProbe {
    let prefixes: [String]
    let rolePins: [String]
    let verify: (String) -> Bool

    static let standard = MachineInstallationProbe(
        prefixes: ["/opt/homebrew", "/usr/local"],
        rolePins: ["/private/var/agent-bot-hq/.config/agent-machine/daemon.pub"],
        verify: { validStaticExecutable($0, requirement: machineReleaseRequirement) }
    )

    private func recognizedExecutable(_ resolved: String) -> Bool {
        for prefix in prefixes where resolved.hasPrefix(prefix + "/") {
            let parts = resolved.dropFirst(prefix.count + 1).split(separator: "/")
            guard let name = parts.last, name == "managed-machine" || name == "agent-machine" else { continue }
            if parts.count == 2 && parts[0] == "bin" { return true }
            if parts.count == 5 && parts[0] == "Cellar" && parts[1] == "managed-machine" && parts[3] == "bin" { return true }
        }
        return false
    }

    func inspect() -> MachineInstallationEvidence {
        var uncertain = false
        var identity = false

        func installed(_ candidate: String, expected: Bool = false) -> Bool {
            switch observePath(candidate) {
            case .missing: if expected { uncertain = true }
            case .invalid: uncertain = true
            case .present(let before):
                guard before.st_mode & S_IFMT == S_IFREG, before.st_mode & 0o111 != 0, before.st_size > 0,
                      let resolved = realpath(candidate, nil) else { uncertain = true; return false }
                defer { free(resolved) }
                let location = String(cString: resolved)
                guard recognizedExecutable(location) else { uncertain = true; return false }
                let valid = verify(location)
                guard case .present(let after) = observePath(candidate),
                      before.st_dev == after.st_dev, before.st_ino == after.st_ino,
                      before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
                      before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec,
                      valid else { uncertain = true; return false }
                return true
            }
            return false
        }

        for prefix in prefixes {
            for name in ["managed-machine", "agent-machine"] {
                if installed(prefix + "/bin/" + name) { return .verifiedExecutable }
            }
            let opt = prefix + "/opt/managed-machine"
            switch observePath(opt) {
            case .present: if installed(opt + "/bin/managed-machine", expected: true) { return .verifiedExecutable }
            case .invalid: uncertain = true
            case .missing: break
            }
            let rack = prefix + "/Cellar/managed-machine"
            switch observePath(rack) {
            case .present(let info):
                guard info.st_mode & S_IFMT == S_IFDIR, let versions = kegNames(rack) else { uncertain = true; continue }
                if versions.isEmpty { uncertain = true }
                for version in versions {
                    if installed(rack + "/" + version + "/bin/managed-machine", expected: true) { return .verifiedExecutable }
                }
            case .invalid: uncertain = true
            case .missing: break
            }
        }
        for path in rolePins + prefixes.map({ $0 + "/var/agent-machine/daemon.pub" }) {
            switch observePath(path, followLeaf: false) {
            case .present(let info):
                if info.st_mode & S_IFMT == S_IFREG, info.st_size == 32 {
                    identity = true
                } else { uncertain = true }
            case .invalid: uncertain = true
            case .missing: break
            }
        }
        if identity { return .priorIdentity }
        // A stopped or partially installed Machine may leave its shared
        // channel behind before a public pin is available.
        for prefix in prefixes {
            switch observePath(prefix + "/var/agent-machine", followLeaf: false) {
            case .missing: continue
            case .present, .invalid: return .indeterminate
            }
        }
        return uncertain ? .indeterminate : .noStandardEvidence
    }
}
