// Native, software-only fixture. No Machine or signer operation is executed.
import CryptoKit
import Darwin
import Foundation
import Security

@main enum MachineInstallationFixture {
    static func main() throws {
        if CommandLine.arguments.count == 3, CommandLine.arguments[1] == "check-writer" {
            let fd = open(CommandLine.arguments[2], O_RDWR | O_NOFOLLOW)
            guard fd >= 0 else { exit(2) }
            var region = flock()
            region.l_type = Int16(F_WRLCK)
            region.l_whence = Int16(SEEK_SET)
            let locked = fcntl(fd, F_SETLK, &region) == 0
            let busy = errno == EACCES || errno == EAGAIN
            close(fd)
            exit(locked ? 0 : busy ? 1 : 2)
        }
        guard let selfPath = realpath(CommandLine.arguments[0], nil) else { fatalError("fixture executable unavailable") }
        let executableURL = URL(fileURLWithPath: String(cString: selfPath))
        free(selfPath)
        // Check the dynamic CDHash requirement against this running fixture.
        // A second, independently signed system executable has a different hash.
        var processCode: SecCode?
        precondition(SecCodeCopySelf([], &processCode) == errSecSuccess)
        try matchingRunningCode(processCode!, path: executableURL)
        do {
            try matchingRunningCode(processCode!, path: URL(fileURLWithPath: "/bin/echo"))
            fatalError("a different on-disk executable cannot authorize the running code")
        } catch is StandaloneFailure {}
        let fm = FileManager.default
        guard let resolved = realpath(fm.temporaryDirectory.path, nil) else { fatalError("fixture temporary directory unavailable") }
        defer { free(resolved) }
        let root = URL(fileURLWithPath: String(cString: resolved)).appendingPathComponent("hq-install-evidence-" + UUID().uuidString)
        try fm.createDirectory(at: root, withIntermediateDirectories: false,
                               attributes: [.posixPermissions: NSNumber(value: 0o700)])
        defer { try? fm.removeItem(at: root) }
        let arm = root.appendingPathComponent("arm")
        let intel = root.appendingPathComponent("intel")
        let rolePin = root.appendingPathComponent("role/daemon.pub")
        let echo = URL(fileURLWithPath: "/bin/echo")
        let probe = MachineInstallationProbe(prefixes: [arm.path, intel.path], rolePins: [rolePin.path], verify: {
            validStaticExecutable($0, requirement: #"anchor apple and identifier "com.apple.echo""#)
        })
        func expect(_ want: MachineInstallationEvidence, _ test: String) {
            precondition(probe.inspect() == want, test)
        }
        func directory(_ p: URL) throws { try fm.createDirectory(at: p, withIntermediateDirectories: true) }
        expect(.noStandardEvidence, "an empty standard layout remains unverified")
        precondition(!validStaticExecutable(echo.path, requirement: machineReleaseRequirement), "wrong signed identity")
        try directory(intel.appendingPathComponent("bin"))
        let active = intel.appendingPathComponent("bin/agent-machine")
        let official = intel.appendingPathComponent("bin/managed-machine")
        try fm.copyItem(at: echo, to: official)
        try fm.createSymbolicLink(atPath: active.path, withDestinationPath: "managed-machine")
        expect(.verifiedExecutable, "active installed executable on second prefix")
        try fm.removeItem(at: active)
        try fm.removeItem(at: official)
        try fm.createSymbolicLink(at: active, withDestinationURL: echo)
        expect(.indeterminate, "external symlink target cannot prove a standard installation")
        try fm.removeItem(at: active)
        let rack = arm.appendingPathComponent("Cellar/managed-machine")
        let keg = rack.appendingPathComponent("1.0.0/bin/managed-machine")
        try directory(keg.deletingLastPathComponent())
        try fm.copyItem(at: echo, to: keg)
        expect(.verifiedExecutable, "unlinked keg")
        try fm.removeItem(at: keg)
        expect(.indeterminate, "partially installed keg")
        try fm.createSymbolicLink(atPath: keg.path, withDestinationPath: "/missing-fixture-target")
        expect(.indeterminate, "dangling executable")
        try fm.removeItem(at: rack)
        let opt = arm.appendingPathComponent("opt/managed-machine")
        try directory(opt.deletingLastPathComponent())
        try fm.createSymbolicLink(atPath: opt.path, withDestinationPath: "../Cellar/managed-machine/missing")
        expect(.indeterminate, "dangling opt link")
        try fm.removeItem(at: opt)
        try Data([0x7f, 0x45, 0x4c, 0x46]).write(to: active)
        precondition(chmod(active.path, 0o755) == 0)
        expect(.indeterminate, "invalid executable data")
        try fm.removeItem(at: active)
        precondition(mkfifo(active.path, 0o600) == 0)
        expect(.indeterminate, "a special file must never be opened as code")
        try fm.removeItem(at: active)
        if geteuid() != 0 {
            let bin = active.deletingLastPathComponent()
            precondition(chmod(bin.path, 0) == 0)
            expect(.indeterminate, "an unsearchable directory is not absent")
            precondition(chmod(bin.path, 0o700) == 0)
        }
        try directory(rolePin.deletingLastPathComponent())
        try Data(repeating: 0x4b, count: 32).write(to: rolePin)
        expect(.priorIdentity, "prior role pairing pin survives outage")
        try fm.removeItem(at: rolePin)
        let sharedPin = arm.appendingPathComponent("var/agent-machine/daemon.pub")
        try directory(sharedPin.deletingLastPathComponent())
        expect(.indeterminate, "an existing Machine channel without its pin is incomplete installation evidence")
        try Data(repeating: 0x4b, count: 32).write(to: sharedPin)
        expect(.priorIdentity, "persistent Machine public identity survives a stopped service")
        try Data([0]).write(to: sharedPin)
        expect(.indeterminate, "malformed prior Machine identity")
        try fm.removeItem(at: sharedPin.deletingLastPathComponent())
        expect(.noStandardEvidence, "the shared channel has been removed and neither prefix contains Machine")
        // Owner/group are injected only in this fixture to exercise the same
        // fd-based checks without creating accounts or touching /Library.
        let vendor = root.appendingPathComponent("Application Support/ai.true-line.agent-bot-hq")
        let auth = vendor.appendingPathComponent("standalone")
        try directory(auth)
        var parentInfo = stat()
        precondition(stat(root.path, &parentInfo) == 0)
        for dir in [vendor, auth] { precondition(chmod(dir.path, 0o755) == 0) }
        let installation = StandaloneInstallation(library: root.path, owner: getuid(), group: parentInfo.st_gid, inventory: probe)
        let binary = auth.appendingPathComponent("hq-signer")
        let declaration = auth.appendingPathComponent("declaration-v1")
        let retired = auth.appendingPathComponent("machine-retired-v1")
        let fixture = Data("inert fixture bytes".utf8)
        try fixture.write(to: binary)
        precondition(chmod(binary.path, 0o555) == 0)
        let uuid = UUID()
        let hash = SHA256.hash(data: fixture).map { String(format: "%02x", $0) }.joined()
        let text = "agent-bot-hq/standalone-signing/v1\nrole=_agent-bot-hq\nuid=350\nuuid=\(uuid.uuidString)\nno-custom-machine-installation=true\nhelper-sha256=\(hash)\n"
        func permitted(_ role: UUID? = nil) -> Bool {
            (try? installation.authorized(role: { (350, parentInfo.st_gid, role ?? uuid) }, runningPath: binary.path, perform: { true })) == true
        }
        precondition(!permitted(), "an absent declaration never authorizes signing")
        let transition = auth.appendingPathComponent("transition-v1")
        try Data("agent-bot-hq/standalone-transition/v1\n".utf8).write(to: transition)
        precondition(chmod(transition.path, 0o640) == 0)
        try Data(text.utf8).write(to: declaration)
        precondition(chmod(declaration.path, 0o644) == 0)
        precondition(permitted(), "positive root-established declaration, exact pinned helper and clean inventory")
        let pending = auth.appendingPathComponent("declaration-pending-v1")
        try Data().write(to: pending)
        precondition(!permitted(), "an incomplete declaration must not enable signing")
        try fm.removeItem(at: pending)
        precondition(chmod(transition.path, 0o644) == 0)
        precondition(!permitted(), "unrelated accounts must not have access to the coordination file")
        precondition(chmod(transition.path, 0o640) == 0)
        func writerIsBusy() throws -> Bool {
            let other = Process()
            other.executableURL = executableURL
            other.arguments = ["check-writer", transition.path]
            try other.run()
            other.waitUntilExit()
            return other.terminationStatus == 1
        }
        let output = Pipe()
        let writer = output.fileHandleForWriting.fileDescriptor
        let writerFlags = fcntl(writer, F_GETFL)
        let sent = Data("fixture public result".utf8)
        _ = try installation.authorized(role: { (350, parentInfo.st_gid, uuid) }, runningPath: binary.path, perform: {
            let busy = try writerIsBusy()
            precondition(busy, "the writer waits for key use")
            return sent
        }, publish: { bytes in
            let busy = try writerIsBusy()
            precondition(busy, "the writer waits for bounded reply delivery")
            try publishSignerReply(bytes, fd: writer)
        })
        // Darwin sets FWASWRITTEN on any successful write.
        let mutableFlags = O_NONBLOCK | O_APPEND | O_ASYNC
        precondition(fcntl(writer, F_GETFL) & mutableFlags == writerFlags & mutableFlags, "restore the caller's mutable flags")
        precondition(output.fileHandleForReading.readData(ofLength: sent.count) == sent)
        do {
            _ = try installation.authorized(role: { (350, parentInfo.st_gid, uuid) }, runningPath: binary.path, perform: {
                try Data().write(to: retired)
                return sent
            }, publish: { _ in fatalError("retired result was delivered") })
            fatalError("retirement during key use must withhold the result")
        } catch is StandaloneFailure {}
        try fm.removeItem(at: retired)
        precondition(!permitted(UUID()), "same UID cannot inherit authorization after role recreation")
        precondition(chmod(declaration.path, 0o666) == 0)
        precondition(!permitted(), "unsafe declaration mode")
        precondition(chmod(declaration.path, 0o644) == 0)
        try Data(repeating: 1, count: 32).write(to: rolePin)
        precondition(!permitted(), "a stopped paired Machine prevents key use")
        try fm.removeItem(at: rolePin)
        try Data().write(to: retired)
        precondition(!permitted(), "any tombstone prevents later key use after removal or revocation")
        try fm.removeItem(at: retired)
        try Data(text.replacingOccurrences(of: hash, with: String(repeating:"a",count:64)).utf8).write(to: declaration)
        precondition(!permitted(), "the independently pinned release digest must match")
        try fm.createSymbolicLink(at: rolePin, withDestinationURL: echo)
        expect(.indeterminate, "a symlink cannot establish a valid pairing record")
    }
}
