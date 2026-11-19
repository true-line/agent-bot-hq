// Native, software-only fixture. No Machine or signer operation is executed.
import Darwin
import Foundation

@main enum MachineInstallationFixture {
    static func main() throws {
        if CommandLine.arguments.dropFirst() == ["standard-reason"] {
            print(MachineInstallationProbe.standard.inspect().refusal)
            return
        }
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
        try Data(repeating: 0x4b, count: 32).write(to: sharedPin)
        expect(.priorIdentity, "persistent Machine public identity survives a stopped service")
        try Data([0]).write(to: sharedPin)
        expect(.indeterminate, "malformed prior Machine identity")
        try fm.removeItem(at: sharedPin)
        try fm.createSymbolicLink(at: rolePin, withDestinationURL: echo)
        expect(.indeterminate, "a symlink cannot establish a valid pairing record")
    }
}
