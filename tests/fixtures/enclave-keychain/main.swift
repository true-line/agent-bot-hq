// The fixture binary is built on the ephemeral runner with production storage,
// account checks and signer protocol. The release entry point lives separately.
import Foundation
do {
    try runSigner()
} catch {
    FileHandle.standardError.write(Data("fixture signer failed: \(error)\n".utf8))
    exit(1)
}
