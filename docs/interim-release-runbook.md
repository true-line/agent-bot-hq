# Interim HQ source artifact (proposal)

This runbook covers operator-managed HQ source artifacts for Linux and macOS. Each tar targets one operating system. It does not create the
Stage 3 bundled release, an updater, a service unit, or an automatic rollout.
Do not publish or deploy until the owner approves the exact artifact and target
inventory. The release operator owns the build and publication record; the
deployment operator owns client inventory, installation, monitoring and rollback.

## Build and verify

1. Merge and review the packaging implementation. Select its exact full HQ
   commit; the key-only base is e1c6fcae513f3b1220f5c6b013df5ba89272f958,
   which does not contain this builder. Verify the source commit and clean tree.
2. Obtain the public soul-contracts tree at the release pin's exact commit and
   verify its tag and `sha256-manifest-v1` digest through the approved source
   channel. Record independent tag-to-commit provenance evidence as a mandatory
   release input; the builder verifies directory contents but cannot infer which
   Git commit or tag they came from. Provide its directory to the builder. Do
   not supply private keys.
3. For Linux, on two independent Linux build environments with Node 20+, Git and GNU tar,
   run `node scripts/build-interim-release.mjs <full-hq-commit> <contracts-dir> <new-output.tar>`,
   with the contracts directory and new output path outside the clean checkout.
   For macOS, add `--target darwin` and use a separate output file. The Darwin
   target builds on Linux with GNU tar and on macOS with GNU tar as `gtar`.
   Native CI runs the resulting tar with Node as `_agent-bot-hq` on a macOS 15
   hosted runner and compares its SHA-256 with an independent Linux build of
   that target. The native check covers cooperative status through HQ's private
   socket in an unenrolled service account. LaunchDaemon installation, owner access
   from another account, Secure Enclave signing and protected-profile acceptance
   have separate gates.
   Compare SHA-256 of the two archives. Record source commit, contracts commit,
   contracts digest, artifact SHA-256, builder/tool versions and both results.
   A mismatch blocks publication. Obtain the owner's approval of those bytes.
4. Verify the artifact digest against the approved record before extracting on
   each host. Reject paths escaping the target and unexpected symlinks. Extract
   under a new versioned directory writable only by the deployment operator;
   use a path whose ancestors contain no symlinks. The verifier refuses symlinked
   paths. State, signer and enrollment remain outside the artifact. Retain the prior
   release and state backup under their existing access controls.
5. With networking unavailable, start the artifact entrypoint `node hq/main.mjs
   run` using an isolated HQ home and the legacy enrollment setting; verify
   status. Alter, remove and add a contracts file in disposable copies and
   verify each startup refuses. Test the exact archive, not a working tree.

## Distribution and activation

The deployment operator records an inventory of all intended enrolled HQ
clients, current artifact and pin, owner, online status and update confirmation.
Install and verify the approved digest on each target while the existing signer
and legacy path remain in use. Do not switch the service signer until all
targeted clients have the required release or an owner has explicitly resolved
each exception. Offline clients cannot be counted as updated without evidence.

The owner authorized a cloud-workspace pilot on 2026-11-16. Its response-acceptance
window is [2026-11-16T18:21:50Z, 2027-02-14T18:21:50Z), preserving the existing
public key and the 90-day duration. Prepare its replacement by
2027-01-15T18:21:50Z. These are acceptance-policy dates, not the private key's
creation date. Activation may occur within this window after the artifact and
inventory gates above; a later start does not silently extend the expiry.
Harbor's paired public metadata is recorded in
[deploy/server-response-keys.json](https://github.com/true-line/agent-bot/blob/main/deploy/server-response-keys.json).
Within the accepted window, deploy the matching server public
metadata with the verified signer; wait at least 300 seconds for the endpoint
cache. On a designated enrolled test client, record signed token-grant and
daemon API success, authenticated refusal, client artifact/pin and observed
time without recording token, assertion, private key or response secrets.

If checks fail, stop HQ ingestion and retain any exclusive notice-custody policy
so the queue remains paused; do not clear custody to re-enable old consumers.
Disable the HQ opt-in and switch the host back to the retained verified release.
If server metadata is rolled back with the unchanged uncompromised signer,
record that removing metadata restores legacy signing without the new server
expiry enforcement. Verify health and record the outcome after cache expiry.
Do not extend expiration silently or re-enable a suspected compromised key;
old offline HQ pins cannot be remotely revoked by publishing retired metadata.
Issue #122 remains open until release, coverage, success, refusal and rollback
evidence is recorded.

## Verify the HQ-to-Machine channel

For [HQ #56](https://github.com/true-line/agent-bot-hq/issues/56), provision
the dedicated HQ account and stage the verified HQ artifact and Node runtime
using [Machine’s HQ service installation](https://github.com/true-line/agent-bot-machine/blob/main/docs/plans/member-accounts.md).
Run the following HQ commands with those absolute executable and entrypoint
paths, as `_agent-bot-hq` on macOS or `agent-bot-hq` on Linux.

1. Run `node hq/main.mjs machine identity` as the HQ role. It returns
   `public_key` (Ed25519 hex) and `fingerprint` (SHA-256 hex) for the prefix
   owner. Repeating the command returns the same identity. The seed stays
   under the provisioned HQ role's private home.
2. As the prefix owner, enroll those public values as `agent-daemon`. On macOS
   follow [Machine's owner approval procedure](https://github.com/true-line/agent-bot-machine/blob/main/docs/plans/macos-signing.md#owner-approval-for-a-new-hq-pairing).
   Keep the verified public `machine_key` from the approved challenge for the
   first status check. On Linux obtain the prefix owner's published raw
   Ed25519 `daemon.pub` as 64 hex digits directly from that administrator.
3. As the HQ role, run `node hq/main.mjs machine status --socket PATH --daemon-key HEX`.
   Use the prefix owner's absolute `var/agent-machine/daemon.sock` path and
   the verified Machine public key. HQ persists the pin after a fresh,
   authenticated, successful reply. Later checks use
   `node hq/main.mjs machine status --socket PATH`. A different key is refused.

Record the returned `channel`, `state` and `daemon_fingerprint` as channel
evidence. Secure Enclave custody and protected-profile qualification have
separate checks.
