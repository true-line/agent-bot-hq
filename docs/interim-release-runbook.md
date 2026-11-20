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
2. As the prefix owner, enroll those public values as `agent-daemon`. New
   dedicated-account pairings on macOS require fresh consent in the owner's
   session. For qualification on a fresh Mac, use the signed first-enrollment
   CLI, independently pin its public key in Machine, and verify that Machine
   accepts a fresh proof for the intended HQ. Record that result before
   offering the CLI to customers. An existing pilot keeps its pinned owner
   key and can continue using its matching test provider.
   [First-enrollment CLI](https://github.com/true-line/agent-bot-identity/pull/1469)
   For an existing macOS pairing, use the verified public `machine_key` from
   the approved challenge for the first status check. On Linux obtain the
   prefix owner's published raw Ed25519 `daemon.pub` as 64 hex digits
   directly from that administrator.
3. As the HQ role, run `node hq/main.mjs machine status --socket PATH --daemon-key HEX`.
   Use the prefix owner's absolute `var/agent-machine/daemon.sock` path and
   the verified Machine public key. HQ persists the pin after a fresh,
   authenticated, successful reply. Later checks use
   `node hq/main.mjs machine status --socket PATH`. A different key is refused.

Once the daemon pin is saved, the dedicated HQ role can retrieve the prefix
administrator's saved members plans from a Machine with paired plan lookup.
List up to 64 plan IDs per page. If the reply includes `next_after`, pass
that exact value as the next cursor.

```sh
node hq/main.mjs machine members-plans list --socket "$socket"
node hq/main.mjs machine members-plans list --socket "$socket" --after "$next_after"
node hq/main.mjs machine members-plans get "$plan_id" --socket "$socket"
```

The lookup returns `plan_id`, `plan_digest` and `plan_canonical`. HQ verifies
the Machine signature, request nonce and digest of the complete canonical
plan, including its final newline. These commands read the saved plan for
review. Applying it requires a separate owner approval and human root apply.

Record the returned `channel`, `state` and `daemon_fingerprint` as channel
evidence. Secure Enclave custody and protected-profile qualification have
separate checks.

### Repair the macOS service after pairing

When the dedicated HQ account is healthy and its service is down, the
paired role can request owner approval of one saved repair
plan. The eligible plan contains only the unchanged `_agent-bot-hq` account
and the create or write step for `ai.true-line.agent-bot-hq`. As the paired
HQ role, export the challenge to a transfer file. The file contains the
original signed Machine response and the complete canonical plan.

```sh
node hq/main.mjs machine hq-service-recovery export "$plan_id" --socket "$socket" > "$challenge_file"
```

Transfer the file intact to the daily owner. On the owner's device, verify
the Machine fingerprint against the independently trusted SHA-256 fingerprint
of its raw Ed25519 public key. Check the intended HQ, exact plan and digest,
and confirm the local hardware key matches the pinned owner key. Signing
returns a proof file containing `public_key` and `signature`. The challenge
expires within two minutes. Exporting another challenge replaces the old one.

Return the proof to the paired role and submit it alongside the original
challenge. HQ checks the Machine signature against its saved pin and verifies
the owner's P-256 signature before contacting Machine.

```sh
node hq/main.mjs machine hq-service-recovery approve --challenge-file "$challenge_file" --proof-file "$proof_file" --socket "$socket"
```

An `approved` reply includes the plan ID, digest and approval expiry. The
administrator can then run `sudo managed-machine members apply "$plan_id"`
within that window. To cancel a pending challenge instead, run the following
command as the paired HQ role.

```sh
node hq/main.mjs machine hq-service-recovery cancel --challenge-file "$challenge_file" --socket "$socket"
```

### Upgrade a paired macOS service

Run the upgrade-capable HQ CLI as the existing dedicated role. Use the saved
Machine plan for replacing the installed v2 service. Its unchanged account
and service owner, current plan ID and digest, previous and next release
records, and both LaunchDaemon plists are covered by the challenge.

```sh
node hq/main.mjs machine hq-service-upgrade export "$plan_id" --socket "$socket" > "$challenge_file"
```

Transfer the original signed line to the daily owner's upgrade reviewer.
Confirm the independently trusted Machine fingerprint and both release records.
Return the operation-specific proof to the paired role within the challenge
lifetime. An approved reply records the normal short-lived members approval
for the exact replacement plan. Machine applies the saved plan separately.

```sh
node hq/main.mjs machine hq-service-upgrade approve --challenge-file "$challenge_file" --proof-file "$proof_file" --socket "$socket"
```

To discard a pending upgrade, return its original challenge to Machine as
the paired role.

```sh
node hq/main.mjs machine hq-service-upgrade cancel --challenge-file "$challenge_file" --socket "$socket"
```

### Review a dedicated macOS harness launch policy

Use the paired dedicated HQ account and the Machine pin saved during verified
status. For a saved installation plan, export its signed challenge with:

```sh
node hq/main.mjs machine harness-launch-install export "$plan_id" --socket "$socket" > "$challenge_file"
```

Transfer the original signed line to the daily owner's matching reviewer.
Review the target accounts and UIDs, adapter executable digests and exact
arguments, launcher and sandbox digests, and resulting sudoers rule. Return
the owner's proof to the paired role. Submit it with:

```sh
node hq/main.mjs machine harness-launch-install approve --challenge-file "$challenge_file" --proof-file "$proof_file" --socket "$socket"
```

For retirement use `harness-launch-retire` for both commands and check the
installed plan ID and digest. Each operation requires a fresh challenge and
its own proof. Either operation supports `cancel --challenge-file FILE
--socket PATH`. After an approved response, the administrator applies the
exact saved plan through the usual members apply command.
