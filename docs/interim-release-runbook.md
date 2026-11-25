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
   For Darwin's bundled communications broker, the pin records the published
   agent-comms release tag, source commit, built plugin tree digest and release
   asset SHA-256. The builder checks the tag-to-commit binding and verifies the
   staged plugin tree. Verify the published archive against its recorded asset
   SHA-256 separately; the builder reads source Git blobs, not that archive.
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

For a reviewed public Darwin release, publish the approved tar bytes under
`agent-bot-hq-VERSION-darwin-arm64.tar` in GitHub release `vVERSION`.
Generate the self-tap formula with
`node scripts/build-homebrew-formula.mjs VERSION ARCHIVE APPROVED_SHA256`
and review it as `Formula/agent-bot-hq.rb`. After the formula is published,
install and check it as the Homebrew administrator.

```sh
brew tap true-line/agent-bot-hq https://github.com/true-line/agent-bot-hq.git
brew install agent-bot-hq
brew list --versions agent-bot-hq
brew --prefix agent-bot-hq
brew test agent-bot-hq
```

Use the retained archive under `$(brew --prefix agent-bot-hq)/libexec`
as the source for [Machine's macOS HQ LaunchDaemon setup](https://github.com/true-line/agent-bot-machine/blob/main/docs/plans/member-accounts.md#macos-hq-launchdaemon).
Stage the archive and an approved standalone Node runtime under the root-owned
paths that Machine verifies. Start the dedicated service through the approved
Machine plan. Use `agent-bot-hq status --owner-control` to query that service.

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

Machine v0.12.4 supports signed status and predates the `hq-device` operation.
If HQ reports `MM_DAEMON_VERB_UNKNOWN` for device signing, keep the existing
pairing and use a Machine release that supports `hq-device` before enrollment.

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

This service-only upgrade preserves an existing Machine-backed hardware device
identity. The running service's authenticated owner status must report
`hq.signer.available` as `true`, `hq.signer.backend` as `machine` and
`hq.signer.key_storage` as `hardware`. Machine checks that status during
planning, before stopping the service.

If the current service uses a legacy software signer or its signer cannot be
verified, leave the service running with its pairing, signer files, enrollment
records and prior release intact. An absent local enrollment record cannot
establish that the device was never enrolled. Verify its enrollment history
with the issuer before seeking an explicitly authorized custody transition.

Sign in to the original issuer as the device owner. Compare the public
`thumbprint` in the retained `signer/pin.json` with `thumbprint` on a device
returned by `GET /api/web/devices`. If the original device ID is known,
check `GET /api/web/devices/{id}` as well. A matching RFC 7638 thumbprint
confirms that key was enrolled.

The fleet list omits expired devices. A retained detail record can still
identify an expired device, but revocation removes the key metadata and
cleanup can remove the record entirely. An empty list, a detail without
a thumbprint, or a 404 leaves enrollment history unknown.

Track that work in [the existing custody transition issue](https://github.com/true-line/agent-bot-hq/issues/188).

Run the upgrade-capable HQ CLI as the existing dedicated role. Use the saved
Machine plan for replacing the installed v2 service. Its unchanged account
and service owner, current plan ID and digest, previous and next release
records, and both LaunchDaemon plists are covered by the challenge.

```sh
node hq/main.mjs machine hq-service-upgrade export "$plan_id" --socket "$socket" > "$challenge_file"
```

Before scheduling a physical upgrade, verify that the installed owner
reviewer supports the exact `hq-service-upgrade` purpose with the existing
pinned owner key. The [first-enrollment macOS CLI](https://github.com/true-line/agent-bot-identity/pull/1469)
supports pairing and first-HQ approval only. A physical cutover must wait
until the owner has a supported upgrade reviewer for that pin.

Transfer the original signed line to that reviewer. Confirm the independently
trusted Machine fingerprint and both release records.
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

### Review dedicated macOS harness accounts

From the paired dedicated HQ account, export the administrator’s saved account
plan for the existing owner reviewer.

```sh
node hq/main.mjs machine harness-account-provision export "$plan_id" --socket "$socket" > "$challenge_file"
```

Use the independently pinned Machine fingerprint to review the unchanged HQ
account, each named harness account and its numeric UID and GID, and any broker
directories. After the owner signs, return the proof from the same paired HQ
account. Machine applies the approved plan separately.

```sh
node hq/main.mjs machine harness-account-provision approve --challenge-file "$challenge_file" --proof-file "$proof_file" --socket "$socket"
```

To discard the request, use `cancel --challenge-file "$challenge_file" --socket "$socket"`
in place of `approve` and its arguments. A replacement challenge requires a fresh proof.

### Enable the approved harness broker sockets

Once Machine applies the account plan, check that its receipt lists the intended
accounts and the directory `/Library/Application Support/ai.true-line.agent-bot-hq/ipc`.
HQ reads an adapter-to-account mapping only when the operator configures
selected harnesses. Base HQ, Machine, Souls and Comms installation and clean HQ
startup require no harness packages, credentials or `harnesses` section. For a
Soul explicitly selecting Codex and Claude Code, merge this example into the
HQ home's `config.json`.
Preserve existing settings. The file must belong to the dedicated HQ account.
Use mode `0600`.

```json
{
  "harnesses": {
    "dir": "/Library/Application Support/ai.true-line.agent-bot-hq/ipc",
    "accounts": {
      "codex": "_codex",
      "claude-code": "_claude-code"
    }
  }
}
```

At a suitable break in active work, restart the installed LaunchDaemon with
`sudo launchctl kickstart -k system/ai.true-line.agent-bot-hq`. From the
configured owner account, run `node hq/main.mjs status --owner-control --json`
with the installed HQ release and its Node binary. In `hq.sockets.harnesses`,
check the account, adapter and socket path for each mapping. Each socket should
have mode `0660`, with HQ as owner and the harness account's private group.
Check `hq.launch.accounts` separately for launch availability. A connected
account still needs its admitted runtime's keyed proof to bind to the broker.

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

### Transfer a single-use macOS qualification proof

Use the dedicated paired HQ account and the Machine pin saved during verified
status. Generate a new approval plan first if the saved plan describes itself
as review-only. Existing review-only plans can still be read. For the new
approval plan, export its signed challenge:

```sh
node hq/main.mjs machine harness-qualification-run export "$plan_id" --socket "$socket" > "$challenge_file"
```

Transfer the original signed line to the owner's installed macOS reviewer.
The reviewer shows the exact candidate and native binary, disposable state,
fixed runner, test provider, and gate profiles before owner authentication.
Return the owner's proof to the same paired HQ account and submit it with:

```sh
node hq/main.mjs machine harness-qualification-run approve --challenge-file "$challenge_file" --proof-file "$proof_file" --socket "$socket"
```

An approved response records owner consent for this exact single-use plan.
Execution and evidence are separate. This command does not certify the adapter
or install a launch rule. To abandon a challenge, use
`cancel --challenge-file FILE --socket PATH` for the same operation.

### Review one protected Soul installation

Machine builds and saves the `soul-protected-launch-install` plan from the
reviewed local request. From the paired dedicated HQ account, first establish
the Machine pin with signed `machine status`, then export the saved plan's
signed owner challenge:

```sh
node hq/main.mjs machine soul-protected-launch-install export "$plan_id" --socket "$socket" > "$challenge_file"
```

The owner reviews the exact plan and digest in the signed challenge, including
the frozen `.soul` digest, runner and bridge accounts, installation and host
identity, source paths, measured definition and launch inputs, and Machine
public key. Return the purpose-bound owner proof to the same paired HQ account:

```sh
node hq/main.mjs machine soul-protected-launch-install approve --challenge-file "$challenge_file" --proof-file "$proof_file" --socket "$socket"
```

Use `cancel --challenge-file FILE --socket PATH` with the same verb to abandon
the challenge. Approval authorizes only the saved plan named in the proof.
Machine's root apply and installed receipt are separate steps; this handoff
does not establish physical acceptance or open protected launch.

For a v3 R-only install, the signed challenge additionally names the reviewed
R inventory digest, component release pins, source roots and resource limits.
The v3 plan seals R in Machine custody and defers the protected launch rule.
Use the same `soul-protected-launch-install` export, approve and cancel verbs;
the owner proof must cover the exact v3 plan and digest.

### Review one Soul bridge provisioning plan

Machine creates a separate `soul-bridge-provision` plan for each installation's
credential-sidecar role and fixed endpoint directories. Export its signed
challenge from the paired HQ account after pinning Machine status:

```sh
node hq/main.mjs machine soul-bridge-provision export "$plan_id" --socket "$socket" > "$challenge_file"
```

Review the bridge account, its UID, the linked runner identity, directory
ownership and modes, and the exact plan digest. Submit the owner's proof:

```sh
node hq/main.mjs machine soul-bridge-provision approve --challenge-file "$challenge_file" --proof-file "$proof_file" --socket "$socket"
```

Use `soul-bridge-provision cancel --challenge-file FILE --socket PATH` to
abandon a challenge. Machine's root apply and receipt remain separate.
