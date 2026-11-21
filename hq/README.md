# HQ skeleton

The first slice of [§9 PR 12](../docs/daemon-plugin-split.md#stage-1-local-vertical-slice-wp2wp4)
(#39): HQ core running on the SDK's plugin host ([sdk/](../sdk/README.md)),
beside the existing per-account daemon, which it leaves unchanged
(strangler). No dependencies; Node 20 or later.

```sh
node hq/main.mjs run      # foreground; state in $AGENT_BOT_HQ_HOME or ~/.agent-bot-hq
node hq/main.mjs run --plugins DIR       # also load installed plugins, pinned
node hq/main.mjs run --dev-plugins DIR   # load unpinned plugins; status says so
node hq/main.mjs status   # ask the running HQ, over the control socket
node hq/main.mjs souls    # admitted Souls and their runtimes
```

## What it does

| Piece | Module | Plan |
| --- | --- | --- |
| Durable store: the SDK's tables, blobs and receipts, written atomically to `store.json` (0600) in a 0700 directory. It refuses a wider directory and never overwrites a store it cannot read. | `store.mjs` | §3.2, §4.3 |
| Control socket (owner), admission socket (entry points) and member broker socket. The auth class is the socket, never a client field. Strict NDJSON. Registry refusals are common/v1 error responses; host refusals go in a separate `host_refusal` field. | `socket.mjs` | §7.1, §7.2 |
| Member broker socket ([§9 row 13b](../docs/daemon-plugin-split.md#49-the-member-broker-socket-stage-1)): `broker.sock`, whose frames go to the one plugin serving the broker (`ctx.broker.serve`). It binds a connection with `bind { runtime_id, channel_binding }` through hq-admission's `verifyBinding` and delivers later frames with `ctx.broker.deliver`; consumers authorize by the bound runtime. agent-comms ships the broker plugin; HQ alone refuses every frame with `host.no_broker`. | `hq.mjs`, `socket.mjs` | §4.9 |
| Harness accounts ([§9 row 16a](../docs/daemon-plugin-split.md#stage-2a-member-isolation-wp2), Linux and macOS; D7 as amended by platform PDR-0053): with `harnesses` in the config, each harness account gets its own broker endpoint, `<dir>/<account>/broker.sock`, mode 0660 in a 2750 directory of that account's private group, so the file system tells HQ which account is calling. Accounts are keyed by adapter ID and shared by the agents of every Soul on that harness; several adapters may name one account, which then has one endpoint. A runtime is bound at admission to the account of its role's adapter, and that is kept in the store. It then binds only from that account's endpoint and only with a keyed proof: `bind.challenge { runtime_id }` returns a nonce, and `bind { runtime_id, proof }` answers with HMAC-SHA-256 over it, keyed with the channel binding, which is never sent. Anything else is `caller_mismatch`. The endpoint proves the account, the harness credential; two agents in one account are told apart only by the proof, and are one trust domain to the host. A role whose adapter has no account stays on the shared socket. HQ verifies the directory layout and refuses to start on any other; the provisioner makes it. | `harness-accounts.mjs`, `admission.mjs`, `hq.mjs` | §9 row 16a |
| Agent launch ([§9 row 16b](../docs/daemon-plugin-split.md#stage-2a-member-isolation-wp2), Linux): HQ starts an agent in its harness account, as its parent, through the sudoers rule agent-bot-machine installs, in one fixed form: `sudo -n -H -u <account> -- /bin/sh -c '<shell>' sh <soul_id> <member_id> <command>`, where the fixed shell creates `$HOME/.agent-bot-hq/souls/<soul_id>/<member_id>/` at 0700 as that account and starts the command there; the IDs and the command are arguments, never part of the script. The child gets only the four `AGENT_BOT_SOULS_*` variables a request may set, `AGENT_BOT_SOULS_BROKER` set by HQ to the account's own endpoint, and a fixed `PATH`. On the admission socket, the connection that owns the runtime sends `launch { runtime_id, command, env }` and gets a launch ID and a one-time token (30 seconds); `launch.attach { launch_id, attach }`, the first and only request on a new connection, starts the agent and makes that connection its stdin and stdout. One launch runs per Soul and agent. sudo runs detached. Before the agent starts, the fixed shell reads its own process group from `/proc/self/stat` and prints `agent-bot-hq-launch pgid <n>` on stderr; HQ takes the first such line as the launch's group and does not log it (no marker within five seconds of a stop: sudo's pid). `launch.stop { launch_id }`, a closed connection and HQ's own stop close the agent's stdin and send `kill -TERM -<pgid>`, then `kill -KILL -<pgid>` after a grace period, as the account; an agent that exits on its own gets the KILL to its group. Nothing else is signalled: a process that leaves its group (setsid, or a group of its own) is not stopped by HQ and keeps running in the harness account, whose agents are one trust domain; containing it needs a cgroup and so root. A failed signal, or sudo still running after the KILL, leaves the launch `uncontained`: its slot is held until HQ restarts and its receipt says `contained: false`. Account homes are verified at start (a directory owned by the account, mode exactly 0700); a bad one refuses the start. HQ asks sudo once per account whether the rule covers it; without it HQ serves row 16a and refuses launch for that account. `status` lists launches and each account's readiness, never commands or environments; receipts `hq.launch`, `hq.launch.refused` and `hq.launch.exited` carry a digest of the command, never the environment or the token. Agent stderr goes to HQ's log, clipped and rate limited, with the agent's token replaced by `[redacted]` first. If sudo cannot be run at all (missing or not executable), nothing starts: the exit receipt says `reason: 'spawn-failed'` with the error code in `spawn_error`, the slot is freed, and launch in that account is unavailable until HQ restarts. Any other spawn error (the process limit, for example) gives the same receipt and fails that launch only. | `launch.mjs`, `harness-accounts.mjs`, `socket.mjs`, `hq.mjs` | §9 row 16b |
| Owner sessions: one per control connection, recorded in the store and closed on disconnect or at the next start. | `hq.mjs` | §7.2 |
| Profile reporting: the profile in force, with the reasons a stronger one is not. Never `managed-protected` before §9 PR 16. | `profile.mjs` | §3.3, R8 |
| Task service ([§9 PR 13](../docs/daemon-plugin-split.md#stage-1-local-vertical-slice-wp2wp4), #40): `task/v1` records in the store, the `task-v1` provider (platform PDR-0024). Members commit through `task.commit` with their runtime, over the admission connection or brokered with their bound runtime; only the task Soul's current lead at the current epoch and lease commits, and a specialist's request is recorded as a proposal (T20). CAS on the expected revision (`revision_conflict`), one commit per operation ID with the stored receipt for an exact repeat (T05), write-scope exclusion (`write_scope_conflict`, unless listed in `concurrentWriters`), and offers whose requester is their authenticated source (T04). The owner offers a task with `tasks.offer` and reads `tasks.list` and `tasks.get`. A bound member reads its Soul's waiting directives with the `task.directives` kind, each a wire/v1 directive-or-query record for a task the owner or HQ offered, and one of its Soul's tasks with `task.get`. A peer's offer is never a directive. | `tasks.mjs` | §4.2, 0.4 §7 |
| hq/v1 Hello (with the admission result), Admit, Equip, Ready and Lease, checked against the pinned schemas in both directions. Versions are N/N−1 (T14). The owner's config holds the accepted definitions, there is one current installation epoch per Soul (T15), and leases have generations and renewal sequences. Runtimes are bound to the admitting connection. | `admission.mjs` | §4.2, 0.4 §5 |
| Bootstrap requires the paired HQ channel and a current device record bound by Machine. HQ enters safe mode if verification fails. | `hq.mjs`, `machine-device.mjs` | §4.4, §4.7 |
| Installed plugins: one directory per plugin, with `plugin.json` (static fields) and `plugin.mjs`. Before any plugin code runs, the tree's sha256-manifest-v1 digest must match its pin in [`governance/plugins.json`](../governance/plugins.json), and the set must resolve from `plugin.json` alone. The code's `definePlugin` fields must then equal `plugin.json`. Symlinks are refused. A refused plugin gets a `hq.plugin.refused` receipt and a reason in status, and its dependents are refused with it. `--dev-plugins` skips the pin and status always names it. Core names (`hq`, `hq-admission`, `hq-tasks`, `hq-notices`) cannot be taken. | `plugins.mjs` | §4.1, §4.5 |
| Machine supplies the public P-256 identity and purpose-specific signatures. HQ verifies the pinned channel reply and the corresponding device signature before use. | `machine-channel.mjs`, `machine-device.mjs` | §3.2, §4.4 |
| HQ starts the device-code grant over HTTPS, verifies the issuer-signed approved response and forwards the exact receipt for durable admin binding. The owner can retry a verified pending receipt after a lost reply. | `enrollment.mjs` | §4.4, §4.7 |
| The existing daemon is probed and reported. It is started only when `legacy.supervise` is on, and never stopped. | `legacy.mjs` | §8.2 |

## Identity-service link (row 10)

HQ owns HTTPS. Machine/keyd holds the administrator's device and DPoP signing keys. HQ verifies the issuer's response signature, key ID and exact request nonce before parsing each response. The token exchange binds the sender-constrained token to an administrator-owned session. The API client refuses operations without a matching purpose-specific proof. The paired provider supports a bodyless `GET /api/daemon/whoami` for its own enrolled device. HQ passes Machine the bound session selector, verifies the returned proof against its token and checks the device ID in Identity's signed reply. Issuance reconciliation still requires a proof for a specific authorized task and operation. A verified token alone grants no lookup, notice access or credential issue. SDK approval records can be checked against the current public device key. A new approval decision stays pending when the administrator has no independently verified owner decision. A verified 401 invalidates the cached session token without replaying the request.

[`governance/server-keys.json`](../governance/server-keys.json) is a release
pin, separate from enrollment's transitional `identity/server-key.json`.
The transport never learns trust from the network. Each public key has one
`kid`, `x`, RFC3339 `notBefore` and `notAfter`, and `status` (`active`, `next`
or `retired`). A pre-published next key is usable only inside its interval;
retired, unknown and out-of-window keys refuse. Deploying rotation requires
the reviewed release pin first.

## macOS harness launch readiness

For each configured account, HQ checks the Machine installation plan digest,
the recorded launcher and sandbox, the admitted adapter and UID, and sudo's
noninteractive permission for the exact supervisor command. Status lists the
installed adapters separately from those available for launch. Launch also
requires independently verified Darwin package qualification for that exact
adapter. The production verifier has no qualified adapters yet.

In the owner status report, a grant verification failure means HQ could not
validate the installed launch files. Once it can verify the grant, HQ lists the
matching configured adapter IDs in `installed_adapters`, including when it
cannot confirm supervisor permission. After that permission check succeeds,
`adapters` lists the IDs that also passed package qualification. The reason
identifies missing mappings and missing qualification separately. Granting
supervisor permission alone cannot qualify a package. An account can report
partial readiness while its qualified adapters remain available.

A qualified launch hands the supervisor a private stdin header followed by
ACP. Closing stdin requests shutdown of that launch's process group. HQ holds
the slot as uncontained unless the supervisor confirms group closure or an
explicit refusal before spawn. Per-launch member authentication and retirement
remain under Souls and Machine respectively.

## Linux owner control under the dedicated account

The service manager can pass a Unix stream listener to `hq/main.mjs run
--owner-account NAME` running as `agent-bot-hq`. The systemd socket unit
owns the listener lifecycle: `ListenStream=/run/agent-bot-hq/control.sock`,
`FileDescriptorName=owner-control`, `SocketUser=NAME`, `SocketMode=0600`,
and `Accept=no`. The parent directory must be root-owned and closed to
writes from group and others. The service requires one descriptor for its
own PID. HQ checks its type, listening state, bound path, and the socket
file's owner and permissions before accepting it.

Run `node hq/main.mjs check-owner-control` to check Linux support. It
requires the system interpreter at `/usr/bin/python3` with the standard
socket module. For each incoming connection a short-lived unprivileged
helper reads `SO_PEERCRED` from the connected stream. Only the UID of
the configured owner opens an owner session. The owner uses
`status --owner-control`, `souls --owner-control`, or
`enroll --owner-control` without traversing HQ's private home.
HQ cannot rotate the Machine device key through its control socket or offline CLI. Admission and the broker
continue to use their existing endpoints. The installer, machine-key
pairing and retirement of the old key are tracked in issue #88.

## State directory

`config.json` is optional and written by the owner. HQ refuses it if group or
others can write it, and refuses unknown keys:

```json
{
  "acceptedDefinitions": { "agent_<uuid>": ["sha256:<64 hex>"] },
  "leaseTtlMs": 60000,
  "concurrentWriters": ["workspace:shared"],
  "standalone": false,
  "legacy": { "supervise": false, "probeIntervalMs": 30000 },
  "enrollment": { "source": "hq", "server": "https://agents.true-line.ai" },
  "signer": { "backend": "machine" }
}
```

`node hq/main.mjs enroll --harness NAME` starts the grant and displays the code to approve. The enrollment server must match the administrator-configured origin. The service must support the signed enrollment receipt. Legacy local enrollment records cannot authorize the Machine-held identity.

A routine Machine restart preserves enrollment. Human-readable
`node hq/main.mjs status` shows when a grant is awaiting owner approval, failed,
or approved and waiting for HQ to restart. Once HQ verifies the saved
enrollment after restart, the device line reports `enrolled`. Use
`status --owner-control` for a dedicated HQ service. Use `status --json` to
check which signer HQ can reach before retrying an operation.

If HQ started in safe mode because it could not connect to its paired
Machine, owner status rechecks the original local pairing and saved device
enrollment. When both verify, status asks the owner to restart HQ. The JSON
report includes `hq.signer.restart_required` in this case. Admissions stay
closed until HQ completes its normal startup checks after the restart.

If an HQ is compromised, the Homebrew administrator can run `managed-machine daemon revoke-hq` to stop new local signing for that pairing. The deny record persists across restart. To withdraw the enrolled device's service access as well, the owner can revoke that device on the Identity service's [Devices page](https://agents.true-line.ai/devices). The service rejects subsequent device requests and retries upstream revocation for tracked GitHub installation tokens. Legacy installation tokens expire within one hour. Issuer details are in the [Identity API guide](https://github.com/true-line/agent-bot/blob/e001bf270d2cd45cd0c1919e5f4caae40e22fe66/docs/api.md).

`notices` opts the agent-comms broker plugin into explicit identity-service
queues, for example `{ "harnesses": ["example-codex-agent"] }`. HQ validates
the queue list, count, poll/lease intervals, storage caps, retention and wake
class (`none` or `notify`), then passes ingestion settings to that plugin. Without
the section, ingestion is disabled. The broker owns the custody and recovery
behavior; see [agent-bot-comms's notice ingestion](https://github.com/true-line/agent-bot-comms/blob/main/docs/hq-notices.md)
and [HQ issue #123](https://github.com/true-line/agent-bot-hq/issues/123).
Optional owner-local `notices.scopes` binds an exact accepted assignment to a
remote harness and repository, frozen per runtime. Those mappings stay with
admission; see [HQ notice scope](../docs/hq-notice-scope.md) for configuration,
the trusted guard and rollout dependencies.

The default custody provider uses the local signed Machine channel. The dedicated HQ account is preferred. An ordinary account requires its own explicit Machine pairing for the exact UID and remains cooperative. Only the dedicated account can read members plans or perform paired service recovery. A role's channel key authenticates its calls. It is separate from the administrator's P-256 device key.

The owner permits HQ-local Secure Enclave **signing only** for an explicitly standalone installation in a dedicated HQ account with verified absence of Agent Machine. The administrator declares that no custom Machine installation exists and pins the verified command-line helper for the dedicated account. The helper enforces that declaration for each operation. Machine outage, revoked pairing and an absent socket leave paired custody unavailable. Before opening the Keychain, the native helper checks standard Apple Silicon and Intel Homebrew executable paths, including unlinked kegs. It verifies the Machine executable against its Apple Developer ID chain, team and identifier without executing it. A missing path, an invalid signature or an unreadable installation cannot authorize local signing. Its Developer ID signature and dedicated-account checks establish executable and account identity. A later Machine installation retires the declaration before Machine starts. An older installer requires prior explicit retirement. See [standalone installation and release qualification](../docs/daemon-plugin-split.md). The software and hardware qualification fixtures do not establish installation eligibility. Preserve existing pairing and custody state for authorized migration.

The paired integration test uses the real HQ client, Machine handler and keyd protocol with generated software keys and a local test issuer. From the matching Machine source, run `go test -c -o "$fixture_dir/machine-fixture" ./internal/daemon` with an existing private temporary directory. From HQ, run `node tests/machine-device-interop.mjs "$fixture_dir/machine-fixture" "$machine_src/tests/fixtures/build-keyd-device-interop.sh"`. The test covers enrollment, signed token binding, unavailable operation authority, outage, restart, and revocation. Physical hardware and standalone installation remain separate qualification steps.

The HQ state directory includes `control.sock`, `admission.sock` and `broker.sock`. Public enrollment records live in `identity/`. On an upgrade from local signing, `status` and `status --json` name any local signer key, signer pin, current or previous enrollment record, and pending receipt the role can see. They report inspection failures separately. The diagnostic reads file metadata only. An earlier HQ could create its key and pin at startup before enrollment. Missing records leave enrollment history unconfirmed. The issuer pin in `identity/server-key.json` can be saved before the service grants enrollment and does not establish device enrollment.

If the upgrade pauses, preserve the existing pairing, owner pin, signer and enrollment records. Check the device’s enrollment history with the identity-service administrator before authorizing a custody change. A signed status from the paired Machine verifies its channel. Replacing an established device identity requires a separately approved transition.

The paired integration test also drops Machine’s successful binding reply and restarts both HQ and Machine. The owner CLI must finish enrollment from the original pending receipt without contacting the issuer. To run this case offline on macOS, use the command above from the extracted Darwin archive with `HQ_INTERIM_OFFLINE=1` and cached Machine Cargo dependencies.

On macOS the dedicated HQ account requires an explicit `harnesses.dir` of
`/Library/Application Support/ai.true-line.agent-bot-hq/ipc`. Machine provisions
this directory and one private group directory per configured harness. HQ
checks the connected peer UID with `getpeereid` before opening its broker
session. The keyed bind still authenticates the admitted runtime. macOS
harness process launch and protected-profile qualification remain pending.

On Linux, `harnesses` gives each harness its OS account, one per harness
credential ([platform PDR-0053](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0053-soul-life-and-agent-replace-member.md)):
`{ "dir": "/run/agent-bot-hq/members", "accounts": { "<adapter ID>": "<account>" } }`.
The default directory's name predates PDR-0053. The 16a key `members` is
refused. An agent's working state is in its own directory in its harness
account's home, outside this directory, and an agent HQ starts there can
read nothing in this directory, connect to none of its sockets, and run none
of HQ's tooling against it (T02, run in CI on two throwaway accounts).
Launches are in memory only: after a restart nothing runs under HQ.

The Darwin interim archive includes the production agent-comms broker under
`vendor/plugins/agent-comms`. Its source commit and plugin digest are pinned
in `governance/darwin-broker.json` and recorded in the built archive’s
`governance/interim-release.json`. After the first source fetch, the builder
can use its local Comms Git cache offline. To run the CI archive wrapper
without network, also set `HQ_CONTRACTS_DIR` to an already verified contracts
tree. To build from an existing Comms checkout or
bare repository, set `HQ_COMMS_REPO` to its absolute path. The builder checks
out the pinned commit into a fresh directory and verifies the packaged bytes
before adding the broker to the archive’s `governance/plugins.json`.

## Interim account: D4's stated risk

D6 puts HQ in its own account (`_agent-bot-hq` on macOS, `agent-bot-hq` on
Linux), which agent-bot-machine creates in its S6 slice. Until that account
exists, HQ runs in the owner's `user` account. D4's stated residual risk
then covers HQ too: any process in `user` can read HQ's store and connect
to every socket, and so can every agent that runs in `user`, which is
every agent unless HQ starts it in a harness account (row 16b). The file mode is the only access check,
because Node has no peer-credential API. HQ reports `managed-cooperative`
and names the account as a reason. Machine keeps the privileged device key under administrator custody. Same-account processes share the role-channel trust boundary. The protected-host qualification remains pending.

## Not in this slice

- The rest of the Linux protected profile (§9 rows 16c and 16d). Rows 16a
  and 16b make HQ tell harness accounts apart and start agents in them; HQ
  does not create the accounts or install the sudoers rule (that is
  agent-bot-machine's), and it does not block their network (16c). HQ
  still reports `managed-cooperative`. Without `harnesses` the reason is
  that agents of every harness share one account; with it, the reasons name
  any admitted agent whose harness has no account and any account HQ cannot
  launch in. HQ's own account, the qualification and a hardware key remain
  stated reasons. The Soul entry point in agent-bot-souls does not start
  agents through HQ yet; an agent's working directory is not captured into
  its Soul's package; a launched agent is not stopped when its runtime's
  lease expires or is superseded; HQ does not clean up after a crash, so an
  agent left by a crashed HQ runs on until the owner ends it; and a process
  that leaves its launch's group is not stopped by HQ (containing it needs a
  cgroup, which needs root).
  The agent-comms broker plugin
  ([agent-bot-comms#312](https://github.com/true-line/agent-bot-comms/pull/312))
  and the Soul runtime
  ([agent-bot-souls#3](https://github.com/true-line/agent-bot-souls/pull/3))
  bind by the challenge. Nothing creates the endpoint directories yet; that
  is agent-bot-machine's.
- Signed plugin packages and plugin upgrade. The pins file is the only
  trust anchor, and changing it is a reviewed change to this repository.
- Physical qualification of administrator-held keys, authorized device rotation, and operation-scoped protected credential use. The standalone Secure Enclave exception requires independently verified installation evidence.
- The HQ account, the peer-credential check and the service unit (#88,
  after agent-bot-machine S6), and the Windows named pipe (#89).
- A soul-contracts schema for the hq/v1 request envelope and for the
  Ready/Lease reply. The framing here is HQ's until soul-contracts specifies
  them.

## macOS LaunchDaemon owner control

The Darwin source artifact supports `check-owner-control`, which prints
`{"capability":"darwin-owner-control/v2","launch_diagnostics":"darwin-hq-launch-exits/v2"}`
when the system Ruby can load the native launchd API and read a kernel peer UID
on a Unix socket. The Darwin archive records the same transport version in
`governance/interim-release.json` under `owner_control_capability`. Version 1
artifacts use `/private/var/agent-bot-hq-control.sock`. Use the matching
release’s owner CLI for an installed service. The launch diagnostics
version is independent of the transport version. A system
LaunchDaemon under `_agent-bot-hq` takes these program arguments in order:

```text
/usr/bin/ruby
--disable-gems
<verified HQ artifact>/helpers/darwin-owner.rb
launch
<approved absolute Node path>
<verified HQ artifact>/hq/main.mjs
run
--home
<private HQ state>
--owner-account
<owner login>
```

Configure a single launchd `Sockets` dictionary named `owner-control` with
`SockType=stream`, `SockPathName=/Library/Application Support/ai.true-line.agent-bot-hq/owner-control.sock`
and `SockPathMode` integer 438 (0666). The installer provides the
`ai.true-line.agent-bot-hq` directory as root:wheel, mode 0755. HQ verifies
the root-managed ancestry before using the launchd-owned socket. The helper
checks in with `launch_activate_socket`, validates the returned listening stream,
and replaces itself with Node. Before
accepting an owner session or reading its requests, HQ checks the connected
peer with Darwin `getpeereid` against the configured owner UID. The owner can
run `status --owner-control --json` and inspect `hq.sockets.ownerControl`.
The dedicated account retains its private state directory and control socket.


### macOS launch exit statuses

When the verified artifact advertises `darwin-hq-launch-exits/v2`, Machine can
interpret the approved job's `launchctl print` last exit code using this table.
Version 1 covers exits 80 through 87. Version 2 also distinguishes native
socket activation result 159.
Each value identifies the startup check that failed. It contains no login,
key, path, or child output.

| Exit | Startup check |
| --- | --- |
| 80 | The native launcher could not verify the dedicated role or its launch arguments. |
| 81 | The native launcher could not complete launchd socket check-in. |
| 82 | Launchd returned a descriptor count other than one. |
| 83 | The native launcher could not open or verify the inherited Unix stream descriptor. |
| 84 | The native launcher could not verify the protected public socket or its directory metadata. |
| 85 | The native launcher could not verify the launchd-bound address and its provenance. |
| 86 | The native launcher could not execute the approved Node runtime. |
| 87 | After exec, HQ could not activate the inherited owner-control listener. |
| 88 | Native socket activation returned 159. On macOS 27.0.1 (26A434), `launchctl error posix 159` reports `Sandbox restriction`. |

At launch, the helper waits up to three seconds if the exact public socket
is initially absent under its verified root-owned directories. Every sample
checks those directories again. Other errors and existing entries with
unexpected metadata fail immediately. Later descriptor checks still use a
single metadata sample.

Use the numeric observation alone for an unknown code, an unrecognized
diagnostics version, or an older artifact. Exit 1 can come from several
startup or runtime failures. A launchd signal is a separate observation.

### Task decision receipts

HQ commits each new task offer, lead commitment, specialist proposal, owner or
HQ wait/cancel, and deadline expiration with its task rows and operation key
in one store publication. An exact replay returns its stored result without
adding another decision receipt. Refusal receipts remain a separate audit
event because no task decision was committed. Older stores may contain task
decisions without matching receipts: HQ does not infer or synthesize historical
audit evidence during upgrade or restart. A custom SDK host without the grouped
receipt capability retains the prior separate task-store and receipt append
path; it does not claim cross-store atomicity.
