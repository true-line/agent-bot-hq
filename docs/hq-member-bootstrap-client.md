# Shared member bootstrap client

[HQ #136](https://github.com/true-line/agent-bot-hq/issues/136) provides the
shared mechanical client needed after the query port in #135. The remaining
consumer pin/removal and actual member/MCP composition are tracked under
[#131](https://github.com/true-line/agent-bot-hq/issues/131).

## Existing local socket protocol

`sdk/local-socket-client.mjs` and `sdk/local-socket-lines.mjs` extract the
existing Soul runtime client from `lib/hq-client.mjs` and `lib/ndjson.mjs` at
Souls commit `2097b8dc129737df23ae1fb1f8dc30eb4f7d8033`. That immutable
[Souls PR #10](https://github.com/true-line/agent-bot-souls/pull/10) source
candidate passed parent and independent technical review before extraction;
it is source provenance, not a release claim. The SDK module takes
an explicit verified-contract adapter instead of importing the Soul runtime's
loader. Schema path references remain references to shared records.

```js
const connection = await connectHq(socketPath, { contracts });
try {
  const reply = await connection.request(operation, payload);
} finally {
  await connection.close();
}
```

`contracts.record(schemaPath, value)` synchronously validates a record against
the installation's verified shared release and throws on invalid input.
`contracts.admission(result, hello)` synchronously validates admission and its
negotiation/correlation with the original Hello. Both functions are required
before the client opens a socket. The SDK client provides no permissive
fallback, network contract fetch or loader override.
Every validation invocation must finish synchronously. A returned promise or
thenable is observed for rejection and refused immediately, before an outbound
send or inbound result acceptance; the client never awaits validation. Normal
synchronous validation errors retain their original identity.

The existing local API uses one strict JSON record per line, a 1 MiB line
bound, and fatal incremental UTF-8 decoding. Requests retain
`{id, op, payload?}`; replies retain `{id, ok, result}` or the existing
`refusal`/`host_refusal` alternatives. Duplicate keys, a malformed envelope,
an unsolicited ID, invalid shared response, invalid UTF-8 or a truncated line
poison the connection and refuse pending requests. The original validation
failure is preserved for the affected request. No reconnect or resend occurs
in this socket client. A lost reply has an unknown outcome.

This is the existing local broker/admission/member socket transport from
[the HQ plugin contract §4.9](daemon-plugin-split.md#49-the-member-broker-socket-stage-1).
It does not implement comms' routed wire/v1 framing, sealing, mailbox or
relay. It adds no generic broker envelope or shared schema; the separate
[soul-contracts #34](https://github.com/true-line/soul-contracts/issues/34)
work remains separate.

## Usable member bootstrap

The root SDK export and `@agent-bot/sdk/member` export provide:

```js
const member = await connectMemberQueries({
  memberSocket,  // existing Soul entry point's member socket
  memberToken,   // existing per-member token, held only in memory
  brokerSocket,  // optional existing per-account broker endpoint
  contracts,    // required verified-release validation adapter, as above
  signal,       // optional AbortSignal created before awaiting bootstrap
});
try {
  const result = await member.queries.request('notices.peek', (freshness) => ({
    contract: 'hq/v1', request_id: nextRequestId(), operation: 'peek',
    required_capabilities: ['notices-v1'], ...freshness,
  }), { replay: 'read-once' });
  // The operation adapter still validates the full reply and correlation.
} finally {
  await member.close();
}
```

This opens the existing member socket and authenticates its `hello` with the
provided member token. The first request lazily fetches the entry point's
current `runtime`, validates binding metadata, completes the existing
`bind.challenge`/HMAC-SHA256 `bind` exchange, and publishes one completed
connection/freshness pair. No raw-binding fallback exists. Concurrent capture
and reconnect use the reviewed provider's single-flight publication; a late
failure from a retired pair reuses the newer pair. A failed capture or bind
publishes nothing. Closing aborts pending entry/bind work and current,
candidate and retiring connections; repeated close calls share completion.

An optional `signal` also cancels construction before a facade exists. Create
its controller before awaiting bootstrap, pass the signal, and abort it on
MCP EOF/shutdown. Every entry and broker socket uses Node's `addAbortSignal`
stream helper to cancel the native socket; an already-aborted signal opens
nothing. Aborting rejects
pending hello/runtime/bind/query work, closes the corresponding connections,
and prevents later capture, reconnect or publication. The caller's abort
reason is preserved. Native socket abort listeners are removed on socket
close, including failed construction and ordinary close without abort.
Omitting the signal preserves the existing lifecycle. The SDK adds no timeout
or automatic retry policy.

After successful construction, callers still close the returned facade during
shutdown; abort and close are safe in either order. Cancellation after a
destructive request was sent may leave its outcome unknown. It never replays
that consume, acknowledges delivery or proves that no effect occurred.

The returned object is frozen and has exactly `queries` and `close`.
`queries` is the existing [query port](hq-member-query-port.md): it exposes
only `request`, gives synchronous builders a frozen epoch/generation copy,
and forces destructive/unknown kinds to one send even when a caller requests
read replay. A retryable freshness failure marks only its failed pair so a
later explicit call can repair it; that does not replay the failed destructive
call. Shared freshness refusals authorize recovery only when the local client
validated them against the shared error schema; an imitation host code does
not. No upstream operation, token minting or credential reference is added.

## Private transport-owner facade

`sdk/member-session.mjs` extracts the same reviewed provider lifecycle from
`lib/member.mjs`. Its `openMemberSession(options)` uses the same bootstrap
options, and exposes an integration facade for the transport owner:

- `capture()`, `reconnect(captured, error)` and
  `isRetryableReadFailure(error, captured)` implement the existing query-driver
  contract. Captures are recognized by a private WeakMap.
- `runtimeFor(captured)` returns frozen full runtime metadata with
  `channel_binding` removed. Unknown/forged captures are refused. `member`
  contains only the entry point's Soul ID, member ID and role.
- `requestOnce(captured, kind, payload)` preserves the same captured raw
  request path used by Souls' task-specific commitment recovery. It does not
  adopt generic-query invalidation or retry an operation.
- `entryRequest` delegates only the existing `route`, `note` and `handoffs`
  operations. `hello` and `runtime` stay inside bootstrap; this facade does
  not provide a binding accessor. `dropBroker` retains the existing owner's
  link-loss test hook, and `close` performs the shared cleanup above.

`BIND_CONTEXT` and `bindProof` retain their existing semantics so the Souls
consumer can reexport those helpers during adoption. This owner integration
facade is not returned by `connectMemberQueries` and is not an agent tool or a
new host service. Task-specific operation keys, replay/reconciliation and
task state policy are not moved into the SDK.

## Ownership and integration limits

The SDK code is an untrusted client library in the member process, not an HQ
host binary. Socket access and successful binding confer no authority beyond
what HQ checks on each request. HQ still owns admission, scope, freshness,
grants and credentials. The Soul runtime still owns member-token issuance and
revocation, supervision, admission renewal/replacement and task-specific
commitment recovery. Identity remains a member-surface client and imports no
Soul runtime plugin. See Accepted
[PDR-0027](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0027-hq-identity-authority-lives-in-agent-bot-daemon.md)
and [PDR-0062](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0062-hq-notice-scope-and-legacy-consume-one.md).

Consumer changes must vendor the reviewed SDK bytes and license with the
exact source commit and file hashes, then remove the duplicated mechanical
implementation. The Soul runtime's current vendoring checks tie that commit
to its HQ dependency pin and compare every vendored byte with the pinned
source. No unreviewed SDK tag or plugin-to-plugin import replaces that path.

Actual MCP composition additionally needs identity's own process to construct
the shared query client before its legacy daemon client, and the Soul ACP
launch to supply the fixed installed identity MCP command through its existing
stdio MCP-server slot. A declaration or injected leaf adapter is not this
process-level proof. It must preserve per-member launch constraints, fail
closed on missing/tampered installation or contract dependencies, and avoid
all direct-upstream fallback. This change does not select an arbitrary PATH
command, add a package loader or activate production notice custody.

`tests/sdk-local-socket-client.test.mjs` exercises the extracted client against
real HQ admission/Equip and raw socket faults, including concurrent request
correlation, malformed same-chunk replies, bounded UTF-8 decoding and lost
consume replies without resending.
`tests/sdk-member-client.test.mjs` adapts the reviewed provider regression
cases to the public bootstrap against real HQ admission, store and reference
broker sockets. It covers twelve concurrent first queries, stale binding
recovery and payload rebuilding, late old failures, a durable consume effect
whose reply is cut, invalid challenge/freshness, close during a pending bind,
failed replacement, later explicit repair, and imitation host refusals. Extra
owner-facade cases check foreign-capture rejection, full runtime redaction and
the raw-request/generic-invalidation distinction. Full Souls task commitment
compatibility still needs its consumer to vendor this SDK and remove its
original mechanics; these tests do not claim that adoption or MCP wiring.
`tests/sdk-member-cancel.test.mjs` adds real-socket cancellation cases for
already-aborted construction, silent hello, completion races, runtime/bind and
retiring/replacement work, pending consume, cancellation before its first send,
idempotent close and native listener cleanup without requiring an abort.
