# Bound member-query port preparation

[HQ #134](https://github.com/true-line/agent-bot-hq/issues/134) prepares the SDK
part of [#131](https://github.com/true-line/agent-bot-hq/issues/131).
Ownership follows Accepted
[PDR-0027](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0027-hq-identity-authority-lives-in-agent-bot-daemon.md);
notice handoff and the lost-response limitation follow
[PDR-0062](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0062-hq-notice-scope-and-legacy-consume-one.md).

## Member-facing capability

`createMemberQueryPort(driver)` returns a frozen object with only
`request(kind, buildPayload, options)`:

```js
const reply = await queries.request('notices.peek', (freshness) => ({
  contract: 'hq/v1',
  request_id: nextRequestId(),
  operation: 'peek',
  required_capabilities: ['notices-v1'],
  ...freshness,
}), { replay: 'read-once' });
```

`buildPayload` runs synchronously for each attempt. It receives a fresh frozen
object with exactly `installation_epoch` and `lease_generation`, each a
positive safe integer. It receives no runtime ID, binding material, private
driver object or credential. An async builder is refused before sending.
The returned payload is cloned before it reaches the captured request
function. This generic helper does not replace the operation's shared
request/result validation, correlation checks or transport framing.

The default replay policy is `never`. `read-once` permits one reconnect and
one rebuilt request only for `task.get`, `task.directives` and `notices.peek`,
and only when the private driver's synchronous classifier returns exactly
`true` for the first send failure. A second failure propagates. Builder,
capture and reconnect failures do not trigger another attempt.

Every other kind, including `notices.consume-one` and `task.commit`, gets at
most one send even if its caller supplies `read-once`. No classifier or
reconnect runs for those kinds. Existing task commitment recovery remains in
its operation-specific owner; this helper does not add replay or idempotency.
The bound is a count of attempts; connection deadlines and cancellation remain
the transport owner's responsibility.

## Private driver contract

The transport owner constructs the port and passes only the returned
capability to member surfaces. It supplies:

```js
{
  capture(),                          // captured pair, or a promise for it
  reconnect(captured, error),          // replacement pair, or a promise
  isRetryableReadFailure(error, captured), // synchronous boolean
}
```

Each captured pair is a frozen plain object:

```js
Object.freeze({
  freshness: Object.freeze({ installation_epoch, lease_generation }),
  request: (kind, payload) => boundConnection.request(kind, payload),
});
```

The `request` closure must capture the **same concrete authenticated
connection** whose bound runtime produced `freshness`. It must never look up
a mutable global `broker` when called. `capture` publishes a pair only after
the transport owner's authentication and binding succeed. The SDK validates
the pair's shape and copies only epoch/generation for the builder; it cannot
prove that an arbitrary driver's closure used the right connection.

`reconnect` receives the failed pair. If another operation has already
published a newer binding, the owner reuses that pair without destroying it.
Otherwise it refreshes the failed current binding, completes authentication,
and returns its replacement pair. Concurrent capture/reconnect publication
must be serialized or compare the failed pair with the current one.

The classifier must recognize failures from the owner's authenticated
transport/refusal type. It may allow validated transport failures,
`lease_expired` or `stale_epoch`; an arbitrary object with a matching `code`
does not establish provenance. Scope, caller, schema, version and capability
refusals do not recover. A thrown, asynchronous or non-boolean classifier
result fails closed and preserves the original send failure.

## Evidence and remaining integration

`checkMemberQueryPort(createPort)` runs portable semantic checks using an
instrumented private driver; omitting `createPort` checks the SDK factory.
It reports `{ok, results}` like the existing plugin conformance helper.
The checks exercise pairing across rebinding, freshness reconstruction,
bounded read recovery, destructive/unknown-kind non-replay, private-field
non-exposure and refusal before sending on builder failure. It does not
certify a real provider's challenge/bind logic or secret custody.

`tests/sdk-member-query.test.mjs` additionally covers overlapping requests and
reconnection, invalid/mutable captures, replacement epoch changes, invalid
options, classifier exceptions/async results, and capture/reconnect failure.
A deliberately faulty port that silently opts reads into replay fails the
portable checks.

This preparation creates no network connection, IPC operation, authority
service or member-surface executor. It changes no default plugin loading,
shared schema, error registry or contract release pin. The Soul runtime still
needs to adapt its existing authenticated transport and distribute the real
SDK implementation. Identity then needs an actual supported composition path
that supplies this capability to its member adapter/MCP invocation. Those
provider and wiring tests remain necessary; registering declarations or
injecting this pure port into a leaf test does not prove end-to-end wiring.
Closing #134 alone does not close #131, #130 or the alias tracker #13.
