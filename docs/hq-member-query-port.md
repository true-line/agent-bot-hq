# Bound member-query port

The HQ SDK supplies the query capability that Soul members use over an
authenticated connection. HQ retains authority over admission, scope,
freshness, grants and credentials. The notice handoff follows the accepted
lost-response policy.
[Member-query client (#131)](https://github.com/true-line/agent-bot-hq/issues/131) ·
[Authority (PDR-0027)](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0027-hq-identity-authority-lives-in-agent-bot-daemon.md) ·
[Notice handoff (PDR-0062)](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0062-hq-notice-scope-and-legacy-consume-one.md)

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

## Implementation and test evidence

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

The SDK port landed in [HQ #135](https://github.com/true-line/agent-bot-hq/pull/135).
The authenticated bootstrap client binds the port to a concrete connection
(#137), and the client accepts cancellation during bootstrap and requests
(#139). Souls adopted that client while retaining ownership of member tokens
and task commitment recovery.
[Port tests](https://github.com/true-line/agent-bot-hq/blob/f3c39d2a703085c14bc09f8f0042d048f30525dc/tests/sdk-member-query.test.mjs) ·
[Authenticated client tests](https://github.com/true-line/agent-bot-hq/blob/69505d72ba30dd6c8129397baadb3b0b3397fbbd/tests/sdk-member-client.test.mjs) ·
[Cancellation tests](https://github.com/true-line/agent-bot-hq/blob/42d6f5110019f4b7d835e139875b89a75230afe1/tests/sdk-member-cancel.test.mjs) ·
[Souls adoption](https://github.com/true-line/agent-bot-souls/blob/699ea4a02028a6219695e9a64d4e7cdf3836be01/lib/member.mjs)

Identity #1445 exercised the installed `agent-bot mcp` command with inherited
Soul member inputs. Its test starts HQ at Identity's SDK pin
`42d6f5110019f4b7d835e139875b89a75230afe1` and injects the notice consumer.
The first `take_inbox` returned the notice, the next returned an empty event,
and the mailbox retained the consumed record. Neither query contacted the
upstream service.
[Installed-process test](https://github.com/true-line/agent-bot-identity/blob/843b4433f397d5a3cc746fdc6f9110b6687d9444/tests/integration/hq-inbox-release-gate.test.mjs) ·
[Passing Identity CI](https://github.com/true-line/agent-bot-identity/actions/runs/43808462724/job/133104594419)

HQ #141 separately verified **default host construction** against the then-current
v0.5.0 notice schemas. The real comms broker tests
exercise durable custody before acknowledgment, scoped peek and consume, and
restart with a consumed record.
[Default-host tests](https://github.com/true-line/agent-bot-hq/blob/dd9480195881912c12c537f6ae49eb221ec18cbc/tests/hq-notices-comms.test.mjs) ·
[Passing HQ CI](https://github.com/true-line/agent-bot-hq/actions/runs/43793533198)

## Deployment evidence

HQ #13 subsequently recorded live handoff, lost-response and restart checks
for one Linux `managed-cooperative` cloud pilot with the installed MCP,
default HQ consumer and service-backed mailbox. Its acceptance applies to
that host, harness and repository. Additional harnesses and production
deployments need their own evidence. The platform records Stage 0 acceptance
separately.
[Cloud pilot acceptance](https://github.com/true-line/agent-bot-hq/issues/13#issuecomment-6927251608) ·
[Platform Stage 0](https://github.com/true-line/agent-bot-platform/issues/66)
