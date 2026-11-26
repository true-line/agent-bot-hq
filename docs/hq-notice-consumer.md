# Scoped notice consumer

[HQ #130](https://github.com/true-line/agent-bot-hq/issues/130) tracks the
host consumer for the shared
[notice contract](https://github.com/true-line/soul-contracts/blob/v0.6.0/schemas/hq/v1/notices.md).
The contract owns fields, bounds, compatibility and refusal codes;
[Accepted PDR-0062](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0062-hq-notice-scope-and-legacy-consume-one.md)
owns the scope and handoff decision.

## Host integration

`hq/notices.mjs` exports `noticesPlugin({schemas})`, requiring the shared
`notice-query` and `notice-result` schemas supplied by its host. As with
`tasksPlugin`, schema registration is metadata; the consumer explicitly
executes validation. It checks discriminator, capabilities, closed request
shape and operation/kind agreement before entering
[the trusted admission guard](hq-notice-scope.md). Only broker metadata
supplies the runtime ID.

Inside that guard, the consumer delegates local mailbox mechanics through
`ctx.deps['agent-comms'].notices`:

```js
await notices.peek({ harness, repo, count });
await notices.consumeOne({ harness, repo }, prepareResult);
```

The comms service owns filtering, durable sequence ordering, deduplication and
atomic consumption. It returns shared-shaped sanitized notice arrays, without
storage metadata or upstream credentials. The consumer performs a second
schema/repository/byte check before returning them.

`prepareResult(notices)` is a required **synchronous host callback** invoked
by `consumeOne` inside its mailbox transaction, after selection and sanitation,
including an empty selection, and before a consumption tombstone. It builds
the complete correlated reply and validates its schema, scope and canonical
byte budgets. A throw aborts the transaction; a thenable is refused by comms.
Comms returns the same deeply frozen notice array after durable commit, and
HQ returns the prepared reply. This avoids consuming a notice only to discover
that its reply cannot be validated or framed. These are trusted internal
functions, never agent request fields.

Read-only peek can drop a trailing suffix to fit the full reply budget;
individual source fields are never truncated to manufacture a fit. A missing
or incompatible scoped mailbox is an explicit `host.plugin_degraded` refusal.
This plugin declares no identity-service routes or network service; there is
no upstream fallback, automatic replay, directive or lifecycle action.

## Released contracts and validation

The normal HQ schema loader verifies the complete `v0.6.0` release pin in
`governance/soul-contracts.json`, then loads both notice schemas. Normal host
construction registers `hq-notices` alongside admission and tasks. It requires
no owner notice configuration for ordinary admission or task operation.
Without an existing enrolled, frozen notice scope, requests refuse before any
mailbox effect. Comms ingestion remains disabled without its existing explicit
configuration. The production plugin bundle is unchanged.

`tests/hq-notices.test.mjs` runs the released shared notice corpus and guarded
consumer cases through default host registration, including malformed records,
freshness, missing mailbox, source bounds and full-result preparation before
consumption. `tests/hq-notices-comms.test.mjs` runs the real comms broker and
mailbox from the immutable test-only dependency in
`tests/support/comms-checkout.mjs`, with real HQ admission, challenge-bound
sockets and durable storage. It proves custody before upstream acknowledgment,
read-only peek, one-at-a-time local consumption, withheld repository metadata,
refusal before effects, restart/redelivery tombstones, callback rollback and a
private array that fits while its complete correlated result requires suffix
trimming. Tests use a signed fake upstream; no live queue is activated.

```sh
node scripts/soul-contracts.mjs verify
npm test
```

These checks are component integration evidence for
[HQ #130](https://github.com/true-line/agent-bot-hq/issues/130) and
[comms #317](https://github.com/true-line/agent-bot-comms/issues/317).
They do not close those parents or prove actual identity MCP composition,
exclusive upstream custody, mixed-version rollout, alias parity or T14
readiness. Production queue activation and owner settings remain separate.
