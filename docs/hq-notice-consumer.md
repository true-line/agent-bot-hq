# Scoped notice consumer preparation

[HQ #130](https://github.com/true-line/agent-bot-hq/issues/130) prepares the
host consumer for the shared
[notice contract](https://github.com/true-line/soul-contracts/blob/60c540ea71a720148f6733afc7b29fa1ec255753/schemas/hq/v1/notices.md).
The contract owns fields, bounds, compatibility and refusal codes;
[Accepted PDR-0062](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0062-hq-notice-scope-and-legacy-consume-one.md)
owns the scope and handoff decision.

## Prepared implementation

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

## Release and integration gate

The factory is **not included in HQ's default plugin set or main schema
loader**. The current exact contract pin remains `v0.4.1`, which lacks these
notice schemas. No substitute schema, development loader, environment
override or invented release pin is provided. Production callers must use
released schemas from normal digest verification.

The following remain open before default activation and closure of #130:

- Publish the reviewed shared contract release, update HQ's complete exact
  pin, and load the two schemas through the existing verifier.
- Integrate the reviewed comms scoped mailbox service from
  [comms #317](https://github.com/true-line/agent-bot-comms/issues/317), then
  exercise this consumer against that real durable implementation.
- Provide a supported bound member-query client and replay policy for the
  [identity compatibility slice](https://github.com/true-line/agent-bot-identity/issues/1441).
  Existing Soul member read recovery must not automatically replay a
  destructive consume operation after an unknown transport outcome.
- Review the upstream dedicated-device custody fence and mixed-version
  rollout together with the other slices. Local consumer validation does not
  prove exclusive upstream custody or enable production configuration.

`tests/hq-notices-preparation.test.mjs` confirms missing schemas refuse and
default HQ registers no notice kinds. The portable suite in
`tests/support/notice-consumer-cases.mjs` accepts explicit shared schemas and
fixtures from a test runner and exercises the actual HQ, sockets, broker and
admission guard with an instrumented mailbox service. It includes refusal
before effects, full-result preparation before consumption, malformed result
refusal, source byte boundaries and aggregate peek bounds. It contains no
schema copies and supplies no production loading path.

The explicitly test-only source runner verifies the clean checkout's full
reviewed commit and the 154-file `errors`/`fixtures`/`schemas` manifest with
HQ's existing `sha256-manifest-v1` implementation. It reads verified git blobs
rather than accepting arbitrary schema files. A fresh reviewer can run:

```sh
mkdir -p .cache
git -c credential.helper= -c core.hooksPath=/dev/null clone --no-checkout https://github.com/true-line/soul-contracts.git .cache/notice-contract-source
git -C .cache/notice-contract-source -c core.hooksPath=/dev/null checkout --detach 60c540ea71a720148f6733afc7b29fa1ec255753
node scripts/test-notice-consumer-source.mjs .cache/notice-contract-source
```

The public source checkout is test data only; disabling its checkout hooks
avoids enrolling that cache as a separate agent task. The runner supplies no
production schema path or environment override and never creates a tag or
changes `governance/soul-contracts.json`. A wrong commit, dirty checkout or
manifest mismatch refuses before registering the behavior cases.

This is source-level preparation evidence, **not** released-contract
verification or default activation. Normal `npm test` does not run the portable
source cases until release/pin integration explicitly connects them. The
reviewed source identity here must not be represented as a published release.
