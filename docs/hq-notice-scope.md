# HQ notice scope

[Accepted PDR-0062](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0062-hq-notice-scope-and-legacy-consume-one.md)
governs notice authority. This is the HQ implementation slice tracked by
[HQ #128](https://github.com/true-line/agent-bot-hq/issues/128).

The owner may add `scopes` to the existing `notices` configuration:

```json
{
  "notices": {
    "harnesses": ["example-codex-agent"],
    "scopes": [{
      "soul_id": "agent_0b3f1e2a-7c4d-4e8f-9a1b-2c3d4e5f6a7b",
      "definition_digest": "sha256:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
      "member_id": "m_lead",
      "adapter_id": "fake-adapter",
      "role": "lead",
      "harness": "example-codex-agent",
      "repo": "true-line/agent-bot-hq"
    }]
  }
}
```

The five assignment fields match exactly against a schema-checked Hello and
its owner-accepted definition digest. The example alone does not accept that
definition; `acceptedDefinitions` remains the existing admission policy.
Mappings are unique per assignment, bounded to 1024, and may name only a queue
in `notices.harnesses`. Repository spelling is retained; equality compares
ASCII case-insensitively. URLs, wildcards, missing repository names and extra
path components are refused. An adapter ID or OS harness account establishes
no remote queue authority.

HQ resolves a scope only when the current enrollment's `allowsHarness` proves
that harness in the private persisted enrollment record, with the current
signer key, key generation, storage and configured server. An unreadable,
malformed or revoked record grants no scope. The default legacy enrollment
has no such proof and grants no notice scope; normal admission remains
available under its existing rules. This accessor returns a boolean and does
not expose device credentials or the record to the broker.

Each runtime stores its definition digest and either a frozen `{harness,repo}`
or explicit `null`. A restart keeps that snapshot. Startup migrates older
rows without a snapshot to `null`; a newly added mapping never authorizes an
old runtime. A new Hello is needed after a mapping change or to acquire a
previously absent scope. Replayed Hello results keep their existing runtime
and cannot refresh scope. No Hello or admission-result fields change.

## Trusted consumer interface

The host-only admission provider offers:

```js
await admission.withNoticeScope(boundRuntimeId, {
  installation_epoch,
  lease_generation,
  // optional equality assertion, never a selector:
  expected_repository,
}, async ({ harness, repo }) => {
  // Perform the scoped local mailbox operation here.
});
```

`boundRuntimeId` comes from broker metadata. The consumer validates the full
pinned query record before extracting this context. The guard refuses extra
context fields, unknown or expired/superseded runtimes, stale epoch/generation,
missing scope, removed definition acceptance, changed owner mappings, lost
enrollment membership and a differing expected repository before calling the
effect. The callback receives only an immutable scope copy, never admission
tables, binding proofs or credentials. It must not re-enter the admission
transaction queue.

The callback shares `withBoundRuntime` serialization with Hello and lease
changes: a queued operation checks liveness when it runs, and supersession
cannot interleave with its mailbox effect. Liveness is checked at entry;
this API does not roll back an external effect if the callback later fails.

The later comms consumer must select only stored notices with their own valid
repository equal to `repo`; an absent or invalid stored repository stays
withheld. It must not fill one from the request or this scope. That mailbox
filter and atomic consume-one are owned by comms, not this slice. `scopes`
is removed before forwarding ingestion settings to comms.

## Rollout dependencies

This slice registers no member query and changes no legacy identity shim or
contract pin. Full query validation and mailbox effects await the shared
notice contract and the comms consumer. Upstream queue custody also requires
the dedicated HQ device policy tracked by
[agent-bot #213](https://github.com/true-line/agent-bot/issues/213): other
clients must not share that device credential. Configuring a local scope does
not activate or prove that upstream competing-consumer gate. Production
activation remains outside this change.

`tests/hq-notice-scope.test.mjs` covers scope persistence/null migration,
assignment/configuration changes, freshness and queue races;
`tests/hq-enrollment.test.mjs` covers the current enrollment proof; and
`tests/hq-notices-config.test.mjs` covers separation from ingestion settings.
