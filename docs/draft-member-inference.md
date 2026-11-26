# Draft member inference contract

The [cross-repository proposal](https://github.com/true-line/agent-bot-platform/discussions/103) is open. The candidate uses the existing HQ member socket and member binding. Only an explicitly injected test fixture can register its two operations. Installed and development plugins cannot enable them. The dedicated B broker retains its own operation allowlist.

The fixture's authorization callback checks the bound runtime, Equip handle, task, destination and model before dispatch. A production resolver would need authority for the exact operation and its cost ceiling. The member supplies selectors for that check and has no fields for URLs, credentials, prices or allowances.

`inference.models` uses the ordinary request and result envelope and returns a list of model identifiers. `inference.responses` requires `response: "stream"` and adds a model identifier and a text input. The broker returns correlated `response.output_text.delta` chunks and then either a refusal or one result with input and output token usage. Existing unary requests keep their framing. Responses are limited to 4,096 chunks and 8 MiB total. Both operations have a two-minute deadline starting when HQ begins servicing the frame, before broker dispatch and authorization. Time spent queued behind earlier requests is outside that deadline. The SDK client supports a synchronous chunk callback and closes the bound connection on cancellation. It never replays a failed inference request.

The optional structured `turn` arm replaces `input` on the same private
`inference.responses` request. It models the single Read round trip observed
in [Soul Adapters #15](https://github.com/true-line/soul-adapters/pull/15).
The request carries the original system text or ordered text blocks, one
`Read` declaration and a requested cap of 1–128,000 output tokens. The Read
schema preserves up to twelve primitive property declarations, descriptions
and recognized bounds. It requires a string `file_path`. The initial request
has one user text message. The continuation includes that message, an assistant
`tool_use` block with an ID and typed input, then a user `tool_result` block
with the same ID and text, including an empty result. Supported prompt text
blocks, their order and ephemeral cache metadata carry through unchanged.
The same task uses a separate operation ID for each request. Tool invocation
supports the observed `file_path` argument. Other declared parameters carry
through as schema information. The local fixture forwards the observed
Messages system blocks, history and Read declaration unchanged and maps
`max_tokens` to `max_output_tokens`. Its projection excludes the stock
`thinking`, `context_management` and `metadata` fields. Ancillary Messages
requests stay outside the draft. Supporting those fields or enabling any
provider requires separate review.

The first response has either text or one Read call. A Read response streams
a `response.tool_call.start` and bounded
`response.tool_call.arguments.delta` fragments correlated by call ID. A
`tool_use` terminal result requires complete, strictly parsed Read arguments.
The client must wait for that terminal result before treating the streamed
tool request as complete. A text completion returns `end_turn`. Both
structured terminal results carry the measured input/output token counters.
Legacy text requests retain their original chunks and usage-only result.
Each call independently authorizes and reserves against the same durable
ledger. The requested token cap is a wire bound. The same trusted callback
must still approve the exact call and supply an enforced cost ceiling. The continuation's matching IDs check its structure and convey no
proof of prior provider state or permission to use a tool. Tool execution and
consent stay with the harness. The draft carries no URLs, arbitrary provider
fields or capability to execute the supplied path.

HQ stops waiting on authorization and drops its revocation hook on disconnect, deadline or device revocation, even if the callback is still pending. Trusted authorization and provider callbacks receive the abort signal and must propagate it to their I/O. A host deadline can end signal-aware I/O and result delivery. The vendor may already have accepted or charged for a dispatched request.

Before invoking a Responses producer, HQ reserves the authorized cost bound
against the Soul's working ceiling and persists it in an `outcome_unknown`
operation. A valid terminal response records measured cost and completion
together. Abort before dispatch may release the hold. After dispatch, a lost
response or failed settlement leaves the hold in place and fences replay of
the exact Soul, task and operation. A new runtime, provider destination or
model alias does not change that identity.

Unary budget operations keep their existing SDK API and private plugin-owned
reservation IDs. Pending unary holds and measured debit share the configured
ceiling with typed inference and survive restart. A settled reservation
cannot settle or release again. A released reservation retains its ID and
does not consume budget. Reservations and settlements accept the existing
nonnegative numeric amounts and use the configured pool. This change supplies
no ceilings, units, pricing, new authorizations or cross-operation deduplication
for unary calls. The unary API has no request or operation ID. Only the
owning plugin can settle or release its open hold. It remains responsible
for establishing whether release is safe after a lost outcome.

Both ledgers use HQ storage under a namespace that cannot be a plugin name.
Their transactions use the same file-store queue as ordinary table, blob,
and receipt commits. A failed file-store write rolls back before the next
queued commit can take its snapshot.
Only the initialized inference consumer's earlier draft table can contribute
historical inference accounting. Known earlier spend counts toward the
working pool. Unresolved records without a saved bound, or the same operation
in both historical and private tables, require reconciliation for that Soul
before new working spend. The earlier workspace must reconcile its historical
table before changing provider plugin names. Old unary records were held only
in memory and cannot be recovered from an older store. Retention and recovery
for durable holds, historical aliases and removal of released-ID markers
require owner policy or a verified migration.

## Decisions pending in proposal #103

| Area | Agreement needed before provider calls can be enabled |
| --- | --- |
| Request framing | Contracts, HQ, Comms and the adapter need to agree on capability negotiation, request and reply framing, ordered typed messages, tool schemas and selection, correlated tool results, stop reasons and usage. Agree on the component that owns authenticated adapter translation on the assigned socket paths and how it handles ancillary requests. |
| Provider credentials | Define the trusted destination and grant resolver, the Identity issuance operation under [Machine/keyd custody](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0091-host-privileged-custody.md), and how grant or runtime revocation reaches in-flight vendor I/O. |
| Cost bounds | Agree on charge units, trusted pricing, an enforceable upper bound for a request and the usage evidence that establishes actual cost. The fixture's numeric ceiling and output-token cap are local test inputs. |
| Uncertain charges | Agree on what provider evidence can settle or release a durable hold after disconnect, restart or a failed settlement. Define who resolves unknown or above-bound charges, how operation identity survives retries and how long replay records are retained. |

Physical T03 qualification remains open. The fixture exercises HQ's member
protocol, cancellation and accounting without making vendor calls.
