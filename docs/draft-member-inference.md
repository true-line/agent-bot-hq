# Draft member inference contract

The [cross-repository proposal](https://github.com/true-line/agent-bot-platform/discussions/103) is under review. The candidate uses the existing assigned HQ member socket and member binding. There is no configured production provider. The trusted provider plugin's authorization callback must check the current bound runtime, Equip handle, task, destination, operation and any cost ceiling against HQ policy. Client-supplied identifiers select an operation for that check. The callback decides authority before the external operation starts. The client sends no URL, provider secret, price, or authority override.

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
Only the initialized inference consumer's earlier draft table can contribute
historical inference accounting. Known earlier spend counts toward the
working pool. Unresolved records without a saved bound, or the same operation
in both historical and private tables, require reconciliation for that Soul
before new working spend. The earlier workspace must reconcile its historical
table before changing provider plugin names. Old unary records were held only
in memory and cannot be recovered from an older store. Retention and recovery
for durable holds, historical aliases and removal of released-ID markers
require owner policy or a verified migration.

Deployment requires approval of this private member envelope and provider routing, including cost units, a verified bound the provider can enforce, and handling of incomplete outcomes. A vendor charge that exceeds its bound and cannot be persisted still needs reconciliation. Production also needs the Identity credential operation, verified vendor cancellation and cost reporting, compatible Codex transport, and signed launch qualification. The synthetic fixture covers this draft behavior.
