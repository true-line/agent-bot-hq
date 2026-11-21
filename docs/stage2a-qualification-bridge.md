# Stage 2a Messages qualification seam

This is the narrow test-provider route for [Platform #68 T03](https://github.com/true-line/agent-bot-platform/issues/68) and [HQ #231](https://github.com/true-line/agent-bot-hq/issues/231). It does not add a live Claude provider or enable a protected profile.

`hq/claude-qualification-http.mjs` runs under the **assigned harness credential UID**, not HQ's UID. Its `socketPath` is in that UID's private 0700 directory and the Unix socket is 0600. The [PDR-0052](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0052-process-isolation-for-harness-egress.md) two-destination rule applies separately to two confined harness processes:

| Process | Assigned outbound Unix paths | Local listener |
| --- | --- | --- |
| HTTP bridge | Its Soul member socket; HQ's per-harness NDJSON broker socket | Private HTTP broker socket |
| Stock ACP | Its Soul member socket; the bridge's private HTTP broker socket | None |

The bridge HTTP socket **is the ACP launch assignment's broker path**, not a third allowed destination. The bridge's listening socket is not an outbound egress path in its own profile. Both profiles must refuse direct IPv4/IPv6, the shared HQ broker socket and sibling launch sockets. The HTTP `x-api-key` is an inert stock-client placeholder, never authorization. Machine and HQ still need a reviewed dual-process launch plan and exact UID/path matching before this can qualify physically; no policy expansion is authorized by this component change.

The two processes must be pinned to the same Soul installation, start, harness UID and one-use plan. The sidecar alone holds the member bootstrap token and HMAC-bound HQ session; ACP gets neither. Machine must demonstrate that ACP cannot connect to HQ's NDJSON endpoint and the sidecar cannot connect to ACP's other paths. Other same-UID processes in a shared harness account can potentially inspect or race the sidecar socket; the exact prompt and HQ one-use plan limit the effect but do not isolate that UID from itself. Physical qualification must record this residual trust-domain risk rather than treating the socket mode as per-process authentication.

The sidecar receives an existing member session from `sdk/member-session.mjs`: member-token bootstrap, HQ challenge, HMAC bind, then one captured broker request. It accepts only policy-limit GET and a streamed Messages POST with the exact model and last-user prompt from the owner-approved qualification plan. Ancillary POSTs return 422 without broker delivery. It caps HTTP bodies at 256 KiB, enough for the measured 87,619-byte stock ACP main request. The reply uses Anthropic Messages SSE framing.

`hq/qualification-provider.mjs` is an opt-in plugin; production HQ does not install it by default. Its caller must inject a callback that verifies the **Machine-authorized plan** against the admission-checked bound runtime, exact model and prompt digest, expiry and intended one-use operation. The plugin consumes the plan once before it returns a fixed text response. Its in-memory `used` guard does not survive an HQ restart; Machine's persistent one-use authorization must refuse the replay. It holds no vendor credential and makes no network call. `() => true` is only a test fixture, never a production authorization callback. Until Machine supplies that callback and the exact socket rule, this code is a reviewable component seam, not physical T03 evidence.

The current provider returns one text value, which the bridge emits as one Messages `content_block_delta`. This proves stock framing and broker routing, not incremental HQ streaming. Two separately observable HQ deltas and a terminal frame are still needed for any streaming claim.

The full inference route, provider credentials, tool streaming, budget ledger and live vendor calls remain the Stage 2b work tracked by [HQ #208](https://github.com/true-line/agent-bot-hq/pull/208). A physical T03 acceptance run still needs the pinned release artifact, actual HQ-started Soul, Machine plan, stock ACP and signed host receipt.
