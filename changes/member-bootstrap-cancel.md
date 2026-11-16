Allow the shared member bootstrap and sessions to accept an optional
AbortSignal. Native local-socket cancellation closes pending hello, binding
and query work before a close facade exists, blocks reopening, and preserves
the caller's abort reason. Destructive queries never replay on abort.

Keep the existing lifecycle when no signal is supplied, and cover cancellation
races, idempotent close and listener cleanup with real socket tests.

Refs #138; parent #131 remains open for consumer integration.
