Share the reviewed existing member bootstrap, challenge-bound session and
strict local-socket client through the SDK. `connectMemberQueries` returns
only the never-replay query capability and cleanup; the private owner facade
preserves captured runtime metadata and the raw request path needed by Souls'
task-specific recovery. Add real HQ/socket regression tests and provenance.

Souls consumer pin/removal and identity's actual MCP composition remain open
under #131. No notice activation, upstream fallback or contract pin changes.

Refs #136.
