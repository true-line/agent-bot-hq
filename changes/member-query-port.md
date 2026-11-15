Prepare an SDK member-query capability that pairs each request with one
privately captured bound session and immutable freshness. Opt-in read recovery
reconnects and rebuilds at most once for known read-only kinds; destructive and
unknown operations never replay through this helper.

Include portable semantic checks and unit coverage. Real transport adaptation
and member/MCP composition remain open under #131; default notice activation
and shared contract pins are unchanged.

Refs #134.
