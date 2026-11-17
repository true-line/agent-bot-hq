Run the offline HQ artifact as the dedicated Linux service account in hosted
CI. The status check verifies the process UID, account, private control socket
and durable store. When HQ runs under a different account, its profile reason
reports the observed and expected names.

Refs #43.
