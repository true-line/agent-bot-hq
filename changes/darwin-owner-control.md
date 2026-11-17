Serve the macOS owner's control requests from HQ under the dedicated
`_agent-bot-hq` account. The Darwin source artifact accepts the launchd
listener and authenticates the connecting account using the kernel peer UID.
The native hosted fixture exercises the owner status CLI and the service UID.

Refs #88. Admission-client migration and deployment on enrolled Macs remain
separate work.
