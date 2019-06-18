## Replay/Rollback {#replay-rollback}

Replay is the ability to use a previously used credential that was designed for one-time approval to access protected content beyond the first instance. Typically, a timestamp, nonce value, or monotonic counter can be used to detect replay.

Rollback is the ability to start at a newer level of a release and go back to a forbidden earlier level of a release. Typically, the firmware needs to use a lowest support version (LSV) or secure version number (SVN) to control the update.