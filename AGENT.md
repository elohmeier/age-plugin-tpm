# Unlock agent protocol

The agent keeps PIN-protected TPM identities usable after a single unlock until the agent
stops (logout/reboot), `--lock` is requested, or the optional `--timeout` expires. The private
key never leaves the TPM: the agent caches the PIN (in locked memory, zeroed on lock) and the
parent SRK, and loads the identity for each key agreement.

The same protocol is used by the macOS Secure Enclave agent in the age-plugin-se fork, so the
plugin side can stay identical across platforms.

## Transport

- Unix stream socket, one request and one response per connection.
- Request and response are each a single line of JSON terminated by `\n`.
- The socket directory is created `0700`. Both the agent and the plugin refuse a socket
  directory that is not owned by the current user or is writable by others. The agent rejects
  peers whose UID differs from its own (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS).
- Socket path: `$AGE_PLUGIN_TPM_AGENT_SOCK`, else `$XDG_RUNTIME_DIR/age-plugin-tpm/agent.sock`.
  With systemd socket activation (`LISTEN_PID`/`LISTEN_FDS=1`) the agent uses fd 3.
- The plugin uses the agent when the socket accepts a connection; otherwise it accesses the TPM
  directly and asks for the PIN on every decryption. `AGE_PLUGIN_NO_AGENT=1` forces the direct
  path.

## Messages

All binary values are standard base64 with padding. `key` is the serialized identity, the
bech32 payload of `AGE-PLUGIN-TPM-1…`.

| Request | Success response |
|---|---|
| `{"op":"status"}` | `{"ok":true,"unlocked":<int>}` |
| `{"op":"lock"}` | `{"ok":true}` (forgets all cached PINs) |
| `{"op":"unlock","key":K,"password":P}` | `{"ok":true}`. The agent verifies P with a key agreement against a random P-256 point before caching it. Identities without a PIN need no unlock. |
| `{"op":"ecdh","key":K,"share":S}` | `{"ok":true,"secret":X}`. X is the raw P-256 ECDH shared secret (the x-coordinate); S is an uncompressed (65-byte) P-256 point. |

Error response: `{"ok":false,"error":E,"message":"…"}` where E is one of:

- `locked`: the identity has a PIN and none is cached. The plugin asks for the PIN via the age
  client (or uses `AGE_TPM_PIN`), sends `unlock`, then retries.
- `bad-password`: the PIN was rejected. This counts towards the TPM dictionary attack lockout,
  so the plugin asks at most twice per key agreement, and only once when the PIN comes from
  `AGE_TPM_PIN`.
- `invalid`: malformed request.
- `internal`: anything else, including dictionary attack lockout.

## CLI

```
age-plugin-tpm --agent [--socket PATH] [--timeout DURATION]
age-plugin-tpm --unlock IDENTITY_FILE [--socket PATH]
age-plugin-tpm --lock [--socket PATH]
age-plugin-tpm --agent-status [--socket PATH]
```

`--unlock` takes the PIN from `AGE_TPM_PIN`, the terminal, or, without a terminal, from
`$PINENTRY_PROGRAM` (default `pinentry` on `PATH`).
