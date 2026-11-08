# Local patches to arti-client 0.48.0

## 1. Fatal protocol recommendations no longer exit the process

**File:** `src/client.rs` (`TorClient::new` protocol-recommendation callback)

Upstream calls `std::process::exit(1)` when the directory consensus declares
this client version fatally unsupported. Inside a messenger process that
would kill the whole app — so the callback instead records the reason into a
`OnceLock` (`protocol_fatal`) and drives the channel manager dormant
(`Dormancy::Dormant`), which tears down Tor background activity while the
host process stays alive. A new `TorClient::protocol_fatal_reason()` exposes
the recorded reason so the Noid supervisor can surface `TorState::Failed`
to the UI.

## Licensing

Unmodified files are MIT OR Apache-2.0 (upstream). The modifications above
are distributed under the same dual license. See `LICENSE-MIT` and
`LICENSE-APACHE` in this directory.
