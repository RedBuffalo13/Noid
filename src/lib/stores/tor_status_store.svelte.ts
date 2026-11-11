// OPT-F07: single Tor status subscription for the whole app —
// TorStatusChip, TorSettings and RelaySettings each used to hold their
// own `tor-status` listener plus an initial fetch. The backend pushes
// every supervisor snapshot, so one upstream listener feeds all readers.
import { getTorStatus, onTorStatus, type TorStatus } from "#lib/services/tor_service";

let status = $state<TorStatus | null>(null);
let started = false;

export const torStatusStore = {
  get status() { return status; },

  /** Idempotent — safe to call from every screen that needs the status. */
  async init() {
    if (started) return;
    started = true;
    try {
      status = await getTorStatus();
      await onTorStatus((s) => { status = s; });
    } catch {
      // tor feature absent — allow a later retry instead of latching.
      started = false;
    }
  },
};
