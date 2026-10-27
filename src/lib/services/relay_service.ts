import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { NodeRole, PrivacyMode, RelayConfig, RelayStatus } from "$lib/relay";

/** Persisted relay configuration (role, privacy, limits). */
export async function getRelayConfig(): Promise<RelayConfig> {
  return invoke<RelayConfig>("get_relay_config");
}

/** Latest relay/NAT status snapshot; also triggers a fresh report via event. */
export async function getRelayStatus(): Promise<RelayStatus> {
  return invoke<RelayStatus>("get_relay_status");
}

/** Set node role: "auto" | "relay" | "client". Applies after restart. */
export async function setNodeRole(role: NodeRole): Promise<RelayConfig> {
  return invoke<RelayConfig>("set_node_role", { role });
}

/** Set privacy mode: "direct" | "relayed_only". Applies after restart. */
export async function setPrivacyMode(mode: PrivacyMode): Promise<RelayConfig> {
  return invoke<RelayConfig>("set_privacy_mode", { mode });
}

/** Live relay status updates pushed by the backend. */
export async function onRelayStatus(cb: (status: RelayStatus) => void): Promise<UnlistenFn> {
  return listen<RelayStatus>("relay-status", (e) => cb(e.payload));
}
