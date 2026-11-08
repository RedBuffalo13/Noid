import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export type TorMode = "off" | "additional" | "tor_only";
export type TorState =
  | "off" | "starting" | "bootstrapping" | "publishing" | "ready"
  | "degraded" | "stopping" | "failed" | "unsupported";

export interface TorStatus {
  desired_mode: TorMode;
  effective_mode: TorMode;
  generation: number;
  state: TorState;
  bootstrap_percent: number;
  service_published: boolean;
  onion_address?: string | null;
  relay_enabled?: boolean;
  relay_active?: boolean;
  allow_metered_relay?: boolean;
  error_code?: string | null;
}

export async function getTorStatus(): Promise<TorStatus> {
  return invoke<TorStatus>("get_tor_status");
}

export async function setTorMode(
  mode: TorMode,
  consentVersion: number
): Promise<TorStatus> {
  return invoke<TorStatus>("set_tor_mode", { mode, consentVersion });
}

export async function setTorRelay(
  enabled: boolean,
  allowMetered: boolean
): Promise<TorStatus> {
  return invoke<TorStatus>("set_tor_relay", { enabled, allowMetered });
}

// Live status stream — the backend forwards every supervisor snapshot as
// "tor-status" events (bootstrap progress, mode transitions, service
// publish). Mirrors onRelayStatus; callers must unlisten on teardown.
export function onTorStatus(
  cb: (status: TorStatus) => void
): Promise<UnlistenFn> {
  return listen<TorStatus>("tor-status", (e) => cb(e.payload));
}
