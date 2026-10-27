import { invoke } from "@tauri-apps/api/core";

export type AuthOutcome = "ok" | "wiped" | "locked_out" | "failed";

export interface AuthResult {
  success: boolean;
  message: string;
  kind: AuthOutcome;
  /** FE-03: seconds until the lockout lifts (`locked_out` only). */
  retry_after_secs?: number | null;
  /** FE-03: attempts left before lockout (`failed` only). */
  attempts_remaining?: number | null;
}

export async function login(pin: string): Promise<AuthResult> {
  return invoke<AuthResult>("login", { pin });
}

export async function setupPins(truePin: string, killPin: string): Promise<AuthResult> {
  return invoke<AuthResult>("setup_pins", { truePin, killPin });
}

export async function isFirstRun(): Promise<boolean> {
  return invoke<boolean>("is_first_run");
}
