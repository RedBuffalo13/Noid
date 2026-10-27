import { t } from "$lib/i18n/index.svelte";
import { login as svcLogin, setupPins as svcSetupPins, isFirstRun as svcIsFirstRun } from "$lib/services";
import { profileStore } from "./profile_store.svelte";
import { contactStore } from "./contact_store.svelte";
import { uiStore } from "./ui_store.svelte";
import { usernameStore } from "./username_store.svelte";

let screen = $state("checking");
let pin = $state("");
let truePin = $state("");
let confirmTruePin = $state("");
let killPin = $state("");
let confirmKillPin = $state("");
let busy = $state(false);
// FE-03: surfaced lockout/attempt state — the backend reports them in
// AuthResponse; without them the user saw a bare "Invalid PIN" forever.
let lockoutRemaining = $state(0);
let attemptsRemaining = $state<number | null>(null);
let lockoutTimer: ReturnType<typeof setInterval> | null = null;

function startLockoutCountdown(secs: number) {
  if (lockoutTimer) clearInterval(lockoutTimer);
  lockoutRemaining = secs;
  lockoutTimer = setInterval(() => {
    lockoutRemaining -= 1;
    if (lockoutRemaining <= 0) {
      lockoutRemaining = 0;
      if (lockoutTimer) { clearInterval(lockoutTimer); lockoutTimer = null; }
    }
  }, 1000);
}

export const authStore = {
  get screen() { return screen; },
  set screen(val) { screen = val; },
  get busy() { return busy; },
  get lockoutRemaining() { return lockoutRemaining; },
  get attemptsRemaining() { return attemptsRemaining; },
  get pin() { return pin; },
  set pin(val) { pin = val; },
  get truePin() { return truePin; },
  set truePin(val) { truePin = val; },
  get confirmTruePin() { return confirmTruePin; },
  set confirmTruePin(val) { confirmTruePin = val; },
  get killPin() { return killPin; },
  set killPin(val) { killPin = val; },
  get confirmKillPin() { return confirmKillPin; },
  set confirmKillPin(val) { confirmKillPin = val; },

  async checkFirstRun() {
    try {
      const isFirstRun = await svcIsFirstRun();
      screen = isFirstRun ? "setup" : "pin-entry";
    } catch (e) {
      console.error("Error checking first run:", e);
      screen = "pin-entry";
    }
  },

  async handleAuth() {
    if (pin.length < 8 || busy) return;
    busy = true;
    try {
      const res = await svcLogin(pin);
      if (res.success) {
        lockoutRemaining = 0;
        attemptsRemaining = null;
        // RC26: branch on the typed outcome, not the display string.
        if (res.kind === "wiped") {
          uiStore.showToast(t("auth.toast.wiped"));
          pin = "";
          // FE-13: wipe destroyed the keys — the next step is re-setup, not
          // another PIN attempt against a vault that no longer exists.
          screen = "setup";
        } else {
          await profileStore.loadProfile();
          await contactStore.loadContacts();
          await usernameStore.loadUsername();
          uiStore.resetNav("chats");
          screen = "main";
        }
      } else if (res.kind === "locked_out") {
        // FE-03: show the real lockout state + a live countdown. PIN entry
        // stays enabled — a valid KillPin must still wipe during lockout.
        if (res.retry_after_secs) startLockoutCountdown(res.retry_after_secs);
        attemptsRemaining = 0;
        uiStore.showToast(res.message);
        pin = "";
      } else {
        // FE-03: surface the real failure + attempts left before lockout.
        attemptsRemaining = res.attempts_remaining ?? null;
        uiStore.showToast(res.message || t("auth.toast.invalidPin"));
        pin = "";
      }
    } catch (e) {
      uiStore.showToast(t("auth.toast.error"));
    } finally {
      busy = false;
    }
  },

  async handleSetup() {
    if (busy) return;
    if (truePin !== confirmTruePin) {
      uiStore.showToast(t("auth.toast.mainMismatch"));
      return;
    }
    if (killPin !== confirmKillPin) {
      uiStore.showToast(t("auth.toast.killMismatch"));
      return;
    }
    if (truePin.length < 8) {
      uiStore.showToast(t("auth.toast.mainShort"));
      return;
    }
    if (killPin.length < 8) {
      uiStore.showToast(t("auth.toast.killShort"));
      return;
    }
    if (truePin === killPin) {
      uiStore.showToast(t("auth.toast.samePins"));
      return;
    }

    busy = true;
    try {
      const res = await svcSetupPins(truePin, killPin);
      if (res.success) {
        uiStore.showToast(t("auth.toast.setupDone"));
        screen = "pin-entry";
        truePin = "";
        confirmTruePin = "";
        killPin = "";
        confirmKillPin = "";
      } else {
        uiStore.showToast(t("auth.toast.setupError", { e: res.message }));
      }
    } catch (e) {
      uiStore.showToast(t("auth.toast.setupError", { e: String(e) }));
    } finally {
      busy = false;
    }
  },

  resetSetup() {
    truePin = "";
    confirmTruePin = "";
    killPin = "";
    confirmKillPin = "";
  }
};
