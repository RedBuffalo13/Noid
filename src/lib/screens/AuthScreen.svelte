<script lang="ts">
  import { authStore } from "$lib/stores";
  import { uiStore } from "$lib/stores";
  import { t } from "$lib/i18n/index.svelte";

  // ---- Setup wizard state (4 steps: main → confirm → kill → confirm) ----
  // The first-run form used text inputs that fell below the keyboard/edge on
  // Android — the wizard drives the SAME numpad as the login screen instead.
  let setupStep = $state(0);
  let wizardPin = $state("");
  let wizardMainPin = $state("");
  let wizardKillPin = $state("");

  const setupSteps = [
    { titleKey: "auth.setup.main.enter", hintKey: "auth.setup.main.hint" },
    { titleKey: "auth.setup.main.confirm", hintKey: "auth.setup.main.hint" },
    { titleKey: "auth.setup.kill.enter", hintKey: "auth.setup.kill.hint" },
    { titleKey: "auth.setup.kill.confirm", hintKey: "auth.setup.kill.hint" },
  ] as const;

  const addPin = (key: string) => {
    if (authStore.busy) return;
    if (key === "C") authStore.pin = "";
    else if (key === "⌫") authStore.pin = authStore.pin.slice(0, -1);
    else if (key === "OK") authStore.handleAuth();
    // Backend accepts 8–64 digit PINs — the numpad must not cap at 8 or a
    // longer PIN set at setup can never be entered at login.
    else if (authStore.pin.length < 64) authStore.pin += key;
  };

  const addWizardPin = (key: string) => {
    if (authStore.busy) return;
    if (key === "C") wizardPin = "";
    else if (key === "⌫") wizardPin = wizardPin.slice(0, -1);
    else if (key === "OK") wizardAdvance();
    else if (wizardPin.length < 64) wizardPin += key;
  };

  function wizardAdvance() {
    if (wizardPin.length < 8) return; // OK is disabled below 8 anyway
    switch (setupStep) {
      case 0:
        wizardMainPin = wizardPin; wizardPin = ""; setupStep = 1; break;
      case 1:
        if (wizardPin !== wizardMainPin) {
          uiStore.showToast(t("auth.setup.mismatch"));
          wizardPin = ""; setupStep = 0; return;
        }
        wizardPin = ""; setupStep = 2; break;
      case 2:
        if (wizardPin === wizardMainPin) {
          uiStore.showToast(t("auth.toast.samePins"));
          wizardPin = ""; return; // stay on kill-PIN step
        }
        wizardKillPin = wizardPin; wizardPin = ""; setupStep = 3; break;
      case 3:
        if (wizardPin !== wizardKillPin) {
          uiStore.showToast(t("auth.setup.mismatch"));
          wizardPin = ""; setupStep = 2; return;
        }
        // Fill the store fields handleSetup() validates against.
        authStore.truePin = wizardMainPin;
        authStore.confirmTruePin = wizardMainPin;
        authStore.killPin = wizardKillPin;
        authStore.confirmKillPin = wizardPin;
        wizardPin = ""; wizardMainPin = ""; wizardKillPin = ""; setupStep = 0;
        authStore.handleSetup();
        break;
    }
  }

  function wizardBack() {
    if (setupStep > 0) { setupStep -= 1; wizardPin = ""; }
  }
</script>

{#if authStore.screen === "checking"}
  <div class="auth-container">
    <div class="auth-logo">
      <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    </div>
    <h1 class="auth-title">{t("auth.loading")}</h1>
  </div>
{:else if authStore.screen === "setup"}
  <div class="auth-container scrollable">
    <div class="auth-logo">
      <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    </div>
    <h1 class="auth-title">{t("auth.setup.title")}</h1>
    <p class="setup-step-label">{t("auth.setup.step", { n: setupStep + 1 })}</p>
    <p class="auth-subtitle">{t(setupSteps[setupStep].titleKey)}</p>
    <p class="setup-hint">{t(setupSteps[setupStep].hintKey)}</p>
    <div class="pin-display">
      {#each Array(8) as _, i}<div class="pin-dot" class:active={wizardPin.length > i}></div>{/each}
      {#if wizardPin.length > 8}<span class="pin-extra">+{wizardPin.length - 8}</span>{/if}
      {#if wizardPin.length > 0}
        <button class="pin-clear" aria-label={t("auth.pin.clear")} onclick={() => wizardPin = ""}>✕</button>
      {/if}
    </div>
    {#if wizardPin.length > 0 && wizardPin.length < 8}
      <p class="pin-hint" aria-live="polite">{t("auth.pin.tooShort")}</p>
    {/if}
    <div class="numpad" class:busy={authStore.busy}>
      {#each ["1","2","3","4","5","6","7","8","9","⌫","0","OK"] as key}
        <button
          class="num-btn"
          class:special={key === "OK" || key === "⌫"}
          disabled={authStore.busy || (key === "OK" && wizardPin.length < 8)}
          aria-label={key === "⌫" ? t("auth.pin.backspace") : key}
          onclick={() => addWizardPin(key)}
        >{key}</button>
      {/each}
    </div>
    <div class="wizard-actions">
      {#if setupStep > 0}
        <button class="btn-text" onclick={wizardBack} type="button">{t("nav.back")}</button>
      {/if}
      <button class="btn-text" onclick={() => { authStore.screen = "pin-entry"; authStore.resetSetup(); wizardPin = ""; wizardMainPin = ""; wizardKillPin = ""; setupStep = 0; }} type="button">
        {t("auth.setup.toLogin")}
      </button>
    </div>
  </div>
{:else if authStore.screen === "pin-entry"}
  <div class="auth-container scrollable">
    <div class="auth-logo">
      <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    </div>
    <h1 class="auth-title">{t("auth.login.title")}</h1>
    {#if authStore.lockoutRemaining > 0}
      <p class="lockout-banner" role="alert" aria-live="assertive">
        {t("auth.login.locked", { s: authStore.lockoutRemaining })}
      </p>
    {:else}
      <p class="auth-subtitle" aria-live="polite">
        {authStore.busy ? t("auth.login.unlocking") : t("auth.login.subtitle")}
        {#if authStore.attemptsRemaining !== null && authStore.attemptsRemaining > 0}
          · {t("auth.login.attemptsLeft", { n: authStore.attemptsRemaining })}
        {/if}
      </p>
    {/if}
    <div class="pin-display">
      {#each Array(8) as _, i}<div class="pin-dot" class:active={authStore.pin.length > i}></div>{/each}
      {#if authStore.pin.length > 8}<span class="pin-extra">+{authStore.pin.length - 8}</span>{/if}
      {#if authStore.pin.length > 0}
        <button class="pin-clear" aria-label={t("auth.pin.clear")} onclick={() => authStore.pin = ""}>✕</button>
      {/if}
    </div>
    {#if authStore.pin.length > 0 && authStore.pin.length < 8}
      <p class="pin-hint" aria-live="polite">{t("auth.pin.tooShort")}</p>
    {/if}
    <div class="numpad" class:busy={authStore.busy}>
      {#each ["1","2","3","4","5","6","7","8","9","⌫","0","OK"] as key}
        <button
          class="num-btn"
          class:special={key === "OK" || key === "⌫"}
          disabled={authStore.busy || (key === "OK" && authStore.pin.length < 8)}
          aria-label={key === "⌫" ? t("auth.pin.backspace") : key}
          onclick={() => addPin(key)}
        >{key}</button>
      {/each}
    </div>
  </div>
{/if}

<style>
  .auth-container.scrollable {
    overflow-y: auto;
    justify-content: safe center;
  }
  .auth-title { font-size: 1.875rem; font-weight: 800; margin-bottom: 0.5rem; }
  .auth-subtitle { font-size: 0.875rem; color: var(--text-secondary); }
  .setup-step-label {
    font-size: 11px;
    font-weight: 600;
    color: var(--primary);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin: 0;
  }
  .setup-hint {
    font-size: 12px;
    color: var(--text-tertiary);
    max-width: 300px;
    text-align: center;
    margin: 0;
    line-height: 1.4;
  }
  .pin-extra { align-self:center; font-size:14px; color:var(--text-secondary); margin-left:4px; }
  .pin-clear {
    align-self: center;
    margin-left: 8px;
    min-width: 44px;
    min-height: 44px;
    border: none;
    background: transparent;
    color: var(--text-secondary);
    font-size: 18px;
    cursor: pointer;
  }
  .pin-clear:hover { color: var(--text-primary); }
  .pin-hint { font-size: 13px; color: var(--warning); margin: -8px 0 8px; }
  .lockout-banner {
    font-size: 14px;
    color: var(--error);
    font-weight: 600;
    max-width: 320px;
    text-align: center;
  }
  .numpad.busy {
    opacity: 0.5;
    pointer-events: none;
  }
  .wizard-actions {
    display: flex;
    gap: 16px;
    margin-top: 4px;
  }
  .btn-text {
    background: none;
    border: none;
    color: var(--text-secondary);
    font-size: 13px;
    cursor: pointer;
    padding: 10px;
    min-height: 44px;
  }
  .btn-text:hover { color: var(--text-primary); }
</style>
