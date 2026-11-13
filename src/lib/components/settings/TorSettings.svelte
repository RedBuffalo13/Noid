<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { getTorStatus, setTorMode, setTorRelay, type TorMode, type TorStatus } from "#lib/services/tor_service";
  import { torStatusStore } from "#lib/stores/tor_status_store.svelte";
  import { t } from "#lib/i18n/index.svelte";

  let mode = $state<TorMode>("off");
  let status = $state<TorStatus | null>(null);
  let relayEnabled = $state(false);
  let allowMetered = $state(false);
  let consentAccepted = $state(false);
  let bridgesText = $state("");
  let busy = $state(false);
  let error = $state("");
  let saved = $state(false);

  // Consent text version — bump when the wording changes; the backend
  // refuses to start Tor with consent_version = 0.
  const CONSENT_VERSION = 1;

  let mounted = false;

  // `initial` restores the full form from persisted state (mode + relay
  // toggles); periodic polls touch ONLY `status` — writing `mode` on every
  // poll would clobber a not-yet-saved selection back to desired_mode.
  async function refresh(initial = false) {
    try {
      status = await getTorStatus();
      if (initial) {
        mode = status.desired_mode;
        relayEnabled = status.relay_enabled ?? false;
        allowMetered = status.allow_metered_relay ?? false;
        // FE-A10: a non-off desired mode means consent was already granted —
        // reflect it, so re-saving the unchanged mode carries the existing
        // consent instead of silently sending 0 (revocation).
        consentAccepted = status.desired_mode !== "off";
        const lines = await invoke<string[]>("get_tor_bridges").catch(() => [] as string[]);
        bridgesText = lines.join("\n");
      }
    } catch (e) {
      error = String(e);
    }
  }

  // OPT-F07: live snapshots flow from the shared store — no own listener.
  // apply()/saveRelay() may still write `status` from the command result;
  // the next pushed snapshot supersedes it, same as before.
  $effect(() => {
    const s = torStatusStore.status;
    if (s) status = s;
  });
  onMount(async () => {
    mounted = true;
    refresh(true);
  });

  async function apply() {
    busy = true;
    saved = false;
    error = "";
    try {
      const consent = mode === "off" ? 0 : (consentAccepted ? CONSENT_VERSION : 0);
      status = await setTorMode(mode, consent);
      saved = true;
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  async function saveRelay() {
    busy = true;
    error = "";
    try {
      status = await setTorRelay(relayEnabled, allowMetered);
      saved = true;
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  async function saveBridges() {
    busy = true;
    error = "";
    try {
      const lines = bridgesText.split("\n").map((l) => l.trim()).filter(Boolean);
      status = await invoke<TorStatus>("set_tor_bridges", { lines });
      saved = true;
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  async function rotateOnion() {
    busy = true;
    error = "";
    try {
      const addr = await invoke<string>("rotate_onion_identity");
      status = await getTorStatus();
      if (status && !status.onion_address) status.onion_address = addr;
      saved = true;
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  function stateLabel(s: TorStatus | null): string {
    if (!s) return "…";
    if (s.state === "ready") return `${t("tor.ready")} (${s.bootstrap_percent}%)`;
    if (s.state === "bootstrapping") return `${t("tor.bootstrapping")} ${s.bootstrap_percent}%`;
    if (s.state === "unsupported") return t("tor.unsupported");
    if (s.state === "failed") return `${t("tor.failed")}${s.error_code ? `: ${s.error_code}` : ""}`;
    return t(`tor.${s.state}`) || s.state;
  }
</script>

<div class="tor-settings" style="padding:12px;display:flex;flex-direction:column;gap:10px;">
  <span class="label">{t("tor.title")}</span>

  {#if status?.state === "unsupported"}
    <p style="font-size:12px;color:var(--text-dim);margin:0;">{t("tor.unsupported_body")}</p>
  {:else}
    <p style="font-size:12px;color:var(--text-dim);margin:0;">{t("tor.desc")}</p>

    <label for="tor-mode" class="label">{t("tor.mode")}</label>
    <select id="tor-mode" bind:value={mode} disabled={busy}
      style="padding:8px;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:8px;">
      <option value="off">{t("tor.mode_off")}</option>
      <option value="additional">{t("tor.mode_additional")}</option>
      <option value="tor_only">{t("tor.mode_tor_only")}</option>
    </select>

    {#if mode !== "off"}
      <label style="display:flex;gap:8px;align-items:flex-start;font-size:12px;">
        <input type="checkbox" bind:checked={consentAccepted} />
        <span>{t("tor.consent")}</span>
      </label>
    {/if}

    <div style="display:flex;gap:8px;align-items:center;">
      <button class="btn" onclick={apply} disabled={busy || (mode !== "off" && !consentAccepted && status?.desired_mode !== mode)}>
        {busy ? "…" : t("settings.save")}
      </button>
      <span style="font-size:12px;color:var(--text-dim);">{stateLabel(status)}</span>
    </div>

    {#if status?.onion_address}
      <p style="font-size:11px;color:var(--text-dim);margin:0;word-break:break-all;">
        {t("tor.onion")}: {status.onion_address}
      </p>
      <button class="btn" onclick={rotateOnion} disabled={busy}>
        {t("tor.rotate_onion")}
      </button>
      <p style="font-size:11px;color:var(--text-dim);margin:0;">{t("tor.rotate_onion_hint")}</p>
    {/if}

    <hr style="border:none;border-top:1px solid var(--border);margin:4px 0;" />

    <span class="label">{t("tor.bridges_title")}</span>
    <p style="font-size:12px;color:var(--text-dim);margin:0;">{t("tor.bridges_desc")}</p>
    <textarea bind:value={bridgesText} rows={3} disabled={busy}
      placeholder="obfs4 1.2.3.4:443 FINGERPRINT cert=… iat-mode=0"
      style="padding:8px;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:8px;font-family:monospace;font-size:11px;resize:vertical;"></textarea>
    <button class="btn" onclick={saveBridges} disabled={busy}>
      {busy ? "…" : t("settings.save")}
    </button>

    {#if mode === "tor_only"}
      <p style="font-size:11px;color:var(--warn,#c90);margin:0;">{t("tor.strict_note")}</p>
    {/if}

    <hr style="border:none;border-top:1px solid var(--border);margin:4px 0;" />

    <span class="label">{t("tor.relay_title")}</span>
    <p style="font-size:12px;color:var(--text-dim);margin:0;">{t("tor.relay_desc")}</p>
    <label style="display:flex;gap:8px;font-size:12px;">
      <input type="checkbox" bind:checked={relayEnabled} />
      <span>{t("tor.relay_enabled")}</span>
    </label>
    <label style="display:flex;gap:8px;font-size:12px;">
      <input type="checkbox" bind:checked={allowMetered} />
      <span>{t("tor.relay_metered")}</span>
    </label>
    <button class="btn" onclick={saveRelay} disabled={busy}>
      {busy ? "…" : t("settings.save")}
    </button>
  {/if}

  {#if error}<p style="font-size:12px;color:var(--error,#c33);margin:0;">{error}</p>{/if}
  {#if saved}<p style="font-size:12px;color:var(--success,#3c3);margin:0;">{t("settings.saved")}</p>{/if}
</div>
