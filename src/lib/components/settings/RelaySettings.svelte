<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import type { UnlistenFn } from "@tauri-apps/api/event";
  import {
    getRelayConfig,
    getRelayStatus,
    setNodeRole,
    setPrivacyMode,
    onRelayStatus,
  } from "$lib/services/relay_service";
  import { getMyInvite } from "$lib/services/contact_service";
  import type { NodeRole, PrivacyMode, RelayConfig, RelayStatus } from "$lib/relay";
  import { t } from "$lib/i18n/index.svelte";

  let config = $state<RelayConfig | null>(null);
  let status = $state<RelayStatus | null>(null);
  let invite = $state<string>("");
  let inviteCopied = $state(false);
  let error = $state<string>("");
  let unlisten: UnlistenFn | null = null;

  const natKeys: Record<string, string> = {
    unknown: "relay.nat.unknown",
    public: "relay.nat.public",
    private: "relay.nat.private",
  };

  onMount(async () => {
    try {
      [config, status] = await Promise.all([getRelayConfig(), getRelayStatus()]);
      unlisten = await onRelayStatus((s) => {
        status = s;
        refreshInvite();
      });
      refreshInvite();
    } catch (e) {
      error = String(e);
    }
  });

  onDestroy(() => {
    unlisten?.();
  });

  async function changeRole(role: NodeRole) {
    try {
      config = await setNodeRole(role);
      error = "";
    } catch (e) {
      error = String(e);
    }
  }

  async function refreshInvite() {
    try {
      invite = await getMyInvite();
    } catch {
      invite = "";
    }
  }

  async function copyInvite() {
    if (!invite) return;
    try {
      await navigator.clipboard.writeText(invite);
      inviteCopied = true;
      setTimeout(() => (inviteCopied = false), 2000);
    } catch (e) {
      error = String(e);
    }
  }

  async function changePrivacy(mode: PrivacyMode) {
    try {
      config = await setPrivacyMode(mode);
      error = "";
    } catch (e) {
      error = String(e);
    }
  }
</script>

<div class="settings-section">
  <h3 class="section-title">{t("relay.title")}</h3>

  {#if error}
    <p class="error-text">{error}</p>
  {/if}

  <div class="setting-item column">
    <div class="setting-info">
      <span class="setting-label">{t("relay.role")}</span>
      <span class="setting-description">{t("relay.role.desc")}</span>
    </div>
    <div class="segmented">
      {#each ["auto", "relay", "client"] as role}
        <button
          type="button"
          class="seg-btn"
          class:active={config?.role === role}
          onclick={() => changeRole(role as NodeRole)}
        >
          {role === "auto" ? "Auto" : role === "relay" ? "Relay" : "Client"}
        </button>
      {/each}
    </div>
  </div>

  <div class="setting-item column">
    <div class="setting-info">
      <span class="setting-label">{t("relay.privacy")}</span>
      <span class="setting-description">{t("relay.privacy.desc")}</span>
    </div>
    <div class="segmented">
      <button
        type="button"
        class="seg-btn"
        class:active={config?.privacy === "direct"}
        onclick={() => changePrivacy("direct")}
      >Direct</button>
      <button
        type="button"
        class="seg-btn"
        class:active={config?.privacy === "relayed_only"}
        onclick={() => changePrivacy("relayed_only")}
      >Relayed Only</button>
    </div>
  </div>

  {#if status}
    <div class="status-block">
      <div class="status-row">
        <span class="status-label">{t("relay.nat")}</span>
        <span class="status-value" class:status-ok={status.natStatus === "public"}>
          {t((natKeys[status.natStatus] ?? "relay.nat.unknown") as never)}
        </span>
      </div>
      <div class="status-row">
        <span class="status-label">{t("relay.relaying")}</span>
        <span class="status-value">{status.isRelaying ? t("relay.relaying.on") : t("relay.relaying.off")}</span>
      </div>
      <div class="status-row">
        <span class="status-label">{t("relay.peers")}</span>
        <span class="status-value">{status.peersConnected}</span>
      </div>
      <div class="status-row">
        <span class="status-label">{t("relay.knownRelays")}</span>
        <span class="status-value">{status.knownRelays}</span>
      </div>
      <div class="status-row">
        <span class="status-label">{t("relay.reservations")}</span>
        <span class="status-value">{status.activeReservations}</span>
      </div>
      <div class="status-row">
        <span class="status-label">{t("relay.inbound")}</span>
        <span class="status-value">{status.inboundReservations} / {status.activeCircuits}</span>
      </div>
    </div>
  {/if}

  <div class="setting-item column">
    <div class="setting-info">
      <span class="setting-label">{t("relay.invite")}</span>
      <span class="setting-description">{t("relay.invite.desc")}</span>
    </div>
    <div class="invite-row">
      <input class="invite-input" readonly value={invite || t("relay.invite.loading")} />
      <button type="button" class="seg-btn invite-copy" onclick={copyInvite} disabled={!invite}>
        {inviteCopied ? t("relay.invite.copied") : t("settings.copy")}
      </button>
    </div>
    {#if invite && !invite.includes("@")}
      <p class="invite-warn">
        {t("relay.invite.warn")}
      </p>
    {/if}
  </div>
</div>

<style>
  .settings-section {
    padding: 20px 0;
  }
  .section-title {
    font-size: var(--text-lg);
    font-weight: var(--font-bold);
    color: var(--text-primary);
    margin-bottom: 16px;
  }
  .setting-item {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    padding: 16px 0;
    border-bottom: 1px solid var(--border-subtle);
  }
  .setting-item.column {
    flex-direction: column;
    gap: 12px;
  }
  .setting-info {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .setting-label {
    font-weight: var(--font-semibold);
    font-size: var(--text-base);
    color: var(--text-primary);
  }
  .setting-description {
    font-size: var(--text-sm);
    color: var(--text-secondary);
    line-height: 1.5;
  }
  .segmented {
    display: flex;
    gap: 6px;
  }
  .seg-btn {
    flex: 1;
    padding: 10px 18px;
    border-radius: 12px;
    border: 1px solid var(--border-subtle);
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    font-size: var(--text-sm);
    font-weight: var(--font-semibold);
    cursor: pointer;
    transition: all 0.15s;
  }
  .seg-btn.active {
    background: var(--primary);
    color: var(--text-inverse);
    border-color: var(--primary);
  }
  .status-block {
    margin-top: 16px;
    padding: 12px 16px;
    border-radius: 12px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border-subtle);
  }
  .status-row {
    display: flex;
    justify-content: space-between;
    padding: 6px 0;
    font-size: var(--text-sm);
  }
  .status-label {
    color: var(--text-secondary);
  }
  .status-value {
    color: var(--text-primary);
    font-weight: var(--font-semibold);
  }
  .status-ok {
    color: var(--success);
  }
  .error-text {
    color: var(--error);
    font-size: var(--text-sm);
    margin-bottom: 8px;
  }
  .invite-row {
    display: flex;
    gap: 8px;
  }
  .invite-input {
    flex: 1;
    padding: 10px 12px;
    border-radius: 10px;
    border: 1px solid var(--border-subtle);
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    font-family: monospace;
    font-size: 11px;
    outline: none;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .invite-copy {
    flex: 0 0 auto;
    padding: 10px 14px;
  }
  .invite-warn {
    font-size: var(--text-sm);
    color: var(--warning);
    margin: 4px 0 0;
    line-height: 1.4;
  }
</style>
