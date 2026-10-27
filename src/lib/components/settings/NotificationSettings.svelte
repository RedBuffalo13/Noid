<script lang="ts">
  // FE-29: notification preferences were persisted to localStorage but had no
  // UI — this panel is the live control surface for them.
  import {
    getNotificationSettings,
    saveNotificationSettings,
    initializeNotifications,
    checkNotificationPermission,
    type NotificationSettings,
  } from "$lib/notifications";
  import { uiStore } from "$lib/stores/ui_store.svelte";
  import { t } from "$lib/i18n/index.svelte";

  let settings = $state<NotificationSettings>(getNotificationSettings());
  let permissionGranted = $state<boolean | null>(null);

  $effect(() => {
    checkNotificationPermission()
      .then((g) => (permissionGranted = g))
      .catch(() => (permissionGranted = null));
  });

  function update(patch: Partial<NotificationSettings>) {
    settings = { ...settings, ...patch };
    saveNotificationSettings(settings);
  }

  async function requestPermission() {
    const ok = await initializeNotifications();
    permissionGranted = ok;
    uiStore.showToast(ok ? t("notif.toast.enabled") : t("notif.toast.denied"));
  }
</script>

<div class="notif-panel">
  <span class="label">{t("notif.title")}</span>

  {#if permissionGranted === false}
    <div class="perm-hint">
      <span>{t("notif.noPermission")}</span>
      <button class="num-btn special perm-btn" onclick={requestPermission} type="button">{t("notif.enable")}</button>
    </div>
  {/if}

  <label class="toggle-row">
    <input
      type="checkbox"
      class="toggle-input"
      checked={settings.enabled}
      onchange={(e) => update({ enabled: e.currentTarget.checked })}
    />
    <span class="toggle-track" aria-hidden="true"><span class="toggle-thumb"></span></span>
    <span class="toggle-label">{t("notif.enabled")}</span>
  </label>

  <label class="toggle-row" class:disabled={!settings.enabled}>
    <input
      type="checkbox"
      class="toggle-input"
      checked={settings.showPreview}
      disabled={!settings.enabled}
      onchange={(e) => update({ showPreview: e.currentTarget.checked })}
    />
    <span class="toggle-track" aria-hidden="true"><span class="toggle-thumb"></span></span>
    <span class="toggle-label">{t("notif.preview")}</span>
  </label>

  <label class="toggle-row" class:disabled={!settings.enabled}>
    <input
      type="checkbox"
      class="toggle-input"
      checked={settings.onlyMentions}
      disabled={!settings.enabled}
      onchange={(e) => update({ onlyMentions: e.currentTarget.checked })}
    />
    <span class="toggle-track" aria-hidden="true"><span class="toggle-thumb"></span></span>
    <span class="toggle-label">{t("notif.mentions")}</span>
  </label>

  <label class="toggle-row" class:disabled={!settings.enabled}>
    <input
      type="checkbox"
      class="toggle-input"
      checked={settings.sound}
      disabled={!settings.enabled}
      onchange={(e) => update({ sound: e.currentTarget.checked })}
    />
    <span class="toggle-track" aria-hidden="true"><span class="toggle-thumb"></span></span>
    <span class="toggle-label">{t("notif.sound")}</span>
  </label>
</div>

<style>
  .notif-panel {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .label {
    display: block;
    margin-bottom: 8px;
    font-size: 14px;
    font-weight: 500;
    color: var(--text-primary);
  }

  .perm-hint {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 10px 12px;
    margin-bottom: 8px;
    border-radius: 10px;
    border: 1px solid var(--border-default);
    background: var(--bg-tertiary);
    font-size: 13px;
    color: var(--text-secondary);
  }

  .perm-btn {
    min-height: 36px;
    padding: 0 12px;
    border-radius: 10px;
    font-size: 12px;
    flex-shrink: 0;
  }

  .toggle-row {
    display: flex;
    align-items: center;
    gap: 12px;
    min-height: 44px;
    cursor: pointer;
    user-select: none;
  }

  .toggle-row.disabled {
    opacity: 0.45;
    cursor: default;
  }

  .toggle-input {
    position: absolute;
    opacity: 0;
    width: 1px;
    height: 1px;
    overflow: hidden;
  }

  .toggle-track {
    width: 44px;
    height: 24px;
    border-radius: 12px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border-default);
    position: relative;
    flex-shrink: 0;
    transition: background 0.2s, border-color 0.2s;
  }

  .toggle-thumb {
    position: absolute;
    top: 2px;
    left: 2px;
    width: 18px;
    height: 18px;
    border-radius: 50%;
    background: var(--text-secondary);
    transition: transform 0.2s, background 0.2s;
  }

  .toggle-input:checked + .toggle-track {
    background: var(--primary);
    border-color: var(--primary);
  }

  .toggle-input:checked + .toggle-track .toggle-thumb {
    transform: translateX(20px);
    background: var(--text-on-accent);
  }

  .toggle-input:focus-visible + .toggle-track {
    outline: 2px solid var(--primary);
    outline-offset: 2px;
  }

  .toggle-label {
    font-size: 14px;
    color: var(--text-primary);
  }
</style>
