<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { t } from "#lib/i18n/index.svelte";

  type ConnectivityConfig = {
    on_demand: boolean;
    idle_conn_ttl_secs: number;
    mailbox_poll_secs: number;
  };

  let onDemand = $state(false);
  let idleTtl = $state(120);
  let mailboxPoll = $state(300);
  let cover = $state(false);
  let hopEntry = $state("");
  let hopExit = $state("");
  let busy = $state(false);
  let saved = $state(false);
  let error = $state("");

  onMount(async () => {
    try {
      const c = await invoke<ConnectivityConfig>("get_connectivity_config");
      onDemand = c.on_demand;
      idleTtl = c.idle_conn_ttl_secs;
      mailboxPoll = c.mailbox_poll_secs;
      cover = localStorage.getItem("noid.cover") === "1";
      if (cover) invoke("set_cover_traffic", { enabled: true }).catch(() => {});
      const rc = await invoke<{ hop_relays?: string[] }>("get_relay_config");
      hopEntry = rc.hop_relays?.[0] ?? "";
      hopExit = rc.hop_relays?.[1] ?? "";
    } catch (e) {
      error = String(e);
    }
  });

  async function apply() {
    busy = true;
    saved = false;
    error = "";
    try {
      await invoke("set_connectivity_config", {
        config: {
          on_demand: onDemand,
          idle_conn_ttl_secs: Math.max(10, idleTtl | 0),
          mailbox_poll_secs: Math.max(30, mailboxPoll | 0),
        },
      });
      await invoke("set_cover_traffic", { enabled: cover });
      localStorage.setItem("noid.cover", cover ? "1" : "0");
      const hops = [hopEntry.trim(), hopExit.trim()].filter((s) => s.length > 0);
      await invoke("set_hop_relays", { relays: hops });
      saved = true;
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }
</script>

<div class="settings-section">
  <h3 class="settings-title">{t("conn.title")}</h3>
  <p class="settings-desc">{t("conn.desc")}</p>

  <label class="toggle-row">
    <input type="checkbox" bind:checked={onDemand} />
    <span>{t("conn.on_demand")}</span>
  </label>
  <p class="hint">{t("conn.on_demand_hint")}</p>

  <div class="form-group">
    <label class="label" for="idle-ttl">{t("conn.idle_ttl")}</label>
    <input id="idle-ttl" class="input-box" type="number" min="10" bind:value={idleTtl} disabled={!onDemand} />
  </div>

  <div class="form-group">
    <label class="label" for="mbox-poll">{t("conn.mailbox_poll")}</label>
    <input id="mbox-poll" class="input-box" type="number" min="30" bind:value={mailboxPoll} />
  </div>

  <label class="toggle-row">
    <input type="checkbox" bind:checked={cover} />
    <span>{t("conn.cover")}</span>
  </label>
  <p class="hint">{t("conn.cover_hint")}</p>

  <div class="form-group">
    <label class="label" for="hop-entry">{t("conn.hop_entry")}</label>
    <input id="hop-entry" class="input-box" type="text" bind:value={hopEntry} placeholder="/ip4/1.2.3.4/tcp/4020/p2p/12D3…" />
  </div>
  <div class="form-group">
    <label class="label" for="hop-exit">{t("conn.hop_exit")}</label>
    <input id="hop-exit" class="input-box" type="text" bind:value={hopExit} placeholder="12D3KooW…" />
  </div>
  <p class="hint">{t("conn.hop_hint")}</p>

  <button class="btn-wide" onclick={apply} disabled={busy}>{t("settings.save")}</button>
  {#if saved}<p class="hint ok">{t("settings.saved")}</p>{/if}
  {#if error}<p class="hint err">{error}</p>{/if}
</div>

<style>
  .toggle-row { display: flex; align-items: center; gap: 10px; margin: 12px 0 4px; cursor: pointer; }
  .toggle-row input { width: 18px; height: 18px; accent-color: var(--accent, #8b5cf6); }
  .hint { font-size: 12px; color: var(--text-dim, #9a9aa5); margin: 4px 0 12px; }
  .hint.ok { color: var(--ok, #10b981); }
  .hint.err { color: var(--err, #ef4444); }
</style>
