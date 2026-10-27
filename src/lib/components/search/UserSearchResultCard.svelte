<script lang="ts">
  import type { UserRecord } from "$lib/types";
  import { t } from "$lib/i18n/index.svelte";

  let {
    record,
    source = "dht",
    isOnline = false,
    onSendRequest,
  }: {
    record: UserRecord;
    source: "dht" | "peer";
    isOnline: boolean;
    onSendRequest: () => void;
  } = $props();

  let displayId = $derived(`${record.nickname}#${record.shortId}`);
</script>

<div class="result-card">
  <div class="avatar">
    {#if record.avatar}
      <img src={record.avatar} alt={record.nickname} />
    {:else}
      {record.nickname.charAt(0).toUpperCase()}
    {/if}
  </div>
  <div class="info">
    <span class="nickname">{record.nickname}</span>
    <span class="public-id">{displayId}</span>
    <div class="badges">
      <span class="badge {isOnline ? 'online' : 'offline'}">{isOnline ? t("search.badge.online") : t("search.badge.offline")}</span>
      <span class="badge source-{source}">{source === 'dht' ? t("search.badge.dht") : t("search.badge.peer")}</span>
    </div>
  </div>
  <button class="send-btn" onclick={onSendRequest} type="button">{t("search.modal.send")}</button>
</div>

<style>
  .result-card {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px;
    border-radius: 12px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border-default);
    transition: border-color 0.2s;
  }

  .result-card:hover {
    border-color: var(--border-default);
  }

  .avatar {
    width: 40px;
    height: 40px;
    border-radius: 50%;
    background: var(--primary, var(--primary));
    color: var(--text-inverse);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 16px;
    font-weight: 600;
    flex-shrink: 0;
    overflow: hidden;
  }

  .avatar img {
    width: 100%;
    height: 100%;
    object-fit: cover;
  }

  .info {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }

  .nickname {
    font-size: 14px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .public-id {
    font-size: 12px;
    color: var(--text-secondary);
    font-family: monospace;
  }

  .badges {
    display: flex;
    gap: 6px;
    margin-top: 4px;
  }

  .badge {
    font-size: 10px;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 6px;
  }

  .badge.online {
    background: color-mix(in srgb, var(--success) 15%, transparent);
    color: var(--success);
  }

  .badge.offline {
    background: color-mix(in srgb, var(--text-tertiary) 15%, transparent);
    color: var(--text-tertiary);
  }

  .badge.source-dht {
    background: color-mix(in srgb, var(--primary) 15%, transparent);
    color: var(--primary);
  }

  .badge.source-peer {
    background: color-mix(in srgb, var(--info) 15%, transparent);
    color: var(--info);
  }

  .send-btn {
    padding: 8px 14px;
    border-radius: 10px;
    border: none;
    background: var(--primary, var(--primary));
    color: var(--text-inverse);
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
    flex-shrink: 0;
  }

  .send-btn:hover {
    filter: brightness(1.1);
  }
</style>
