<script lang="ts">
  // OPT-F05: the DM and room views rendered near-identical message lists —
  // one component owns bubble markup, delivery-status logic, the typing
  // indicator and the scroll container (`listEl` binds out for autoScroll).
  import { t } from "#lib/i18n/index.svelte";
  import { formatTimestamp } from "#lib/utils/format";
  import type { Message } from "#lib/types";

  let {
    messages,
    variant = "dm",
    typing = false,
    senderName = (peer: string) => peer,
    ariaLabel = "",
    emptyText = "",
    listEl = $bindable<HTMLDivElement | null>(null),
  }: {
    messages: Message[];
    /** dm — delivery-status icons + typing bubble; room — sender labels. */
    variant?: "dm" | "room";
    typing?: boolean;
    senderName?: (peer: string) => string;
    ariaLabel?: string;
    emptyText?: string;
    listEl?: HTMLDivElement | null;
  } = $props();
</script>

<div class="message-list" role="log" aria-live="polite" aria-label={ariaLabel} bind:this={listEl}>
  {#each messages as msg}
    <div class="msg-bubble {msg.type}">
      {#if variant === "room" && msg.type === "received" && msg.from}
        <div class="msg-sender">{senderName(msg.from)}</div>
      {/if}
      <div class="msg-content">{msg.content}</div>
      <span class="msg-time">{formatTimestamp(msg.timestamp)}</span>
      {#if variant === "dm" && msg.type === 'sent'}
        <div class="delivery-status">
          {#if msg.status === 'sending'}<span class="sending-indicator">↻</span>
          {:else if msg.status === 'failed'}<span class="failed-indicator">✕</span>
          {:else if msg.seen}<span class="seen-indicator">✓✓</span>
          {:else if msg.status === 'delivered'}<span class="delivered-indicator">✓✓</span>
          {:else if msg.status === 'queued'}<span class="sent-indicator" title="Stored in mailbox">☁</span>
          {:else if msg.status === 'sent'}<span class="sent-indicator">✓</span>
          {:else if msg.delivered}<span class="delivered-indicator">✓</span>
          {:else}<span class="pending-indicator">○</span>{/if}
        </div>
      {/if}
    </div>
  {:else}
    <div class="empty-state"><p>{emptyText}</p></div>
  {/each}
  {#if variant === "dm" && typing}
    <div class="msg-bubble received typing-bubble" aria-live="polite"><span class="typing-dots">{t("chat.typing")}</span></div>
  {/if}
</div>

<style>
  .msg-sender { font-size:11px; opacity:0.6; margin-bottom:2px; font-family:monospace; }
  .msg-content { display:inline-block; margin-right:16px; }
  .msg-time { font-size:10px; opacity:0.55; margin-left:8px; }
  .delivery-status { float:right; margin-left:8px; font-size:10px; }
  .delivered-indicator { color:var(--success); }
  .pending-indicator { color:var(--text-secondary); }
  .sending-indicator { color:var(--info); }
  .sent-indicator { color:var(--info); }
  .failed-indicator { color:var(--error); }
  .seen-indicator { color:var(--success); }
  .typing-bubble { font-size:13px; opacity:0.7; font-style:italic; }
</style>
