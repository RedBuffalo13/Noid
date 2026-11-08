<script lang="ts">
  import { contactStore } from "#lib/stores/contact_store.svelte";
  import { t } from "#lib/i18n/index.svelte";

  // B8: when zero peers are connected the app silently queued everything —
  // the user had no way to see the node was isolated. A persistent banner
  // makes the degraded state explicit instead of looking like normal chat.
  const zeroPeers = $derived(contactStore.onlinePeers.size === 0);
</script>

{#if zeroPeers}
  <div class="net-status" role="status" aria-live="polite"
    style="display:flex;align-items:center;gap:8px;padding:8px 12px;margin:0 12px 8px;border:1px solid var(--warn,#c90);border-radius:10px;background:color-mix(in srgb, var(--warn,#c90) 12%, transparent);font-size:12px;color:var(--warn,#c90);">
    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
      <line x1="1" y1="1" x2="23" y2="23"/><path d="M16.72 11.06A10.94 10.94 0 0 1 19 12.55"/><path d="M5 12.55a10.94 10.94 0 0 1 5.17-2.39"/><path d="M10.71 5.05A16 16 0 0 1 22.58 9"/><path d="M1.42 9a15.91 15.91 0 0 1 21.64 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/>
    </svg>
    <span>{t("net.zeroPeers")}</span>
  </div>
{/if}
