<script lang="ts">
  import { torStatusStore } from "#lib/stores/tor_status_store.svelte";
  import { t } from "#lib/i18n/index.svelte";

  // OPT-F07: shared upstream — the chip renders the store's status, it
  // does not own a listener.
  const status = $derived(torStatusStore.status);

  // What is the visible connectivity? off → no chip (ordinary networking
  // is the default, nothing to indicate); bootstrapping → live %; ready →
  // the transport actually in use; failed → warn.
  let chip = $derived.by(() => {
    if (!status || status.effective_mode === "off") return null;
    switch (status.state) {
      case "starting":
      case "bootstrapping":
        return { text: `${t("tor.bootstrapping")} ${status.bootstrap_percent}%`, cls: "chip-warn" };
      case "ready":
      case "publishing":
        return status.effective_mode === "tor_only"
          ? { text: t("tor.chip.onion_only"), cls: "chip-ok" }
          : { text: t("tor.chip.onion_direct"), cls: "chip-ok" };
      case "failed":
      case "degraded":
        return { text: t("tor.chip.failed"), cls: "chip-err" };
      default:
        return null;
    }
  });
</script>

{#if chip}
  <div class="tor-chip {chip.cls}" role="status" aria-live="polite">
    <span class="dot"></span>{chip.text}
  </div>
{/if}

<style>
  .tor-chip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 3px 10px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: var(--font-semibold, 600);
    border: 1px solid var(--border, #333);
    color: var(--text-secondary, #aaa);
    background: var(--bg-tertiary, #1a1a1a);
  }
  .dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: currentColor;
  }
  .chip-ok { color: var(--success, #3c3); }
  .chip-warn { color: var(--warning, #ca3); }
  .chip-err { color: var(--error, #c33); }
</style>
