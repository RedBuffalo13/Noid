<script lang="ts">
  // Language picker — custom i18n (no dependency): EN default, RU optional.
  import { i18n, t } from "$lib/i18n/index.svelte";
  import type { Locale } from "$lib/i18n/index.svelte";

  const langs: { id: Locale; labelKey: "settings.language.en" | "settings.language.ru" }[] = [
    { id: "en", labelKey: "settings.language.en" },
    { id: "ru", labelKey: "settings.language.ru" },
  ];
</script>

<div class="lang-panel">
  <span class="label">{t("settings.language")}</span>
  <div class="segmented" role="radiogroup" aria-label={t("settings.language")}>
    {#each langs as lang}
      <button
        type="button"
        class="seg-btn"
        class:active={i18n.locale === lang.id}
        role="radio"
        aria-checked={i18n.locale === lang.id}
        onclick={() => i18n.setLocale(lang.id)}
      >{t(lang.labelKey)}</button>
    {/each}
  </div>
</div>

<style>
  .lang-panel {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .label {
    display: block;
    font-size: 14px;
    font-weight: 500;
    color: var(--text-primary);
  }

  .segmented {
    display: flex;
    gap: 6px;
  }

  .seg-btn {
    flex: 1;
    padding: 10px 18px;
    min-height: 44px;
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
    color: var(--text-on-accent);
    border-color: var(--primary);
  }
</style>
