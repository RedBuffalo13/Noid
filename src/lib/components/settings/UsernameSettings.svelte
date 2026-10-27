<script lang="ts">
  import { usernameStore } from "$lib/stores/username_store.svelte";
  import { chatStore } from "$lib/stores/chat_store.svelte";
  import { t } from "$lib/i18n/index.svelte";

  let localUsername = $state("");
  // FE-26: seed from the store ONCE — re-writing on every store refresh
  // would clobber the text the user is currently typing.
  let usernameTouched = $state(false);
  $effect(() => {
    if (!usernameTouched && usernameStore.username) {
      localUsername = usernameStore.username;
    }
  });

  let shortId = $derived(chatStore.myId ? chatStore.myId.slice(-4) : "");
  let publicId = $derived(localUsername ? `${localUsername}#${shortId}` : "");

  function handleInput(e: Event) {
    const target = e.target as HTMLInputElement;
    usernameTouched = true;
    localUsername = target.value;
    usernameStore.checkAvailability(localUsername);
  }

  function handleSave() {
    if (!localUsername.trim()) return;
    usernameStore.saveUsername(localUsername.trim());
  }
</script>

<div class="username-settings">
  <div class="form-group">
    <label class="label" for="username">{t("username.label")}</label>
    <div class="username-row">
      <input
        id="username"
        type="text"
        class="input-box"
        placeholder="alice"
        value={localUsername}
        oninput={handleInput}
      />
      {#if usernameStore.availabilityStatus === "checking"}
        <span class="status-icon checking" title={t("username.status.checking")}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>
        </span>
      {:else if usernameStore.availabilityStatus === "available"}
        <span class="status-icon available" title={t("username.status.available")}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M20 6L9 17l-5-5"/></svg>
        </span>
      {:else if usernameStore.availabilityStatus === "taken"}
        <span class="status-icon taken" title={t("username.status.taken")}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M18 6L6 18M6 6l12 12"/></svg>
        </span>
      {:else if usernameStore.availabilityStatus === "unknown"}
        <span class="status-icon taken" title={t("username.status.unknown")}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3"/><path d="M12 17h.01"/></svg>
        </span>
      {/if}
    </div>
    {#if publicId}
      <p class="hint">{t("username.publicId")} <span class="public-id">{publicId}</span></p>
    {/if}
  </div>
  <button class="btn-wide" onclick={handleSave} disabled={!localUsername.trim() || usernameStore.availabilityStatus === "taken" || usernameStore.availabilityStatus === "checking" || usernameStore.availabilityStatus === "unknown"}>{t("username.save")}</button>
</div>

<style>
  .username-settings {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .form-group {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .username-row {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .username-row .input-box {
    flex: 1;
  }

  .status-icon {
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .status-icon.checking {
    color: var(--text-secondary);
    animation: spin 1s linear infinite;
  }

  .status-icon.available {
    color: var(--success);
  }

  .status-icon.taken {
    color: var(--error);
  }

  @keyframes spin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
  }

  .hint {
    font-size: 12px;
    color: var(--text-tertiary);
    margin: 0;
  }

  .public-id {
    color: var(--primary, var(--primary));
    font-weight: 600;
    font-family: monospace;
  }

  .btn-wide {
    padding: 12px;
    border-radius: 12px;
    border: none;
    background: var(--primary, var(--primary));
    color: var(--text-inverse);
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
  }

  .btn-wide:hover:not(:disabled) {
    filter: brightness(1.1);
  }

  .btn-wide:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
</style>
