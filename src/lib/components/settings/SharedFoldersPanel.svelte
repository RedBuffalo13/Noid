<script lang="ts">
  import { folderStore } from "$lib/stores/folder_store.svelte";
  import { t } from "$lib/i18n/index.svelte";

  let showPasswordModal = $state(false);
  let passwordFolderId = $state("");
  let passwordInput = $state("");
  let confirmDeleteId = $state("");
  let modalEl = $state<HTMLDivElement | null>(null);

  // a11y: move focus into the dialog when it opens.
  $effect(() => {
    if (showPasswordModal && modalEl) modalEl.focus();
  });

  function handleBrowse() {
    folderStore.pickFolder();
  }

  function handleAdd() {
    folderStore.registerFolder();
  }

  function handleEditPath(id: string) {
    folderStore.updatePath(id);
  }

  function handleToggleVisibility(id: string, current: boolean) {
    folderStore.toggleVisibility(id, !current);
  }

  function handleSetPassword(id: string) {
    passwordFolderId = id;
    passwordInput = "";
    showPasswordModal = true;
  }

  function handleClearPassword(id: string) {
    folderStore.setPassword(id, "");
  }

  function handleSavePassword() {
    folderStore.setPassword(passwordFolderId, passwordInput);
    showPasswordModal = false;
  }

  function handleDelete(id: string) {
    confirmDeleteId = id;
  }

  function confirmDelete() {
    folderStore.removeFolder(confirmDeleteId);
    confirmDeleteId = "";
  }

  function handleSearch(e: Event) {
    const target = e.target as HTMLInputElement;
    folderStore.search(target.value);
  }

  let displayFolders = $derived(
    folderStore.searchQuery.trim()
      ? folderStore.searchResults.map((r) => ({ id: r[0], path: r[1], isPublic: r[2], hasPassword: !!r[3] }))
      : folderStore.folders.map((f) => ({ id: f[0], path: f[1], isPublic: f[2], hasPassword: false }))
  );
</script>

<div class="shared-folders-panel">
  <span class="label">{t("folders.title")}</span>

  <div class="add-row">
    <input
      type="text"
      class="path-input"
      placeholder={t("folders.placeholder")}
      readonly
      value={folderStore.selectedPath}
    />
    <button class="action-btn" onclick={handleBrowse} type="button">{t("folders.browse")}</button>
    <button class="action-btn primary" onclick={handleAdd} type="button">{t("folders.add")}</button>
  </div>

  <div class="search-row">
    <input
      type="text"
      class="search-input"
      placeholder={t("folders.search")}
      value={folderStore.searchQuery}
      oninput={handleSearch}
    />
  </div>

  {#if displayFolders.length > 0}
    <div class="folder-list">
      {#each displayFolders as folder (folder.id)}
        <div class="folder-item">
          <button class="folder-path" onclick={() => handleEditPath(folder.id)} type="button" title={t("folders.changePath")}>
            {folder.path}
          </button>
          <div class="folder-actions">
            <button
              class="badge-btn {folder.isPublic ? 'public' : 'private'}"
              onclick={() => handleToggleVisibility(folder.id, folder.isPublic)}
              type="button"
              title={t("folders.toggleVisibility")}
            >
              {folder.isPublic ? t("folders.public") : t("folders.private")}
            </button>
            {#if folder.hasPassword}
              <button class="icon-btn" onclick={() => handleClearPassword(folder.id)} type="button" title={t("folders.removePassword")}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
              </button>
            {:else}
              <button class="icon-btn" onclick={() => handleSetPassword(folder.id)} type="button" title={t("folders.setPassword")}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
              </button>
            {/if}
            {#if confirmDeleteId === folder.id}
              <button class="icon-btn confirm" onclick={confirmDelete} type="button" title={t("folders.confirmDelete")}>✓</button>
              <button class="icon-btn cancel" onclick={() => (confirmDeleteId = "")} type="button" title={t("common.cancel")}>×</button>
            {:else}
              <button class="icon-btn delete" onclick={() => handleDelete(folder.id)} type="button" title={t("folders.delete")}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
              </button>
            {/if}
          </div>
        </div>
      {/each}
    </div>
  {:else}
    <p class="empty-hint">{t("folders.empty")}</p>
  {/if}

  {#if showPasswordModal}
    <div class="modal-overlay" role="presentation" onclick={(e) => { if (e.target === e.currentTarget) showPasswordModal = false; }}>
      <div class="modal" role="dialog" aria-modal="true" tabindex="-1" bind:this={modalEl} onkeydown={(e) => e.key === 'Escape' && (showPasswordModal = false)}>
        <label class="modal-label" for="folder-password">{t("folders.password.title")}</label>
        <input id="folder-password" type="password" class="modal-input" bind:value={passwordInput} placeholder={t("folders.password.placeholder")} />
        <div class="modal-actions">
          <button class="action-btn" onclick={() => (showPasswordModal = false)} type="button">{t("common.cancel")}</button>
          <button class="action-btn primary" onclick={handleSavePassword} type="button">{t("folders.password.save")}</button>
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .shared-folders-panel {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .label {
    font-size: 14px;
    font-weight: 500;
    color: var(--text-primary);
  }

  .add-row {
    display: flex;
    gap: 8px;
    align-items: center;
  }

  .path-input {
    flex: 1;
    padding: 10px 12px;
    border-radius: 12px;
    border: 1px solid var(--border-default);
    background-color: var(--bg-tertiary);
    color: var(--text-secondary);
    font-size: 14px;
    cursor: default;
  }

  .search-row {
    display: flex;
    gap: 8px;
  }

  .search-input {
    flex: 1;
    padding: 10px 12px;
    border-radius: 12px;
    border: 1px solid var(--border-default);
    background-color: var(--bg-tertiary);
    color: var(--text-primary);
    font-size: 14px;
    outline: none;
    transition: border-color 0.2s;
  }

  .search-input:focus {
    border-color: var(--primary, var(--primary));
  }

  .folder-list {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .folder-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 0;
    border-bottom: 1px solid var(--bg-tertiary);
  }

  .folder-path {
    flex: 1;
    background: none;
    border: none;
    color: var(--text-secondary);
    font-size: 13px;
    text-align: left;
    cursor: pointer;
    padding: 4px 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .folder-path:hover {
    color: var(--text-secondary);
  }

  .folder-actions {
    display: flex;
    gap: 6px;
    align-items: center;
    flex-shrink: 0;
  }

  .action-btn {
    padding: 8px 14px;
    border-radius: 10px;
    border: 1px solid var(--border-default);
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    font-size: 13px;
    cursor: pointer;
    transition: all 0.2s;
  }

  .action-btn:hover {
    border-color: var(--border-default);
  }

  .action-btn.primary {
    background: var(--primary, var(--primary));
    color: var(--text-inverse);
    border: none;
    font-weight: 600;
  }

  .action-btn.primary:hover {
    filter: brightness(1.1);
  }

  .badge-btn {
    padding: 4px 10px;
    border-radius: 8px;
    border: none;
    font-size: 11px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
  }

  .badge-btn.public {
    background: color-mix(in srgb, var(--success) 15%, transparent);
    color: var(--success);
  }

  .badge-btn.private {
    background: color-mix(in srgb, var(--text-tertiary) 15%, transparent);
    color: var(--text-tertiary);
  }

  .icon-btn {
    width: 44px;
    height: 44px;
    border-radius: 8px;
    border: none;
    background: color-mix(in srgb, var(--text-primary) 5%, transparent);
    color: var(--text-secondary);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.2s;
  }

  .icon-btn:hover {
    background: color-mix(in srgb, var(--text-primary) 10%, transparent);
    color: var(--text-secondary);
  }

  .icon-btn.delete:hover {
    color: var(--error);
    background: color-mix(in srgb, var(--error) 10%, transparent);
  }

  .icon-btn.confirm {
    color: var(--success);
    background: color-mix(in srgb, var(--success) 10%, transparent);
  }

  .icon-btn.cancel {
    color: var(--error);
  }

  .empty-hint {
    font-size: 13px;
    color: var(--text-tertiary);
    padding: 8px 0;
  }

  .modal-overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
  }

  .modal {
    background: var(--bg-tertiary);
    border: 1px solid var(--border-default);
    border-radius: 16px;
    padding: 24px;
    display: flex;
    flex-direction: column;
    gap: 16px;
    max-width: 360px;
    width: 90%;
  }

  .modal-label {
    font-size: 13px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .modal-input {
    padding: 12px;
    border-radius: 12px;
    border: 1px solid var(--border-default);
    background: var(--bg-tertiary);
    color: var(--text-primary);
    font-size: 15px;
    outline: none;
  }

  .modal-input:focus {
    border-color: var(--primary, var(--primary));
  }

  .modal-actions {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
  }
</style>
