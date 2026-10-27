<script lang="ts">
  import { usernameStore } from "$lib/stores/username_store.svelte";
  import { connectToAddr, sendContactRequest } from "$lib/services/contact_service";
  import { uiStore } from "$lib/stores/ui_store.svelte";
  import UserSearchResultCard from "./UserSearchResultCard.svelte";
  import { t } from "$lib/i18n/index.svelte";

  let searchInput = $state("");
  let requestMessage = $state("");
  let inviteInput = $state("");
  let inviteBusy = $state(false);
  let selectedRecord = $state<{ peerId: string; nickname: string; shortId: string; avatar: string | null; addrHints?: string[] } | null>(null);
  let modalEl = $state<HTMLDivElement | null>(null);

  // a11y: move focus into the dialog when it opens.
  $effect(() => {
    if (selectedRecord && modalEl) modalEl.focus();
  });

  function handleSearch(e: KeyboardEvent) {
    if (e.key === "Enter") {
      doSearch();
    }
  }

  function doSearch() {
    if (!searchInput.trim()) return;
    usernameStore.searchUsers(searchInput.trim());
  }

  async function handleConnectInvite() {
    const input = inviteInput.trim();
    if (!input || inviteBusy) return;
    inviteBusy = true;
    try {
      // Backend parses invite / multiaddr / bare peer id, dials addr hints
      // and queues a DHT lookup. Returns the resolved peer id.
      const peerId = await connectToAddr(input);
      inviteInput = "";
      // Preserve the invite's dial hints — the contact-request send must
      // reuse them, not re-resolve via DHT (which may not know the peer).
      // Formats: `noid:<peer>@<addr1>,<addr2>` / bare multiaddr / peer id.
      let addrHints: string[] | undefined;
      if (input.startsWith("noid:")) {
        const at = input.indexOf("@");
        if (at >= 0) {
          const hints = input
            .slice(at + 1)
            .split(",")
            .map((s) => s.trim())
            .filter((s) => s.length > 0);
          if (hints.length > 0) addrHints = hints;
        }
      } else if (input.startsWith("/")) {
        addrHints = [input];
      }
      selectedRecord = {
        peerId,
        nickname: "Peer",
        shortId: peerId.slice(-4),
        avatar: null,
        addrHints,
      };
      requestMessage = "";
    } catch (e) {
      uiStore.showToast(t("search.toast.badInvite", { e: String(e) }));
    } finally {
      inviteBusy = false;
    }
  }

  function handleSendRequest(record: { peerId: string; nickname: string; shortId: string; avatar: string | null }) {
    selectedRecord = record;
    requestMessage = "";
  }

  let requestBusy = $state(false);

  async function confirmSendRequest() {
    if (!selectedRecord || requestBusy) return;
    requestBusy = true;
    const msg = requestMessage || t("search.defaultMessage");
    try {
      if (selectedRecord.nickname === "Peer") {
        // Invite/addr path — the record is a raw peer id, not a DHT user.
        await sendContactRequest(selectedRecord.peerId, msg, selectedRecord.addrHints);
        uiStore.showToast(t("search.toast.sent"));
      } else {
        await usernameStore.sendRequestToUser(selectedRecord, msg);
      }
      selectedRecord = null;
      requestMessage = "";
    } catch (e) {
      uiStore.showToast(t("search.toast.failed", { e: String(e) }));
    } finally {
      requestBusy = false;
    }
  }

  function cancelSendRequest() {
    selectedRecord = null;
    requestMessage = "";
  }
</script>

<div class="user-search">
  <div class="search-bar">
    <input
      type="text"
      class="search-input"
      placeholder={t("search.placeholder")}
      bind:value={searchInput}
      onkeydown={handleSearch}
    />
    <button class="search-btn" onclick={doSearch} type="button">{t("search.button")}</button>
  </div>

  {#if usernameStore.searching}
    <div class="searching-hint">
      <span class="spinner"></span>
      <span>{t("search.searching")}</span>
    </div>
  {:else if usernameStore.searchResults.length > 0}
    <div class="results-list">
      {#each usernameStore.searchResults as result (result.record.peerId)}
        <UserSearchResultCard
          record={result.record}
          source={result.source}
          isOnline={result.isOnline}
          onSendRequest={() => handleSendRequest(result.record)}
        />
      {/each}
    </div>
  {:else if searchInput.trim() && !usernameStore.searching}
    <p class="empty-hint">{t("search.noResults")}</p>
  {/if}

  <div class="invite-section">
    <span class="invite-label">{t("search.inviteLabel")}</span>
    <div class="search-bar">
      <input
        type="text"
        class="search-input mono"
        placeholder={t("search.invitePlaceholder")}
        bind:value={inviteInput}
        onkeydown={(e) => e.key === "Enter" && handleConnectInvite()}
        disabled={inviteBusy}
      />
      <button class="search-btn" onclick={handleConnectInvite} type="button" disabled={inviteBusy}>
        {inviteBusy ? "…" : t("search.connect")}
      </button>
    </div>
    <p class="invite-hint">{t("search.inviteHint")}</p>
  </div>

  {#if selectedRecord}
    <div class="modal-overlay" role="presentation" onclick={(e) => { if (e.target === e.currentTarget) cancelSendRequest(); }}>
      <div class="modal" role="dialog" aria-modal="true" tabindex="-1" bind:this={modalEl} onkeydown={(e) => e.key === 'Escape' && cancelSendRequest()}>
        <div class="modal-header">
          <span>{t("search.modal.title")}</span>
          <span class="modal-target">{selectedRecord.nickname}#{selectedRecord.shortId}</span>
        </div>
        <textarea
          class="modal-textarea"
          placeholder={t("search.modal.message")}
          bind:value={requestMessage}
          rows="3"
        ></textarea>
        <div class="modal-actions">
          <button class="action-btn" onclick={cancelSendRequest} type="button">{t("common.cancel")}</button>
          <button class="action-btn primary" disabled={requestBusy} onclick={confirmSendRequest} type="button">{requestBusy ? t("search.modal.sending") : t("search.modal.send")}</button>
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .user-search {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .search-bar {
    display: flex;
    gap: 8px;
  }

  .search-input {
    flex: 1;
    padding: 12px 14px;
    border-radius: 12px;
    border: 1px solid var(--border-default);
    background: var(--bg-tertiary);
    color: var(--text-primary);
    font-size: 14px;
    outline: none;
    transition: border-color 0.2s;
  }

  .search-input:focus {
    border-color: var(--primary, var(--primary));
  }

  .search-btn {
    padding: 12px 20px;
    border-radius: 12px;
    border: none;
    background: var(--primary, var(--primary));
    color: var(--text-inverse);
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
  }

  .search-btn:hover {
    filter: brightness(1.1);
  }

  .searching-hint {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    color: var(--text-secondary);
  }

  .spinner {
    width: 14px;
    height: 14px;
    border: 2px solid var(--border-default);
    border-top-color: var(--primary, var(--primary));
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
  }

  .results-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .empty-hint {
    font-size: 13px;
    color: var(--text-tertiary);
    text-align: center;
    padding: 16px 0;
  }

  .invite-section {
    margin-top: 16px;
    padding-top: 16px;
    border-top: 1px solid var(--border-default);
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .invite-label {
    font-size: 11px;
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .search-input.mono {
    font-family: monospace;
    font-size: 12px;
  }

  .invite-hint {
    font-size: 12px;
    color: var(--text-tertiary);
    margin: 0;
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
    max-width: 380px;
    width: 90%;
  }

  .modal-header {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .modal-header span:first-child {
    font-size: 16px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .modal-target {
    font-size: 13px;
    color: var(--primary, var(--primary));
    font-family: monospace;
  }

  .modal-textarea {
    padding: 12px;
    border-radius: 12px;
    border: 1px solid var(--border-default);
    background: var(--bg-tertiary);
    color: var(--text-primary);
    font-size: 14px;
    outline: none;
    resize: none;
    font-family: inherit;
  }

  .modal-textarea:focus {
    border-color: var(--primary, var(--primary));
  }

  .modal-actions {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
  }

  .action-btn {
    padding: 10px 16px;
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
</style>
