<script lang="ts">
  import { roomStore, contactStore, uiStore } from "$lib/stores";
  import { formatId } from "$lib/utils/format";
  import { t } from "$lib/i18n/index.svelte";

  let editName = $state("");
  let confirmDelete = $state(false);
  let confirmLeave = $state(false);
  let kickTarget = $state<string | null>(null);
  let error = $state("");

  const room = $derived(roomStore.current);
  const memberIds = $derived(new Set((room?.members ?? []).map((m) => m.peerId)));
  /** Members minus the owner — the owner has a dedicated row above. */
  const displayMembers = $derived(
    (room?.members ?? []).filter((m) => m.peerId !== room?.owner)
  );
  const invitable = $derived(
    contactStore.contacts.filter(([peer]) => !memberIds.has(peer) && peer !== room?.owner)
  );

  /** Display name for any peer — member profile → contact → short id. */
  const peerName = (peer: string | null | undefined) => {
    if (!peer) return t("roomSettings.unknown");
    if (peer === roomStore.myId) return t("roomSettings.you");
    return (
      roomStore.memberName(peer) ??
      contactStore.contacts.find(([p]) => p === peer)?.[1] ??
      formatId(peer)
    );
  };
  const peerAvatar = (peer: string | null | undefined) => {
    if (!peer) return null;
    return (
      roomStore.memberAvatar(peer) ??
      contactStore.contacts.find(([p]) => p === peer)?.[2] ??
      null
    );
  };

  $effect(() => {
    if (room && editName === "") editName = room.name;
  });

  const run = async (fn: () => Promise<void>, errMsg: string) => {
    error = "";
    try { await fn(); } catch (e) { console.error(errMsg, e); error = errMsg; }
  };
</script>

{#if room}
  <div class="settings-view" data-entered="true">
    <div class="avatar-upload">
      <div class="avatar avatar-large">
        {#if room.avatar}<img src={room.avatar} alt="Room" />{:else}{room.name.charAt(0)}{/if}
      </div>
      {#if roomStore.isOwner}
        <button class="upload-overlay" onclick={() => roomStore.pickAvatar()} aria-label={t("roomSettings.avatar")}>
          <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg>
        </button>
      {/if}
    </div>

    {#if error}<p style="color:var(--error);font-size:13px;margin:8px 0;">{error}</p>{/if}

    <div class="form-group">
      <label class="label" for="room-name">{t("roomSettings.name")}</label>
      <div style="display:flex;gap:8px;">
        <input id="room-name" type="text" class="input-box flex-1" maxlength="128"
          bind:value={editName} disabled={!roomStore.isOwner} />
        {#if roomStore.isOwner}
          <button class="num-btn special" style="width:64px;border-radius:14px;font-size:13px;"
            onclick={() => run(() => roomStore.rename(editName), t("roomSettings.err.rename"))}>{t("roomSettings.save")}</button>
        {/if}
      </div>
    </div>

    <div style="margin-top:20px;">
      <span class="label">{t("roomSettings.members", { n: displayMembers.length + 1 })}</span>
      <div class="chat-card" style="cursor:default;display:flex;align-items:center;">
        <div class="avatar" style="min-width:44px;min-height:44px;font-size:13px;">
          {#if peerAvatar(room.owner)}<img src={peerAvatar(room.owner)} alt="" />{:else}★{/if}
        </div>
        <div class="chat-main" style="margin-left:12px;">
          <span class="chat-name" style="font-size:14px;">{peerName(room.owner)}</span>
          <span class="chat-msg">{room.owner ? t("roomSettings.owner") : t("roomSettings.ownerUnknown")}</span>
        </div>
      </div>
      {#each displayMembers as m (m.peerId)}
        <div class="chat-card" style="cursor:default;display:flex;align-items:center;">
          <div class="avatar" style="min-width:44px;min-height:44px;font-size:13px;">
            {#if m.avatar}<img src={m.avatar} alt="" />{:else}{(m.name ?? m.peerId).charAt(0)}{/if}
          </div>
          <div class="chat-main" style="margin-left:12px;">
            <span class="chat-name" style="font-size:14px;">{m.peerId === roomStore.myId ? t("roomSettings.you") : peerName(m.peerId)}</span>
            <span class="chat-msg">{!m.approved ? t("roomSettings.invited") : m.name ? formatId(m.peerId) : ""}</span>
          </div>
          {#if roomStore.isOwner && m.peerId !== roomStore.myId}
            {#if kickTarget === m.peerId}
              <button class="num-btn" style="min-height:44px;padding:0 10px;border-radius:10px;margin-left:8px;background:var(--error);color:var(--text-on-accent);font-size:12px;font-weight:600;"
                onclick={() => run(async () => { kickTarget = null; await roomStore.kick(m.peerId); }, t("roomSettings.err.kick"))}>{t("roomSettings.kick")}</button>
              <button class="num-btn" style="min-height:44px;min-width:44px;border-radius:50%;margin-left:6px;"
                onclick={() => kickTarget = null} aria-label={t("common.cancel")}>↩</button>
            {:else}
              {#if !m.approved}
                <button class="num-btn special" style="min-height:44px;padding:0 10px;border-radius:10px;margin-left:8px;font-size:12px;"
                  onclick={() => run(() => roomStore.approve(m.peerId), t("roomSettings.err.approve"))}>{t("roomSettings.approve")}</button>
              {/if}
              <button class="num-btn" style="min-height:44px;min-width:44px;border-radius:50%;margin-left:8px;"
                onclick={() => kickTarget = m.peerId} title={t("roomSettings.remove")} aria-label={t("roomSettings.remove")}>×</button>
            {/if}
          {/if}
        </div>
      {/each}
    </div>

    {#if roomStore.isOwner && invitable.length > 0}
      <div style="margin-top:20px;">
        <span class="label">{t("roomSettings.inviteContacts")}</span>
        {#each invitable as contact}
          <div class="chat-card" style="cursor:default;display:flex;align-items:center;">
            <div class="avatar" style="min-width:44px;min-height:44px;font-size:13px;">
              {#if contact[2]}<img src={contact[2]} alt="" />{:else}{contact[1]?.charAt(0) || "?"}{/if}
            </div>
            <div class="chat-main" style="margin-left:12px;">
              <span class="chat-name" style="font-size:14px;">{contact[1] || t("contacts.unknown")}</span>
            </div>
            <button class="num-btn special" style="min-height:44px;padding:0 12px;border-radius:10px;font-size:12px;"
              onclick={() => run(() => roomStore.invite(contact[0]), t("roomSettings.err.invite"))}>{t("rooms.invite")}</button>
          </div>
        {/each}
      </div>
    {/if}

    <div style="margin-top:28px;border-top:1px solid var(--border-default);padding-top:16px;">
      {#if roomStore.isOwner}
        {#if confirmDelete}
          <p style="font-size:13px;color:var(--text-secondary);margin:0 0 8px 0;">{t("roomSettings.delete.desc")}</p>
          <div style="display:flex;gap:8px;">
            <button class="num-btn" style="flex:1;min-height:44px;border-radius:12px;background:var(--error);color:var(--text-on-accent);font-weight:600;"
              onclick={() => run(async () => { confirmDelete = false; await roomStore.remove(); }, t("roomSettings.err.delete"))}>{t("roomSettings.delete.confirm")}</button>
            <button class="num-btn special" style="flex:1;min-height:44px;border-radius:12px;" onclick={() => confirmDelete = false}>{t("common.cancel")}</button>
          </div>
        {:else}
          <button class="btn-wide" style="background:color-mix(in srgb, var(--error) 25%, transparent);color:var(--error);" onclick={() => confirmDelete = true}>{t("roomSettings.delete.button")}</button>
        {/if}
      {:else}
        {#if confirmLeave}
          <p style="font-size:13px;color:var(--text-secondary);margin:0 0 8px 0;">{t("roomSettings.leave.desc")}</p>
          <div style="display:flex;gap:8px;">
            <button class="num-btn" style="flex:1;min-height:44px;border-radius:12px;background:var(--error);color:var(--text-on-accent);font-weight:600;"
              onclick={() => run(async () => { confirmLeave = false; await roomStore.leave(); }, t("roomSettings.err.leave"))}>{t("roomSettings.leave.confirm")}</button>
            <button class="num-btn special" style="flex:1;min-height:44px;border-radius:12px;" onclick={() => confirmLeave = false}>{t("common.cancel")}</button>
          </div>
        {:else}
          <button class="btn-wide" style="background:color-mix(in srgb, var(--error) 25%, transparent);color:var(--error);" onclick={() => confirmLeave = true}>{t("roomSettings.leave.button")}</button>
        {/if}
      {/if}
    </div>
  </div>
{:else}
  <div class="settings-view"><p style="color:var(--text-secondary);">Room not found.</p></div>
{/if}
