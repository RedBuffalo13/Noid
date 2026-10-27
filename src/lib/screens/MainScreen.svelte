<script lang="ts">
  import { uiStore, chatStore, contactStore, profileStore, folderStore, usernameStore, roomStore } from "$lib/stores";
  import { formatId, formatTimestamp } from "$lib/utils/format";
  import { t, i18n } from "$lib/i18n/index.svelte";
  import { sendFile, createRoom, joinRoom, sendRoomMessage, inviteToRoom, getRoomMessages } from "$lib/services";
  import { getLastSyncTime } from "$lib/services";
  import SharedFoldersPanel from "$lib/components/settings/SharedFoldersPanel.svelte";
  import UsernameSettings from "$lib/components/settings/UsernameSettings.svelte";
  import RelaySettings from "$lib/components/settings/RelaySettings.svelte";
  import RoomSettings from "$lib/components/settings/RoomSettings.svelte";
  import UserSearch from "$lib/components/search/UserSearch.svelte";
  import NotificationSettings from "$lib/components/settings/NotificationSettings.svelte";
  import LanguageSettings from "$lib/components/settings/LanguageSettings.svelte";

  let roomId = $state("");
  let roomMsg = $state("");
  let lastSync = $state("");
  let fileInput = $state<HTMLInputElement | null>(null);
  let killPinInput = $state("");
  // FE-08: invites target an explicitly selected room — never the stale
  // chatStore.currentPeer left over from a previously open chat.
  let inviteRoomId = $state("");
  // FE-10: two-step confirms for destructive actions (RoomSettings pattern).
  let confirmDeleteChatPeer = $state("");
  let confirmDeleteContactPeer = $state("");
  let confirmWipe = $state(false);
  // FE-21: busy flags against double-submit through slow IPC calls.
  let fileBusy = $state(false);
  let roomBusy = $state(false);
  let inviteBusy = $state(false);
  let requestBusyPeer = $state("");

  // FE-25: side-effect loads belong in $effect, not in template {@const}.
  $effect(() => {
    if (uiStore.subPage === "settings") {
      loadSyncTime();
      folderStore.loadFolders();
      usernameStore.loadUsername();
    }
    if (uiStore.subPage === "create-room") {
      roomStore.loadRooms();
      inviteRoomId = "";
    }
  });

  /** FE-12: display name for the open chat peer — contact nickname first. */
  const currentPeerName = () =>
    contactStore.contacts.find(([p]) => p === chatStore.currentPeer)?.[1]
    || formatId(chatStore.currentPeer);
  const currentPeerOnline = () =>
    contactStore.onlinePeers.has(chatStore.currentPeer);

  const handleKillSwitch = async () => {
    if (!killPinInput.trim()) {
      uiStore.showToast(t("settings.wipe.needPin"));
      return;
    }
    if (!confirmWipe) {
      // FE-10: one-tap wipe is a footgun — require the second click.
      confirmWipe = true;
      return;
    }
    confirmWipe = false;
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      const result = await invoke("kill_switch", { pin: killPinInput }) as any;
      if (result && result.success) {
        uiStore.showToast(t("settings.wipe.done"));
        killPinInput = "";
        setTimeout(() => window.location.reload(), 2000);
      } else {
        uiStore.showToast(result?.message || t("settings.wipe.failed"));
        killPinInput = "";
      }
    } catch (e) {
      uiStore.showToast(t("contacts.toast.error", { e: String(e) }));
      killPinInput = "";
    }
  };

  const openChat = async (peerId: string) => {
    chatStore.currentPeer = peerId;
    uiStore.subPage = "chat-view";
    chatStore.messages = [];
    chatStore.clearUnread(peerId);
    await chatStore.loadMessages(peerId);
  };

  const deleteChatEntry = async (peerId: string) => {
    try {
      await chatStore.deleteChat(peerId);
      uiStore.showToast(t("chats.deleted"));
      confirmDeleteChatPeer = "";
      await contactStore.loadContacts();
    } catch (e) {
      uiStore.showToast(t("contacts.toast.error", { e: String(e) }));
    }
  };

  const deleteContactEntry = async (peerId: string) => {
    try {
      await contactStore.deleteContact(peerId);
      confirmDeleteContactPeer = "";
    } catch (e) {
      uiStore.showToast(t("contacts.toast.error", { e: String(e) }));
    }
  };

  const handleFileSelect = async () => {
    fileInput?.click();
  };

  const onFileChosen = async (e: Event) => {
    const input = e.target as HTMLInputElement;
    if (!input.files || !input.files[0] || !chatStore.currentPeer || fileBusy) return;
    fileBusy = true;
    uiStore.showToast(t("chat.toast.sendingFile"));
    try {
      await sendFile(chatStore.currentPeer, input.files[0]);
      uiStore.showToast(t("chat.toast.fileSent"));
    } catch (err) {
      console.error("File send failed:", err);
      uiStore.showToast(t("chat.toast.fileFailed"));
    } finally {
      fileBusy = false;
      input.value = "";
    }
  };

  const handleCreateRoom = async () => {
    if (!roomId.trim() || roomBusy) return;
    roomBusy = true;
    try {
      // The input is a room *name* — the room id is a fingerprint of the
      // freshly generated key, returned by the backend.
      const id = await createRoom(roomId.trim());
      uiStore.showToast(t("rooms.toast.created", { id: id.slice(0, 8) }));
      chatStore.currentPeer = id;
      chatStore.messages = [];
      await roomStore.loadRooms();
      roomStore.openSettings(id).catch(() => {});
      uiStore.subPage = "room-view";
      roomId = "";
    } catch (e) {
      console.error("Failed to create room:", e);
      uiStore.showToast(t("rooms.toast.createFailed"));
    } finally {
      roomBusy = false;
    }
  };

  const openRoom = async (id: string) => {
    try {
      await joinRoom(id);
      chatStore.currentPeer = id;
      chatStore.messages = (await getRoomMessages(id)).map(([msgId, sender, content, ts]) => ({
        id: msgId,
        from: sender,
        content,
        type: "received" as const,
        timestamp: Date.parse(ts) || Date.now(),
      }));
      // Load room details (name + member profiles) for the header and
      // sender labels — failures must not block opening the room.
      roomStore.openSettings(id).catch(() => {});
      uiStore.subPage = "room-view";
    } catch (e) {
      console.error("Failed to open room:", e);
      uiStore.showToast(t("rooms.toast.openFailed"));
    }
  };

  /** Sender label for room messages — announced member profile first,
   * bare peer id as fallback. Only resolves against the CURRENT room's
   * member list so a stale `current` can't mislabel senders. */
  const roomSenderName = (peer: string) =>
    roomStore.current?.id === chatStore.currentPeer
      ? roomStore.memberName(peer) ?? formatId(peer)
      : formatId(peer);

  const handleSendRoomMessage = async () => {
    if (!roomMsg.trim() || !chatStore.currentPeer) return;
    try {
      await sendRoomMessage(chatStore.currentPeer, roomMsg);
      chatStore.appendMessage({ from: "Me", content: roomMsg, type: "sent", timestamp: Date.now(), delivered: true, seen: false });
      roomMsg = "";
    } catch (e) {
      console.error("Failed to send room message:", e);
      uiStore.showToast(t("rooms.toast.sendFailed"));
    }
  };

  const handleInviteToRoom = async (peerId: string) => {
    // Two-phase invite: sends an OFFER — the peer must accept before the
    // room key is delivered. No eager approve here: membership flips to
    // approved when their RoomInviteAccept arrives.
    // FE-08: the target room is the one the user selected on this page —
    // chatStore.currentPeer may still point at an unrelated open chat.
    if (!inviteRoomId || inviteBusy) return;
    inviteBusy = true;
    try {
      await inviteToRoom(inviteRoomId, peerId);
      uiStore.showToast(t("rooms.toast.inviteSent"));
    } catch (e) {
      console.error("Failed to invite:", e);
      uiStore.showToast(t("rooms.toast.inviteFailed"));
    } finally {
      inviteBusy = false;
    }
  };

  const openRoomSettings = async () => {
    if (!chatStore.currentPeer) return;
    try {
      await roomStore.openSettings(chatStore.currentPeer);
      uiStore.subPage = "room-settings";
    } catch (e) {
      console.error("Failed to load room:", e);
      uiStore.showToast(t("rooms.toast.loadFailed"));
    }
  };

  const loadSyncTime = async () => {
    try {
      lastSync = await getLastSyncTime();
    } catch (e) {
      lastSync = t("settings.never");
    }
  };

</script>

<svelte:window onpopstate={() => { if (!uiStore.navBack()) uiStore.resetNav("chats"); }} />

<header>
  {#if uiStore.subPage === "chats"}
    <div class="header-user">
      <div class="avatar">{#if profileStore.avatar}<img src={profileStore.avatar} alt="Me" />{:else}{profileStore.nickname.charAt(0)}{/if}</div>
      <div class="header-info"><span class="header-name">{profileStore.nickname}</span><span class="header-id">{chatStore.myId || t("nav.connecting")}</span></div>
    </div>
    <div style="display:flex;gap:8px;">
      <button class="num-btn" style="width:44px;height:44px;border-radius:14px;" onclick={() => uiStore.subPage = "contacts"} aria-label={t("nav.contacts")}><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg></button>
      <button class="num-btn" style="width:44px;height:44px;border-radius:14px;position:relative;" onclick={() => uiStore.subPage = "received-requests"} aria-label={t("nav.requests")}><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><path d="M12 7v2"/><path d="M12 13h.01"/></svg>{#if contactStore.contactRequests.length + roomStore.pendingInvites.length > 0}<span class="badge">{contactStore.contactRequests.length + roomStore.pendingInvites.length}</span>{/if}</button>
      <button class="num-btn" style="width:44px;height:44px;border-radius:14px;" onclick={() => uiStore.subPage = "create-room"} aria-label={t("nav.createRoom")}><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 21v-2a4 4 0 0 1 4-4h9a4 4 0 0 1 4 4v2"/><circle cx="10" cy="7" r="4"/><path d="M19 8v6"/><path d="M22 11h-6"/></svg></button>
      <button class="num-btn" style="width:44px;height:44px;border-radius:14px;" onclick={() => uiStore.subPage = "settings"} aria-label={t("nav.settings")}><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg></button>
    </div>
  {:else}
    <div class="header-user">
      {#if uiStore.subPage === "chat-view"}
        <span class="header-name" style="font-size:18px;">{currentPeerName()}</span>
        <span class="peer-status" class:online={currentPeerOnline()}>{currentPeerOnline() ? t("chat.online") : t("chat.offline")}</span>
      {:else}
        <span class="header-name" style="font-size:18px;text-transform:capitalize;">{uiStore.subPage === "room-view" && roomStore.current?.id === chatStore.currentPeer ? roomStore.current.name : uiStore.subPage.replace("-", " ")}</span>
      {/if}
    </div>
    <div style="display:flex;gap:8px;">
      {#if uiStore.subPage === "room-view"}
        <button class="num-btn" style="width:44px;height:44px;border-radius:14px;" onclick={openRoomSettings} aria-label={t("nav.roomSettings")}><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33 1.65 1.65 0 0 0-2.83 0l-.06.06a1.65 1.65 0 0 0-1.51 1H3a2 2 0 0 1-2-2v-.09a1.65 1.65 0 0 0 .33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1.51 1 1.65 1.65 0 0 0 1 .82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.51-1V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82-.33l-.06-.06a2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.51 1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0 .33-1.82l.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.51 1H9a2 2 0 0 1 2-2 2 2 0 0 1 2-2h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0 1-.82l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06A1.65 1.65 0 0 0 19.4 15z"/></svg></button>
      {/if}
      <button class="num-btn special" style="height:44px;padding:0 16px;border-radius:14px;" onclick={() => history.back()}>{t("nav.back")}</button>
    </div>
  {/if}
</header>

<main class="content-wrapper">
  {#if uiStore.subPage === "chats"}
    <div class="scroll-content">
      <span class="label">{t("chats.title")}</span>
      {#each contactStore.chatList as chat}
        <div class="chat-card" style="display:flex;align-items:center;">
          <button class="chat-card-btn" style="flex:1;display:flex;align-items:center;background:none;border:none;padding:12px;cursor:pointer;min-width:0;" onclick={() => openChat(chat.id)}>
            <div class="avatar">{#if chat.avatar}<img src={chat.avatar} alt="Avatar" />{:else}{chat.name.charAt(0)}{/if}{#if chat.isOnline}<div class="online-indicator online"></div>{:else}<div class="online-indicator offline"></div>{/if}</div>
            <div class="chat-main"><div class="chat-header"><span class="chat-name">{chat.name}</span><span class="chat-time">{chat.lastMsgTime ? formatTimestamp(chat.lastMsgTime) : ""}</span></div><div class="chat-msg">{chat.lastMsg}</div></div>
            {#if chat.unread > 0}<span class="unread-badge">{chat.unread}</span>{/if}
          </button>
          {#if confirmDeleteChatPeer === chat.id}
            <button class="num-btn" style="min-height:44px;padding:0 10px;border-radius:10px;margin-left:8px;flex-shrink:0;background:color-mix(in srgb, var(--error) 25%, transparent);color:var(--error);" onclick={() => deleteChatEntry(chat.id)}>{t("chats.confirmDelete")}</button>
            <button class="num-btn" style="min-height:44px;min-width:44px;height:44px;width:44px;border-radius:50%;flex-shrink:0;" onclick={() => confirmDeleteChatPeer = ""} aria-label={t("common.cancel")}>✕</button>
          {:else}
            <button class="num-btn" style="min-height:44px;min-width:44px;height:44px;width:44px;border-radius:50%;margin-left:8px;flex-shrink:0;" onclick={() => confirmDeleteChatPeer = chat.id} title={t("chats.delete")} aria-label={t("chats.delete")}>×</button>
          {/if}
        </div>
      {:else}
        <div class="empty-state"><p>{t("chats.empty")}</p></div>
      {/each}
    </div>
  {:else if uiStore.subPage === "contacts"}
    <div class="scroll-content">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;"><span class="label">{t("contacts.title")}</span><button class="num-btn special" style="min-height:44px;padding:0 12px;border-radius:10px;font-size:12px;" onclick={() => uiStore.subPage = "send-request"}>{t("contacts.addNew")}</button></div>
      {#each contactStore.contacts as contact}
        <div class="chat-card" style="display:flex;align-items:center;">
          <button class="chat-card-btn" style="flex:1;display:flex;align-items:center;background:none;border:none;padding:12px;cursor:pointer;" onclick={() => openChat(contact[0])}>
            <div class="avatar">{#if contact[2]}<img src={contact[2]} alt="Avatar" />{:else}{contact[1]?.charAt(0) || "?"}{/if}{#if contactStore.onlinePeers.has(contact[0])}<div class="online-indicator online"></div>{:else}<div class="online-indicator offline"></div>{/if}</div>
            <div class="chat-main" style="margin-left:12px;"><span class="chat-name">{contact[1] || t("contacts.unknown")}</span><span class="chat-msg">{formatId(contact[0])}</span></div>
          </button>
          {#if confirmDeleteContactPeer === contact[0]}
            <button class="num-btn" style="min-height:44px;padding:0 10px;border-radius:10px;margin-left:8px;background:color-mix(in srgb, var(--error) 25%, transparent);color:var(--error);" onclick={() => deleteContactEntry(contact[0])}>{t("chats.confirmDelete")}</button>
            <button class="num-btn" style="min-height:44px;min-width:44px;height:44px;width:44px;border-radius:50%;" onclick={() => confirmDeleteContactPeer = ""} aria-label={t("common.cancel")}>✕</button>
          {:else}
            <button class="num-btn" style="min-height:44px;min-width:44px;height:44px;width:44px;border-radius:50%;margin-left:8px;" onclick={() => confirmDeleteContactPeer = contact[0]} title={t("contacts.delete")} aria-label={t("contacts.delete")}>×</button>
          {/if}
        </div>
      {:else}
        <div class="empty-state"><p>{t("contacts.empty")}</p></div>
      {/each}
      {#if contactStore.contactRequests.length > 0}
        <div style="margin-top:24px;"><span class="label">{t("contacts.incoming")}</span>
          {#each contactStore.contactRequests as req}
            <div class="chat-card" style="cursor:default;">
              <div class="avatar">{#if req[3]}<img src={req[3]} alt="Avatar" />{:else}{req[2]?.charAt(0) || "?"}{/if}</div>
              <div class="chat-main"><span class="chat-name">{req[2] || formatId(req[0])}</span><span class="chat-msg">{req[1]}</span><span class="chat-time" style="font-size:10px;color:var(--text-tertiary);">{formatId(req[0])}</span></div>
              <button class="num-btn special" disabled={requestBusyPeer === req[0]} style="min-height:44px;padding:0 12px;border-radius:10px;" onclick={async () => { requestBusyPeer = req[0]; try { await contactStore.acceptRequest(req[0]); } finally { requestBusyPeer = ""; } }}>{t("requests.accept")}</button>
            </div>
          {/each}
        </div>
      {/if}
    </div>
  {:else if uiStore.subPage === "send-request"}
    <div class="settings-view">
      <UserSearch />
    </div>
  {:else if uiStore.subPage === "settings"}
    <div class="settings-view" data-entered="true">
      <div class="avatar-upload">
        <div class="avatar avatar-large">{#if profileStore.avatar}<img src={profileStore.avatar} alt="Profile" />{:else}{profileStore.nickname.charAt(0)}{/if}</div>
        <button class="upload-overlay" onclick={() => profileStore.pickAvatar()} aria-label={t("profile.uploadAvatar")}><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg></button>
      </div>
      <div class="form-group"><label class="label" for="nickname">{t("settings.publicName")}</label><input id="nickname" type="text" class="input-box" bind:value={profileStore.nickname} onkeydown={(e) => e.key === "Enter" && profileStore.saveProfile()} /></div>
      <div style="margin-top:16px;border-top:1px solid var(--border-default);padding-top:16px;">
        <UsernameSettings />
      </div>
      <div class="form-group"><label class="label" for="peer-id">{t("settings.myPeerId")}</label><div style="display:flex;gap:8px;"><input id="peer-id" type="text" class="input-box mono flex-1" readonly value={chatStore.myId} /><button class="num-btn special" style="width:64px;border-radius:16px;font-size:13px;" onclick={() => profileStore.copyId(chatStore.myId)}>{t("settings.copy")}</button></div></div>
      <button class="btn-wide" style="margin-top:10px;" onclick={() => profileStore.saveProfile()}>{t("settings.save")}</button>
      <div style="margin-top:24px;border-top:1px solid var(--border-default);padding-top:16px;">
        <SharedFoldersPanel />
      </div>
      <div style="margin-top:24px;border-top:1px solid var(--border-default);padding-top:0;">
        <RelaySettings />
      </div>
      <div style="margin-top:24px;border-top:1px solid var(--border-default);padding-top:16px;">
        <LanguageSettings />
      </div>
      <div style="margin-top:24px;border-top:1px solid var(--border-default);padding-top:16px;">
        <NotificationSettings />
      </div>
      <div style="margin-top:16px;">
        <span class="label">{t("settings.lastSync")}</span>
        <div style="display:flex;gap:8px;align-items:center;margin-top:6px;">
          <span style="font-size:14px;color:var(--text-secondary);">{lastSync || t("settings.never")}</span>
          <button class="num-btn special" style="min-height:44px;padding:0 12px;border-radius:10px;font-size:12px;" onclick={loadSyncTime}>{t("settings.refresh")}</button>
        </div>
      </div>
      <div style="margin-top:24px;border-top:1px solid var(--border-default);padding-top:16px;">
        <span class="label" style="color:var(--error);">{t("settings.wipe.title")}</span>
        <p style="font-size:13px;color:var(--text-secondary);margin:6px 0 12px 0;">{t("settings.wipe.desc")}</p>
        <div style="display:flex;gap:8px;">
          <input id="kill-pin" type="password" class="input-box" style="flex:1;" placeholder={t("settings.wipe.placeholder")} bind:value={killPinInput} />
          <button class="num-btn" style="height:44px;padding:0 16px;border-radius:12px;background:var(--error);color:var(--text-on-accent);font-weight:600;" onclick={handleKillSwitch}>{confirmWipe ? t("settings.wipe.confirm") : t("settings.wipe.button")}</button>
          {#if confirmWipe}
            <button class="num-btn" style="height:44px;padding:0 12px;border-radius:12px;" onclick={() => confirmWipe = false}>{t("common.cancel")}</button>
          {/if}
        </div>
      </div>
    </div>
  {:else if uiStore.subPage === "chat-view"}
    <div style="display:flex;flex-direction:column;height:100%;">
      <div class="message-list" role="log" aria-live="polite" aria-label={t("chat.messages")}>
        {#each chatStore.messages as msg}
          <div class="msg-bubble {msg.type}">
            <div class="msg-content">{msg.content}</div>
            <span class="msg-time">{formatTimestamp(msg.timestamp)}</span>
            {#if msg.type === 'sent'}
              <div class="delivery-status">
                {#if msg.status === 'sending'}<span class="sending-indicator">↻</span>
                {:else if msg.status === 'failed'}<span class="failed-indicator">✕</span>
                {:else if msg.seen}<span class="seen-indicator">✓✓</span>
                {:else if msg.status === 'delivered'}<span class="delivered-indicator">✓✓</span>
                {:else if msg.status === 'sent'}<span class="sent-indicator">✓</span>
                {:else if msg.delivered}<span class="delivered-indicator">✓</span>
                {:else}<span class="pending-indicator">○</span>{/if}
              </div>
            {/if}
          </div>
        {:else}
          <div class="empty-state"><p>{t("chat.empty")}</p></div>
        {/each}
        {#if chatStore.typingFrom === chatStore.currentPeer}
          <div class="msg-bubble received typing-bubble" aria-live="polite"><span class="typing-dots">{t("chat.typing")}</span></div>
        {/if}
      </div>
      <div class="input-bar">
        <input type="file" bind:this={fileInput} onchange={onFileChosen} style="display:none;" />
        <button class="num-btn" style="width:44px;height:44px;border-radius:12px;flex-shrink:0;" onclick={handleFileSelect} aria-label={t("chat.sendFile")}><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg></button>
        <input type="text" class="input-box" style="flex:1;" placeholder={t("chat.placeholder")} bind:value={chatStore.inputMsg} oninput={() => chatStore.notifyTyping()} onkeydown={(e) => e.key === "Enter" && chatStore.sendMessage()} />
        <button class="send-btn" onclick={() => chatStore.sendMessage()} aria-label={t("chat.send")}><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg></button>
      </div>
    </div>
  {:else if uiStore.subPage === "create-room"}
    <div class="settings-view">
      <span class="label">{t("rooms.createTitle")}</span>
      <div class="form-group" style="margin-top:8px;"><label class="label" for="room-id">{t("rooms.name")}</label><input id="room-id" type="text" class="input-box mono" placeholder={t("rooms.namePlaceholder")} bind:value={roomId} onkeydown={(e) => e.key === "Enter" && handleCreateRoom()} /></div>
      <button class="btn-wide" disabled={roomBusy} onclick={handleCreateRoom}>{roomBusy ? t("rooms.creating") : t("rooms.create")}</button>
      {#if roomStore.rooms.length > 0}
        <div style="margin-top:16px;">
          <span class="label">{t("rooms.myRooms")}</span>
          {#each roomStore.rooms as room}
            <div class="chat-card" style="display:flex;align-items:center;">
              <button class="chat-card-btn" style="flex:1;display:flex;align-items:center;background:none;border:none;padding:12px;cursor:pointer;min-width:0;" onclick={() => openRoom(room[0])}>
                <div class="avatar" style="width:36px;height:36px;font-size:14px;">{room[1]?.charAt(0) || "#"}</div>
                <div class="chat-main" style="margin-left:12px;"><span class="chat-name" style="font-size:14px;">{room[1] || room[0]}</span></div>
              </button>
              <button
                class="num-btn"
                class:special={inviteRoomId === room[0]}
                style="min-height:44px;padding:0 12px;border-radius:10px;font-size:12px;flex-shrink:0;"
                onclick={() => inviteRoomId = inviteRoomId === room[0] ? "" : room[0]}
              >{inviteRoomId === room[0] ? t("rooms.selected") : t("rooms.invite")}</button>
            </div>
          {/each}
        </div>
      {:else}
        <div class="empty-state"><p>{t("rooms.empty")}</p></div>
      {/if}
      {#if inviteRoomId && contactStore.contacts.length > 0}
        <div style="margin-top:24px;">
          <span class="label">{t("rooms.inviteContactsTo", { name: roomStore.rooms.find(([id]) => id === inviteRoomId)?.[1] || inviteRoomId })}</span>
          {#each contactStore.contacts as contact}
            <div class="chat-card" style="display:flex;align-items:center;cursor:default;">
              <div class="avatar" style="width:36px;height:36px;font-size:14px;">{contact[1]?.charAt(0) || "?"}</div>
              <div class="chat-main" style="margin-left:12px;"><span class="chat-name" style="font-size:14px;">{contact[1] || t("contacts.unknown")}</span></div>
              <button class="num-btn special" disabled={inviteBusy} style="min-height:44px;padding:0 12px;border-radius:10px;font-size:12px;" onclick={() => handleInviteToRoom(contact[0])}>{t("rooms.invite")}</button>
            </div>
          {/each}
        </div>
      {/if}
    </div>
  {:else if uiStore.subPage === "room-view"}
    <div style="display:flex;flex-direction:column;height:100%;">
      <div class="message-list" role="log" aria-live="polite" aria-label={t("rooms.messages")}>
        {#each chatStore.messages as msg}
          <div class="msg-bubble {msg.type}">
            {#if msg.type === "received" && msg.from}
              <div class="msg-sender">{roomSenderName(msg.from)}</div>
            {/if}
            <div class="msg-content">{msg.content}</div>
            <span class="msg-time">{formatTimestamp(msg.timestamp)}</span>
          </div>
        {:else}
          <div class="empty-state"><p>{t("rooms.emptyChat")}</p></div>
        {/each}
      </div>
      <div class="input-bar">
        <input type="text" class="input-box" style="flex:1;" placeholder={t("rooms.messagePlaceholder")} bind:value={roomMsg} onkeydown={(e) => e.key === "Enter" && handleSendRoomMessage()} />
        <button class="send-btn" onclick={handleSendRoomMessage} aria-label={t("rooms.sendMessage")}><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg></button>
      </div>
    </div>
  {:else if uiStore.subPage === "room-settings"}
    <RoomSettings />
  {:else if uiStore.subPage === "received-requests"}
    <div class="scroll-content">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;"><span class="label">{t("requests.title")}</span></div>
      {#if contactStore.contactRequests.length > 0}
        {#each contactStore.contactRequests as req}
          <div class="chat-card" style="cursor:default;">
            <div class="avatar">?</div>
            <div class="chat-main"><span class="chat-name">{formatId(req[0])}</span><span class="chat-msg">{req[1]}</span></div>
            <div style="display:flex;gap:8px;">
              <button class="num-btn special" disabled={requestBusyPeer === req[0]} style="min-height:44px;padding:0 12px;border-radius:10px;" onclick={async () => { requestBusyPeer = req[0]; try { await contactStore.acceptRequest(req[0]); } finally { requestBusyPeer = ""; } }}>{t("requests.accept")}</button>
              <button class="num-btn" disabled={requestBusyPeer === req[0]} style="min-height:44px;padding:0 12px;border-radius:10px;" onclick={async () => { requestBusyPeer = req[0]; try { await contactStore.denyRequest(req[0]); } finally { requestBusyPeer = ""; } }}>{t("contacts.deny")}</button>
            </div>
          </div>
        {/each}
      {:else}
        <div class="empty-state"><p>{t("requests.empty")}</p></div>
      {/if}
      {#if roomStore.pendingInvites.length > 0}
        <div style="display:flex;justify-content:space-between;align-items:center;margin:16px 0 8px;"><span class="label">{t("requests.roomInvites")}</span></div>
        {#each roomStore.pendingInvites as inv}
          <div class="chat-card" style="cursor:default;">
            <div class="avatar">{#if inv.avatar}<img src={inv.avatar} alt="" style="width:100%;height:100%;border-radius:50%;object-fit:cover;" />{:else}?{/if}</div>
            <div class="chat-main"><span class="chat-name">{inv.name ?? t("requests.room")}</span><span class="chat-msg">{t("requests.from", { name: contactStore.contacts.find(([p]) => p === inv.inviter)?.[1] ?? formatId(inv.inviter) })}</span></div>
            <div style="display:flex;gap:8px;">
              <button class="num-btn special" style="min-height:44px;padding:0 12px;border-radius:10px;" onclick={() => roomStore.acceptInvite(inv.room_id)}>{t("requests.accept")}</button>
              <button class="num-btn" style="min-height:44px;padding:0 12px;border-radius:10px;" onclick={() => roomStore.declineInvite(inv.room_id)}>{t("requests.decline")}</button>
            </div>
          </div>
        {/each}
      {/if}
    </div>
  {/if}
</main>

<style>
  .badge { position:absolute; top:-5px; right:-5px; background:var(--error); color:var(--text-on-accent); border-radius:50%; width:18px; height:18px; font-size:10px; display:flex; align-items:center; justify-content:center; font-weight:bold; }
  .msg-sender { font-size:11px; opacity:0.6; margin-bottom:2px; font-family:monospace; }
  .unread-badge { position:absolute; top:50%; right:12px; transform:translateY(-50%); background:var(--primary); color:var(--text-on-accent); border-radius:50%; width:20px; height:20px; font-size:11px; display:flex; align-items:center; justify-content:center; font-weight:bold; }
  .empty-state { display:flex; flex-direction:column; align-items:center; justify-content:center; padding:40px 20px; text-align:center; color:var(--text-tertiary); }
  .chat-card-btn { text-align:left; }
  .online-indicator { position:absolute; bottom:0; right:0; width:12px; height:12px; border-radius:50%; border:2px solid var(--bg-secondary); }
  .online-indicator.online { background:var(--success); }
  .online-indicator.offline { background:var(--error); }
  .msg-content { display:inline-block; margin-right:16px; }
  .msg-time { font-size:10px; opacity:0.55; margin-left:8px; }
  .peer-status { font-size:12px; color:var(--text-secondary); }
  .peer-status.online { color:var(--success); }
  .delivery-status { float:right; margin-left:8px; font-size:10px; }
  .delivered-indicator { color:var(--success); }
  .pending-indicator { color:var(--text-secondary); }
  .sending-indicator { color:var(--info); }
  .sent-indicator { color:var(--info); }
  .failed-indicator { color:var(--error); }
  .seen-indicator { color:var(--info); }
  .typing-bubble { font-size:13px; opacity:0.7; font-style:italic; }
  .form-group { margin-bottom:16px; }
  .label { display:block; margin-bottom:6px; font-size:14px; font-weight:500; color:var(--text-primary); }
  .input-box { width:100%; padding:12px; border-radius:12px; border:1px solid var(--border-default); background-color:var(--bg-tertiary); color:var(--text-primary); font-size:16px; }
  .btn-wide { width:100%; padding:14px; border-radius:14px; border:none; background-color:var(--primary); color:var(--text-on-accent); font-size:16px; font-weight:600; cursor:pointer; }
</style>
