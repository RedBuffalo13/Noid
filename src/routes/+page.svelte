<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { authStore, uiStore, chatStore, contactStore, usernameStore } from "$lib/stores";
  import AuthScreen from "$lib/screens/AuthScreen.svelte";
  import MainScreen from "$lib/screens/MainScreen.svelte";
  import type { ChatMsgEvent, MessageReadEvent, MessageFailedEvent, Unlistener } from "$lib/types/events";
  import { t } from "$lib/i18n/index.svelte";
  import {
    initializeNotifications,
    notifyChatMessage,
    notifyContactRequest,
    notifyContactAccepted,
    notifyRoomMessage,
    notifyRoomInvite,
  } from "$lib/notifications";

  onMount(() => {
    let unlisteners: Unlistener[] = [];
    // FE-24: if the component unmounts mid-setup (HMR, fast navigation),
    // listeners registered after the cleanup ran would leak — the flag
    // makes every post-await registration self-cleaning.
    let cancelled = false;
    const reg = async (p: Promise<Unlistener>) => {
      const u = await p;
      if (cancelled) u(); else unlisteners.push(u);
    };
    const setup = async () => {
      await authStore.checkFirstRun();
      await initializeNotifications();

      await reg(listen<ChatMsgEvent>("chat-msg", async (event) => {
        const from = event.payload.from;
        const data = event.payload.data;
        const isActiveChat = uiStore.subPage === "chat-view" && from === chatStore.currentPeer;
        if (isActiveChat) {
          chatStore.appendMessage({
            id: data.id,
            from,
            content: data.content,
            type: "received",
            timestamp: Date.now()
          });
          // Phase D.2: Send read receipt for messages in active chat
          if (data.id) {
            try {
              await invoke("send_read_receipt", { peerId: from, messageId: data.id });
            } catch (e) {
              console.warn("Failed to send read receipt:", e);
            }
          }
        } else {
          // Phase D.1: Increment unread count for background messages
          chatStore.incrementUnread(from);
          uiStore.showToast(t("toast.newMessage", { from: from.slice(0, 5) }));
          await contactStore.loadContacts();
        }
        // OS notification for background chats or a hidden/unfocused window
        // (toasts are invisible while the app sits in the tray).
        if (!isActiveChat || !document.hasFocus()) {
          await notifyChatMessage(from, data.content ?? "", usernameStore.username ?? undefined);
        }
        if (from === chatStore.currentPeer) chatStore.markDeliveredToCurrentPeer();
      }));

      await reg(listen<[string, unknown]>("p2p-request", (event) => {
        contactStore.loadContacts();
        const [from] = event.payload;
        notifyContactRequest(from);
      }));
      // TI-6: an accepted request is not a new request — separate event.
      await reg(listen<[string, unknown]>("contact-accepted", (event) => {
        contactStore.loadContacts();
        const [from] = event.payload;
        notifyContactAccepted(from);
      }));
      // IPC-01: post-login sync is bound to `my-id` — the backend emits it
      // only after login unlocked the DB and the P2P node started, so every
      // invoke below can actually succeed. The pre-login init block at the
      // bottom of setup() is a best-effort mirror (it fails closed before
      // PIN entry and used to swallow checkAllMissedMessages entirely).
      const postLoginSync = async () => {
        try {
          const snap = await invoke<{ my_id: string; connected_peers: string[] }>("get_network_snapshot");
          contactStore.clearOnline();
          snap.connected_peers.forEach((p) => contactStore.setOnline(p));
        } catch (e) { console.error("snapshot failed", e); }
        await contactStore.loadContacts();
        try { await invoke("reconnect_to_contacts"); } catch {}
        try { await chatStore.checkAllMissedMessages(); } catch (e) { console.error("missed sync failed", e); }
        try { await invoke("update_last_sync_time"); } catch {}
      };
      await reg(listen<string>("my-id", async (event) => {
        chatStore.myId = event.payload;
        roomStore.myId = event.payload;
        if (event.payload === "Wiped") {
          contactStore.clearOnline();
          return;
        }
        if (event.payload && !event.payload.startsWith("Pending")) {
          await postLoginSync();
        }
      }));

      // Surface node init failures (e.g. unavailable transports on mobile)
      // instead of leaving a bare "P2P not initialized" on every action.
      await reg(listen<string>("p2p-error", (event) => {
        uiStore.showToast(t("toast.p2pError", { e: event.payload }));
      }));

      // TI-11: node incarnation died while the gate stayed open — the
      // backend respawns it; show honest "reconnecting" state.
      // IPC-02: backend cleared connected_peers but emits no
      // peer-disconnected events — the UI must drop its stale online set
      // too or dead peers show "Online" until restart.
      await reg(listen<{ retry_in_secs: number }>("p2p-restarting", (event) => {
        contactStore.clearOnline();
        uiStore.showToast(t("toast.p2pRestarting", { s: event.payload.retry_in_secs }));
      }));

      await reg(listen<MessageReadEvent>("message-read", (event) => {
        const { from, message_id } = event.payload;
        chatStore.messages = chatStore.messages.map(msg => {
          if (msg.from === "Me" && msg.id === message_id) {
            return { ...msg, seen: true };
          }
          return msg;
        });
      }));

      await reg(listen<string>("typing-indicator", (event) => {
        // FE-30: in-chat indicator, not a toast.
        chatStore.setTyping(event.payload);
      }));

      await reg(listen<string>("p2p-event", (event) => {
        const eventData = event.payload;
        if (eventData.includes("Discovered")) {
          const match = eventData.match(/Discovered (\w+) at/);
          if (match && match[1]) { contactStore.setOnline(match[1]); }
        }
      }));

      await reg(listen<MessageFailedEvent>("message-failed", (event) => {
        const failedPeerId = event.payload.to;
        const error = event.payload.error;
        if (error.includes("connection") || error.includes("dial")) { contactStore.setOffline(failedPeerId); }
        chatStore.markFailed(failedPeerId, event.payload.message_id);
        uiStore.showToast(t("toast.deliveryFailed", { e: error }));
      }));

      await reg(listen<string>("peer-connected", (event) => {
        const peerId = event.payload;
        contactStore.setOnline(peerId);
        chatStore.checkMissedMessagesFromPeer(peerId);
      }));

      await reg(listen<string>("peer-online", (event) => {
        const peerId = event.payload;
        contactStore.setOnline(peerId);
        chatStore.checkMissedMessagesFromPeer(peerId);
      }));

      await reg(listen<string>("peer-disconnected", (event) => {
        contactStore.setOffline(event.payload);
      }));

      await reg(listen<string>("pending-messages-sent", (event) => {
        chatStore.markPendingSent(event.payload);
      }));

      // TI-4/TI-5: per-message delivery status — the backend acks a
      // specific message_id; mark that row, never the whole history.
      await reg(listen<{ peer_id: string; message_id: string }>("message-delivered", (event) => {
        chatStore.markMessageDelivered(event.payload.peer_id, event.payload.message_id);
      }));
      await reg(listen<{ peer_id: string; message_id: string }>("mailbox-stored", (event) => {
        chatStore.markMessageDelivered(event.payload.peer_id, event.payload.message_id);
      }));

      // TI-15: inbound file transfer — offer + completion events.
      await reg(listen<{ from: string; offer_id: string; name: string; size: number }>("file-offer", (event) => {
        uiStore.showToast(t("toast.receivingFile", { name: event.payload.name, kb: Math.round(event.payload.size / 1024), from: event.payload.from.slice(0, 8) }));
      }));
      await reg(listen<{ from: string; offer_id: string; path: string }>("file-received", (event) => {
        uiStore.showToast(t("toast.fileReceived", { path: event.payload.path }));
        notifyChatMessage(event.payload.from, `sent a file — saved to ${event.payload.path}`);
      }));

      await reg(listen<{ username: string; available: boolean; uncertain?: boolean }>("username-availability", (event) => {
        usernameStore.handleAvailabilityResult(event.payload);
      }));

      await reg(listen<{ username: string; record: any }>("user-lookup-result", (event) => {
        usernameStore.handleLookupResult(event.payload);
      }));

      // Encrypted rooms: verified+decrypted envelopes arrive as room-msg.
      const { onRoomMessage, onRoomInvite } = await import("$lib/services/room_service");
      await reg(onRoomMessage((payload) => {
        if (uiStore.subPage === "room-view" && payload.room_id === chatStore.currentPeer) {
          chatStore.appendMessage({
            id: payload.msg_id,
            from: payload.sender,
            content: payload.content,
            type: "received",
            timestamp: Date.now(),
          });
        } else {
          uiStore.showToast(t("toast.roomMessage", { id: payload.room_id.slice(0, 8) }));
          notifyRoomMessage(payload.room_id, payload.sender, payload.content);
        }
      }));

      await reg(onRoomInvite((payload) => {
        uiStore.showToast(t("toast.roomInvite", { from: payload.from.slice(0, 8) }));
        notifyRoomInvite(payload.from);
      }));
      // Room membership/meta/key events → keep open settings in sync.
      const { roomStore } = await import("$lib/stores/room_store.svelte");
      await reg(roomStore.bindEvents());
      await roomStore.loadPendingInvites();

      try {
        chatStore.myId = await invoke("get_my_id");
        roomStore.myId = chatStore.myId;
        // TI-9: events are fire-and-forget — after a suspended/reloaded
        // WebView the live peer set would be empty until the next event.
        // IPC-01: each call is individually fault-tolerant — pre-login
        // (P2P down, DB locked) must not abort the rest of the chain;
        // the authoritative post-login run rides the `my-id` listener.
        try {
          const snap = await invoke<{ my_id: string; connected_peers: string[] }>("get_network_snapshot");
          snap.connected_peers.forEach((p) => contactStore.setOnline(p));
        } catch {}
        await contactStore.loadContacts();
        try { await invoke("reconnect_to_contacts"); } catch {}
        try { await chatStore.checkAllMissedMessages(); } catch {}
        try { await invoke("update_last_sync_time"); } catch {}
      } catch (e) { console.error("Failed to initialize", e); }
    };
    setup();

    // IPC-03: Android freezes the WebView in background — events emitted
    // while hidden are lost. On resume, pull a snapshot + reload contacts
    // and the open chat so presence and unread state re-sync.
    const onVisibility = async () => {
      if (document.visibilityState !== "visible" || authStore.screen !== "main") return;
      try {
        const snap = await invoke<{ my_id: string; connected_peers: string[] }>("get_network_snapshot");
        contactStore.clearOnline();
        snap.connected_peers.forEach((p) => contactStore.setOnline(p));
      } catch {}
      await contactStore.loadContacts();
      if (uiStore.subPage === "chat-view" && chatStore.currentPeer) {
        await chatStore.refreshCurrentChat();
      }
    };
    document.addEventListener("visibilitychange", onVisibility);

    // TI-12/TI-15: was two overlapping timers (3s + 5s both calling
    // loadContacts) — one 5s tick covers presence refresh and the open
    // chat, halving wakeups/IPC on battery-bound Android devices.
    const interval = setInterval(async () => {
      await contactStore.loadContacts();
      if (uiStore.subPage === "chat-view" && chatStore.currentPeer) await chatStore.refreshCurrentChat();
    }, 5000);

    return () => {
      cancelled = true;
      unlisteners.forEach((u) => u());
      clearInterval(interval);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  });
</script>

{#if authStore.screen === "main"}
  <MainScreen />
{:else}
  <AuthScreen />
{/if}

{#if uiStore.status}
  <div class="toast animate-entry" role="status" aria-live="polite">{uiStore.status}</div>
{/if}
