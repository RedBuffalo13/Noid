let subPage = $state("chats");
let status = $state("");
let toastTimer: ReturnType<typeof setTimeout> | null = null;

// FE-07/FE-14: nav stack — every subPage transition pushes browser
// history so Android/hardware Back steps to the PREVIOUS page (not the
// app exit, not always "chats"). `popstate` replays the stack.
let navStack: string[] = [];
let suppressNavTrack = false;

export const uiStore = {
  get subPage() { return subPage; },
  set subPage(val: string) {
    if (val !== subPage && !suppressNavTrack) {
      navStack.push(subPage);
      try { history.pushState({ noidNav: true }, ""); } catch (_) {}
    }
    subPage = val;
  },

  /** Hardware/back-button handler — true when a level was popped. */
  navBack(): boolean {
    const prev = navStack.pop();
    suppressNavTrack = true;
    subPage = prev ?? "chats";
    suppressNavTrack = false;
    return prev !== undefined;
  },

  /** Auth transitions (login/logout/wipe) reset navigation to root. */
  resetNav(page = "chats") {
    navStack = [];
    suppressNavTrack = true;
    subPage = page;
    suppressNavTrack = false;
  },
  get status() { return status; },

  // FE-06: a second toast used to leave the FIRST toast's timer armed —
  // it then cleared the new message mid-display. One timer, always reset.
  // FE-A11: an offline peer floods identical p2p-error toasts — dedup by
  // message content: the same text within the cooldown window only
  // refreshes the display (with a repeat counter), never restarts spam.
  showToast(msg: string) {
    const now = Date.now();
    if (msg === lastToastMsg && now - lastToastAt < 10_000) {
      toastRepeats += 1;
      status = `${msg} (×${toastRepeats + 1})`;
      lastToastAt = now;
      if (toastTimer) clearTimeout(toastTimer);
      toastTimer = setTimeout(() => {
        status = "";
        lastToastMsg = "";
        toastRepeats = 0;
      }, 3000);
      return;
    }
    lastToastMsg = msg;
    lastToastAt = now;
    toastRepeats = 0;
    status = msg;
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      status = "";
      lastToastMsg = "";
      toastRepeats = 0;
    }, 3000);
  }
};

let lastToastMsg = "";
let lastToastAt = 0;
let toastRepeats = 0;
