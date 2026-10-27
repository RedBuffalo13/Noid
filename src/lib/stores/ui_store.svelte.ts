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
  showToast(msg: string) {
    status = msg;
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (status = ""), 3000);
  }
};
