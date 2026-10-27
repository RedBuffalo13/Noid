//! Android-only JNI bridge for OS-level callbacks into the Rust runtime.
//!
//! Java → Rust: `com.bst.noid.NoidNative.onNetworkChanged()` is invoked by
//! `NoidService`'s `ConnectivityManager.registerDefaultNetworkCallback` (A6)
//! and by the periodic `NoidPollWorker` (A3 — WorkManager buys us a
//! network+CPU window inside Doze). Both push a unit token into an
//! unbounded channel; a task spawned during app setup forwards each token
//! as `P2PCommand::NetworkChanged`, where the node drops stale external
//! addrs, clears dial backoffs and re-reserves relays.
//!
//! The channel is unbounded by design: bursts coalesce cheaply (the handler
//! is idempotent) and a bounded channel would just drop the same work.

#[cfg(target_os = "android")]
mod imp {
    use std::sync::OnceLock;

    static NETWORK_TX: OnceLock<tokio::sync::mpsc::UnboundedSender<()>> = OnceLock::new();
    /// AN-02: activity visibility pushed from Kotlin — a Tokio worker thread
    /// has no Java frames, so `attach_current_thread` + `find_class` sees
    /// only the BootClassLoader and can NEVER resolve `com.bst.noid.*`.
    /// The Kotlin side flips this flag via JNI on resume/pause instead.
    static APP_VISIBLE: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    /// Called once during app setup — registers the channel that Android
    /// callbacks feed.
    pub fn register(tx: tokio::sync::mpsc::UnboundedSender<()>) {
        let _ = NETWORK_TX.set(tx);
    }

    /// JNI entry point: `NoidNative.onNetworkChangedNative()` (called by
    /// the public Kotlin wrapper `onNetworkChanged`).
    /// Runs on a binder thread — must not block or throw.
    #[no_mangle]
    pub extern "C" fn Java_com_bst_noid_NoidNative_onNetworkChangedNative(
        _env: jni::JNIEnv,
        _class: jni::objects::JClass,
    ) {
        if let Some(tx) = NETWORK_TX.get() {
            let _ = tx.send(());
        }
    }

    /// JNI entry point: `NoidNative.onAppVisibilityChangedNative(visible)`
    /// — called from MainActivity.onResume/onPause. Replaces the
    /// find_class-based `appVisible` field read that always failed on
    /// Tokio-attached threads (BootClassLoader cannot see app classes).
    #[no_mangle]
    pub extern "C" fn Java_com_bst_noid_NoidNative_onAppVisibilityChangedNative(
        _env: jni::JNIEnv,
        _class: jni::objects::JClass,
        visible: jni::sys::jboolean,
    ) {
        APP_VISIBLE.store(visible != 0, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn app_visible() -> bool {
        APP_VISIBLE.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Register the wake channel on Android; a no-op elsewhere (the Kotlin side
/// only exists on Android, so nothing ever calls the JNI entry off it).
pub fn register_network_tx(#[allow(unused_variables)] tx: tokio::sync::mpsc::UnboundedSender<()>) {
    #[cfg(target_os = "android")]
    imp::register(tx);
}

/// A23: message notifications must reach the shade even when the WebView is
/// frozen in background — the frontend `notifyChatMessage` chain is dead
/// there. Posts only when the activity isn't visible (foreground chats are
/// rendered, not notified). No-op off Android.
pub fn notify_new_message(
    #[allow(unused_variables)] app: &tauri::AppHandle,
    #[allow(unused_variables)] from: &str,
) {
    #[cfg(target_os = "android")]
    {
        if android_app_visible() {
            return; // foreground WebView already notifies via JS
        }
        use tauri_plugin_notification::NotificationExt;
        let short: String = from[from.len() - 4..].to_string();
        if let Err(e) = app
            .notification()
            .builder()
            .title("Noid")
            .body(format!("Новое сообщение от {}…", short))
            .show()
        {
            log::warn!("background notification failed: {}", e);
        }
    }
}

#[cfg(target_os = "android")]
fn android_app_visible() -> bool {
    imp::app_visible()
}
