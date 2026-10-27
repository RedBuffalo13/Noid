package com.bst.noid

import android.content.Context
import android.view.WindowManager
import android.app.Activity

/** JNI bridge: Rust-side entry points (libnoid_lib.so) + helpers called from Rust. */
object NoidNative {
    init {
        System.loadLibrary("noid_lib")
    }

    /** NetworkCallback / WorkManager → Rust P2PCommand::NetworkChanged. */
    @JvmStatic
    external fun onNetworkChangedNative()

    /** MainActivity → Rust AtomicBool (replaces find_class appVisible read). */
    @JvmStatic
    external fun onAppVisibilityChangedNative(visible: Boolean)

    /** Rust screenshot_protection → toggle FLAG_SECURE on the activity window. */
    @JvmStatic
    fun setSecure(ctx: Context, enabled: Boolean) {
        (ctx as? Activity)?.runOnUiThread {
            if (enabled) {
                (ctx as? Activity)?.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
            } else {
                (ctx as? Activity)?.window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
            }
        }
    }
}
