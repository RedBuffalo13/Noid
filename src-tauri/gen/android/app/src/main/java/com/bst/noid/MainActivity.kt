package com.bst.noid

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.view.WindowManager
import androidx.core.content.ContextCompat

class MainActivity : TauriActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Screenshots/recents blocked by default — matches desktop secure mode.
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        // Foreground service keeps the P2P node alive in background/Doze.
        ContextCompat.startForegroundService(this, Intent(this, NoidService::class.java))
        NoidService.nodeLoaded = true
        requestBatteryWhitelist()
    }

    override fun onResume() {
        super.onResume()
        // AN-02: push visibility into Rust AtomicBool — the old read path
        // used find_class from a Tokio thread and always failed (BootClassLoader).
        NoidNative.onAppVisibilityChangedNative(true)
    }

    override fun onPause() {
        NoidNative.onAppVisibilityChangedNative(false)
        super.onPause()
    }

    private fun requestBatteryWhitelist() {
        val pm = getSystemService(POWER_SERVICE) as PowerManager
        if (!pm.isIgnoringBatteryOptimizations(packageName)) {
            try {
                startActivity(
                    Intent(
                        Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                        Uri.parse("package:$packageName"),
                    ),
                )
            } catch (_: Exception) {
                // Some OEMs (Xiaomi) block the intent — user can set it manually.
            }
        }
    }
}
