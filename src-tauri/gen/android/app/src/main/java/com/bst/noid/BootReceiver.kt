package com.bst.noid

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.content.ContextCompat

/** Respect Android 15's prohibition on boot-started dataSync services. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            if (Build.VERSION.SDK_INT >= 35) {
                requestNoidResume(context)
            } else {
                ContextCompat.startForegroundService(context, Intent(context, NoidService::class.java))
            }
        }
    }
}
