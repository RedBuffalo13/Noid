package com.bst.noid

import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.content.ContextCompat
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters

/** Poll a live node; modern Android requires user interaction to restart FGS. */
class NoidPollWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {
    override suspend fun doWork(): Result {
        if (!NoidService.serviceRunning) {
            if (Build.VERSION.SDK_INT >= 31) {
                requestNoidResume(applicationContext)
            } else {
                ContextCompat.startForegroundService(
                    applicationContext,
                    Intent(applicationContext, NoidService::class.java),
                )
            }
        } else if (NoidService.nodeLoaded) {
            NoidNative.onNetworkChangedNative()
        }
        return Result.success()
    }
}
