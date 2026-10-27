package com.bst.noid

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters

/** 15-min WorkManager tick — a guaranteed network+CPU window inside Doze;
 * wakes the node so it can re-reserve relays and poll the mailbox. */
class NoidPollWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {
    override suspend fun doWork(): Result {
        if (NoidService.nodeLoaded) {
            NoidNative.onNetworkChangedNative()
        }
        return Result.success()
    }
}
