package com.bst.noid

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.WifiManager
import android.os.IBinder
import android.os.PowerManager
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit

/**
 * Foreground service owning the OS resources the P2P node needs to
 * survive Doze and network transitions: PARTIAL_WAKE_LOCK (renewed —
 * Android caps a held wakelock at 10 min), MulticastLock (mDNS LAN
 * discovery), and a default NetworkCallback driving
 * NoidNative.onNetworkChangedNative on Wi-Fi<->LTE switches.
 */
class NoidService : Service() {

    companion object {
        @Volatile var nodeLoaded = false
        private const val CHANNEL_ID = "noid_fg"
        private const val NOTIF_ID = 42
        private const val WAKE_TAG = "noid:p2p"
        private const val MULTICAST_TAG = "noid:mdns"
        private const val WORK_NAME = "noid-poll"
    }

    private var wakeLock: PowerManager.WakeLock? = null
    private var multicastLock: WifiManager.MulticastLock? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun onCreate() {
        super.onCreate()
        startForegroundWithNotification()
        acquireLocks()
        registerNetworkCallback()
        schedulePollWorker()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // START_STICKY — after a Doze/low-memory kill the service is
        // recreated and re-acquires locks + callbacks.
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    /** FGS dataSync on SDK 34+: onTimeout → keep locks, let the system
     * rebind; do NOT release the wakelock or the node freezes. */
    override fun onTimeout(startId: Int) {
        acquireLocks()
        startForegroundWithNotification()
    }

    override fun onDestroy() {
        releaseLocks()
        networkCallback?.let {
            (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager)
                .unregisterNetworkCallback(it)
        }
        super.onDestroy()
    }

    private fun startForegroundWithNotification() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Noid", NotificationManager.IMPORTANCE_MIN),
            )
        }
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notif: Notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Noid")
            .setContentText("Защищённый узел активен")
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
        startForeground(NOTIF_ID, notif)
    }

    private fun acquireLocks() {
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        if (wakeLock?.isHeld != true) {
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, WAKE_TAG).apply {
                // 10-minute timeout — re-acquired in onTimeout/renew tick;
                // a permanent wakelock invites OEM task-killers.
                acquire(10 * 60 * 1000L)
            }
        }
        if (multicastLock?.isHeld != true) {
            val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            multicastLock = wifi.createMulticastLock(MULTICAST_TAG).apply {
                setReferenceCounted(false)
                acquire()
            }
        }
    }

    private fun releaseLocks() {
        if (wakeLock?.isHeld == true) wakeLock?.release()
        wakeLock = null
        if (multicastLock?.isHeld == true) multicastLock?.release()
        multicastLock = null
    }

    private fun registerNetworkCallback() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = fire()
            override fun onLost(network: Network) = fire()
            override fun onCapabilitiesChanged(n: Network, c: NetworkCapabilities) = fire()
            private fun fire() {
                if (nodeLoaded) NoidNative.onNetworkChangedNative()
            }
        }
        cm.registerDefaultNetworkCallback(cb)
        networkCallback = cb
    }

    private fun schedulePollWorker() {
        val req = PeriodicWorkRequestBuilder<NoidPollWorker>(15, TimeUnit.MINUTES).build()
        WorkManager.getInstance(this)
            .enqueueUniquePeriodicWork(WORK_NAME, ExistingPeriodicWorkPolicy.KEEP, req)
    }
}
