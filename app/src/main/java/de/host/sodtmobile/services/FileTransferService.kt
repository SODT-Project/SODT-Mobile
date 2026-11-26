package de.host.sodtmobile.services

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import de.host.sodtmobile.R
import de.host.sodtmobile.activities.ConnectedActivity
import de.host.sodtmobile.utils.SodtClientUiWrapper

/**
 * FileTransferService is a Android Foreground Service responsible for keeping
 * network socket connections and background file transfers active when the user
 * closes or minimizes the SodtMobile application.
 *
 * It posts a persistent low-priority status notification while active and uses
 * foreground service type `dataSync` to prevent OS termination during data transfers.
 *
 * This class is AI generated
 */
class FileTransferService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP_SERVICE -> {
                ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                val notification = createNotification()
                val serviceType = ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
                try {
                    ServiceCompat.startForeground(
                        this,
                        NOTIFICATION_ID,
                        notification,
                        serviceType
                    )
                } catch (e: Exception) {
                    e.printStackTrace()
                }
            }
        }
        return START_STICKY
    }

    /**
     * Creates the notification channel required for Android O (API 26) and above.
     */
    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "File Transfer Service",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Keeps file transfers active when the app is in the background"
        }
        val manager = getSystemService(NOTIFICATION_SERVICE) as? NotificationManager
        manager?.createNotificationChannel(channel)
    }

    /**
     * Builds the persistent foreground service notification.
     * Tapping the notification redirects the user back to [ConnectedActivity].
     */
    private fun createNotification(): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, ConnectedActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Sodt File Transfer")
            .setContentText("File transfer service is active")
            .setSmallIcon(R.mipmap.ic_launcher)
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    companion object {
        const val CHANNEL_ID = "sodt_file_transfer_channel"
        const val NOTIFICATION_ID = 1001
        const val ACTION_STOP_SERVICE = "de.host.sodtmobile.services.STOP_SERVICE"

        /**
         * Holds a reference to the active [SodtClientUiWrapper] instance while connected.
         */
        var activeClient: SodtClientUiWrapper? = null

        /**
         * Convenience helper to launch [FileTransferService] as a foreground service.
         *
         * @param context Context used to start the foreground service.
         */
        fun startService(context: Context) {
            val intent = Intent(context, FileTransferService::class.java)
            try {
                ContextCompat.startForegroundService(context, intent)
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }

        /**
         * Convenience helper to stop [FileTransferService].
         *
         * @param context Context used to send the stop intent to the service.
         */
        fun stopService(context: Context) {
            val intent = Intent(context, FileTransferService::class.java).apply {
                action = ACTION_STOP_SERVICE
            }
            try {
                context.startService(intent)
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }
}
