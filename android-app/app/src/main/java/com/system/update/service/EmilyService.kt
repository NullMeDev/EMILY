package com.system.update.service

import android.app.*
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import androidx.lifecycle.LifecycleService
import androidx.work.*
import com.system.update.R
import com.system.update.core.EmilyEngine
import com.system.update.core.ScanResult
import com.system.update.utils.PreferenceManager
import kotlinx.coroutines.*
import java.util.concurrent.TimeUnit

class EmilyService : LifecycleService() {
    
    private lateinit var engine: EmilyEngine
    private lateinit var prefs: PreferenceManager
    private lateinit var wakeLock: PowerManager.WakeLock
    private lateinit var notificationManager: NotificationManager
    
    private var serviceJob: Job? = null
    private var isScanning = false
    
    companion object {
        const val ACTION_START = "ACTION_START"
        const val ACTION_STOP = "ACTION_STOP"
        const val ACTION_QUICK_SCAN = "ACTION_QUICK_SCAN"
        
        const val CHANNEL_ID = "emily_service_channel"
        const val NOTIFICATION_ID = 12345
        
        @Volatile
        var isRunning = false
            private set
    }
    
    override fun onCreate() {
        super.onCreate()
        
        engine = EmilyEngine(this)
        prefs = PreferenceManager(this)
        notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        
        createNotificationChannel()
        acquireWakeLock()
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        
        when (intent?.action) {
            ACTION_START -> startEmilyService()
            ACTION_STOP -> stopEmilyService()
            ACTION_QUICK_SCAN -> performQuickScan()
        }
        
        return START_STICKY
    }
    
    private fun startEmilyService() {
        if (isRunning) return
        
        isRunning = true
        
        // Start foreground service
        startForeground(NOTIFICATION_ID, createNotification("EMILY is starting..."))
        
        // Start scanning coroutine
        serviceJob = CoroutineScope(Dispatchers.IO).launch {
            try {
                startContinuousScanning()
            } catch (e: Exception) {
                // Handle error
                updateNotification("EMILY service error: ${e.message}")
            }
        }
        
        updateNotification("EMILY is monitoring for surveillance devices")
    }
    
    private fun stopEmilyService() {
        if (!isRunning) return
        
        isRunning = false
        isScanning = false
        
        serviceJob?.cancel()
        
        updateNotification("EMILY service stopped")
        
        // Stop foreground service
        stopForeground(true)
        stopSelf()
    }
    
    private fun performQuickScan() {
        if (isScanning) return
        
        CoroutineScope(Dispatchers.IO).launch {
            try {
                isScanning = true
                updateNotification("Performing quick scan...")
                
                val result = engine.quickScan()
                handleScanResult(result)
                
                isScanning = false
                updateNotification("Quick scan completed")
            } catch (e: Exception) {
                isScanning = false
                updateNotification("Quick scan failed: ${e.message}")
            }
        }
    }
    
    private suspend fun startContinuousScanning() {
        while (isRunning) {
            try {
                isScanning = true
                updateNotification("Scanning for surveillance devices...")
                
                val result = engine.fullScan()
                handleScanResult(result)
                
                isScanning = false
                
                // Wait for next scan interval
                val interval = prefs.getScanInterval()
                delay(interval * 1000L)
                
            } catch (e: Exception) {
                isScanning = false
                updateNotification("Scan error: ${e.message}")
                delay(30000) // Wait 30 seconds before retry
            }
        }
    }
    
    private fun handleScanResult(result: ScanResult) {
        val threatsFound = result.threats.size
        val devicesFound = result.devices.size
        
        if (threatsFound > 0) {
            // Show threat notification
            showThreatNotification(threatsFound)
            
            // Apply countermeasures if enabled
            if (prefs.isCountermeasuresEnabled()) {
                engine.applyCountermeasures(result.threats)
            }
        }
        
        updateNotification("Monitoring active - Devices: $devicesFound, Threats: $threatsFound")
        
        // Store results
        engine.storeResults(result)
    }
    
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "EMILY Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "EMILY surveillance detection service"
                setShowBadge(false)
                setSound(null, null)
                enableLights(false)
                enableVibration(false)
            }
            
            notificationManager.createNotificationChannel(channel)
        }
    }
    
    private fun createNotification(content: String): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent, 
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("System Update")
            .setContentText(content)
            .setSmallIcon(R.drawable.ic_security)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setSilent(true)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }
    
    private fun updateNotification(content: String) {
        val notification = createNotification(content)
        notificationManager.notify(NOTIFICATION_ID, notification)
    }
    
    private fun showThreatNotification(threatCount: Int) {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 1, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("🚨 EMILY Alert")
            .setContentText("$threatCount surveillance threats detected!")
            .setSmallIcon(R.drawable.ic_warning)
            .setContentIntent(pendingIntent)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setVibrate(longArrayOf(0, 500, 250, 500))
            .build()
        
        notificationManager.notify(NOTIFICATION_ID + 1, notification)
    }
    
    private fun acquireWakeLock() {
        val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = powerManager.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            "EMILY::ServiceWakeLock"
        )
        wakeLock.acquire()
    }
    
    private fun releaseWakeLock() {
        if (::wakeLock.isInitialized && wakeLock.isHeld) {
            wakeLock.release()
        }
    }
    
    override fun onDestroy() {
        super.onDestroy()
        
        isRunning = false
        isScanning = false
        
        serviceJob?.cancel()
        releaseWakeLock()
        
        // Schedule periodic work for background scanning
        scheduleBackgroundWork()
    }
    
    private fun scheduleBackgroundWork() {
        val workRequest = PeriodicWorkRequestBuilder<EmilyWorker>(
            15, TimeUnit.MINUTES
        ).setConstraints(
            Constraints.Builder()
                .setRequiredNetworkType(NetworkType.NOT_REQUIRED)
                .setRequiresBatteryNotLow(false)
                .build()
        ).build()
        
        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            "emily_background_work",
            ExistingPeriodicWorkPolicy.REPLACE,
            workRequest
        )
    }
    
    override fun onBind(intent: Intent): IBinder? {
        super.onBind(intent)
        return null
    }
}
