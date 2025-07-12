package com.system.update.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import com.system.update.service.EmilyService
import com.system.update.utils.PreferenceManager

class BootReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "BootReceiver"
    }

    override fun onReceive(context: Context, intent: Intent) {
        Log.d(TAG, "Boot receiver triggered: ${intent.action}")
        
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_MY_PACKAGE_REPLACED,
            Intent.ACTION_PACKAGE_REPLACED -> {
                startEmilyService(context)
            }
        }
    }
    
    private fun startEmilyService(context: Context) {
        val prefs = PreferenceManager(context)
        
        // Only start if auto-start is enabled
        if (!prefs.isAutoStart()) {
            Log.d(TAG, "Auto-start disabled, not starting service")
            return
        }
        
        Log.d(TAG, "Starting EMILY service on boot")
        
        val intent = Intent(context, EmilyService::class.java).apply {
            action = EmilyService.ACTION_START
        }
        
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
            Log.d(TAG, "EMILY service started successfully")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start EMILY service", e)
        }
    }
}
