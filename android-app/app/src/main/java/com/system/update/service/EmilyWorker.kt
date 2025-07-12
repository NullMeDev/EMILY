package com.system.update.service

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.system.update.core.EmilyEngine
import com.system.update.utils.PreferenceManager

class EmilyWorker(
    context: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(context, workerParams) {

    companion object {
        private const val TAG = "EmilyWorker"
    }

    override suspend fun doWork(): Result {
        Log.d(TAG, "Starting background work")
        
        return try {
            val prefs = PreferenceManager(applicationContext)
            
            // Only run if auto-start is enabled
            if (!prefs.isAutoStart()) {
                Log.d(TAG, "Auto-start disabled, skipping background work")
                return Result.success()
            }
            
            val engine = EmilyEngine(applicationContext)
            val result = engine.quickScan()
            
            Log.d(TAG, "Background scan completed: ${result.devices.size} devices, ${result.threats.size} threats")
            
            // If threats found, could trigger notification here
            if (result.threats.isNotEmpty()) {
                Log.w(TAG, "Threats detected in background scan: ${result.threats.size}")
                // TODO: Send notification or start full service
            }
            
            Result.success()
        } catch (e: Exception) {
            Log.e(TAG, "Background work failed", e)
            Result.retry()
        }
    }
}
