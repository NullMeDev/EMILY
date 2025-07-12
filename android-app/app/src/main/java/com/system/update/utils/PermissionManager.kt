package com.system.update.utils

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.PowerManager
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat

class PermissionManager(private val context: Context) {
    
    private val requiredPermissions = arrayOf(
        Manifest.permission.ACCESS_FINE_LOCATION,
        Manifest.permission.ACCESS_COARSE_LOCATION,
        Manifest.permission.ACCESS_WIFI_STATE,
        Manifest.permission.CHANGE_WIFI_STATE,
        Manifest.permission.BLUETOOTH,
        Manifest.permission.BLUETOOTH_ADMIN,
        Manifest.permission.READ_PHONE_STATE,
        Manifest.permission.WAKE_LOCK,
        Manifest.permission.FOREGROUND_SERVICE,
        Manifest.permission.RECEIVE_BOOT_COMPLETED,
        Manifest.permission.WRITE_EXTERNAL_STORAGE,
        Manifest.permission.READ_EXTERNAL_STORAGE
    )
    
    private val bluetoothPermissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        arrayOf(
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_CONNECT
        )
    } else {
        emptyArray()
    }
    
    private val nfcPermissions = arrayOf(
        Manifest.permission.NFC
    )
    
    fun hasAllPermissions(): Boolean {
        return getAllPermissions().all { permission ->
            ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED
        }
    }
    
    fun getMissingPermissions(): List<String> {
        return getAllPermissions().filter { permission ->
            ContextCompat.checkSelfPermission(context, permission) != PackageManager.PERMISSION_GRANTED
        }
    }
    
    private fun getAllPermissions(): Array<String> {
        val allPermissions = mutableListOf<String>()
        allPermissions.addAll(requiredPermissions)
        allPermissions.addAll(bluetoothPermissions)
        allPermissions.addAll(nfcPermissions)
        return allPermissions.toTypedArray()
    }
    
    fun hasLocationPermission(): Boolean {
        return ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
    }
    
    fun hasBluetoothPermissions(): Boolean {
        val basePermissions = arrayOf(
            Manifest.permission.BLUETOOTH,
            Manifest.permission.BLUETOOTH_ADMIN
        )
        
        val hasBasePermissions = basePermissions.all { permission ->
            ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED
        }
        
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            hasBasePermissions && bluetoothPermissions.all { permission ->
                ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED
            }
        } else {
            hasBasePermissions
        }
    }
    
    fun hasWifiPermissions(): Boolean {
        return ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_WIFI_STATE) == PackageManager.PERMISSION_GRANTED &&
               ContextCompat.checkSelfPermission(context, Manifest.permission.CHANGE_WIFI_STATE) == PackageManager.PERMISSION_GRANTED
    }
    
    fun hasNfcPermission(): Boolean {
        return ContextCompat.checkSelfPermission(context, Manifest.permission.NFC) == PackageManager.PERMISSION_GRANTED
    }
    
    fun hasPhoneStatePermission(): Boolean {
        return ContextCompat.checkSelfPermission(context, Manifest.permission.READ_PHONE_STATE) == PackageManager.PERMISSION_GRANTED
    }
    
    fun hasStoragePermissions(): Boolean {
        return ContextCompat.checkSelfPermission(context, Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED &&
               ContextCompat.checkSelfPermission(context, Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED
    }
    
    fun isBatteryOptimizationDisabled(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val powerManager = context.getSystemService(Context.POWER_SERVICE) as PowerManager
            powerManager.isIgnoringBatteryOptimizations(context.packageName)
        } else {
            true
        }
    }
    
    fun getPermissionStatus(): Map<String, Boolean> {
        val status = mutableMapOf<String, Boolean>()
        
        status["Location"] = hasLocationPermission()
        status["Bluetooth"] = hasBluetoothPermissions()
        status["WiFi"] = hasWifiPermissions()
        status["NFC"] = hasNfcPermission()
        status["Phone State"] = hasPhoneStatePermission()
        status["Storage"] = hasStoragePermissions()
        status["Battery Optimization"] = isBatteryOptimizationDisabled()
        
        return status
    }
    
    companion object {
        fun shouldShowRequestPermissionRationale(activity: Activity, permission: String): Boolean {
            return ActivityCompat.shouldShowRequestPermissionRationale(activity, permission)
        }
    }
}
