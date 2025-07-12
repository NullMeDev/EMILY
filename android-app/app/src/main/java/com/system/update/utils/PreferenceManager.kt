package com.system.update.utils

import android.content.Context
import android.content.SharedPreferences
import androidx.preference.PreferenceManager

class PreferenceManager(private val context: Context) {
    
    private val prefs: SharedPreferences = PreferenceManager.getDefaultSharedPreferences(context)
    
    companion object {
        // General settings
        const val PREF_STEALTH_MODE = "stealth_mode"
        const val PREF_AUTO_START = "auto_start"
        const val PREF_DEBUG_MODE = "debug_mode"
        const val PREF_SCAN_INTERVAL = "scan_interval"
        
        // Detection settings
        const val PREF_WIFI_ENABLED = "wifi_enabled"
        const val PREF_BLUETOOTH_ENABLED = "bluetooth_enabled"
        const val PREF_NFC_ENABLED = "nfc_enabled"
        const val PREF_CELLULAR_ENABLED = "cellular_enabled"
        
        // Countermeasures
        const val PREF_COUNTERMEASURES_ENABLED = "countermeasures_enabled"
        const val PREF_AUTO_COUNTERMEASURES = "auto_countermeasures"
        
        // VPS settings
        const val PREF_VPS_ENABLED = "vps_enabled"
        const val PREF_VPS_ENDPOINT = "vps_endpoint"
        const val PREF_VPS_API_KEY = "vps_api_key"
        
        // Notification settings
        const val PREF_NOTIFICATIONS_ENABLED = "notifications_enabled"
        const val PREF_SOUND_ALERTS = "sound_alerts"
        const val PREF_VIBRATE_ALERTS = "vibrate_alerts"
        
        // Advanced settings
        const val PREF_COLLECT_LOGS = "collect_logs"
        const val PREF_EXPORT_DATA = "export_data"
        const val PREF_WIPE_ON_DETECTION = "wipe_on_detection"
        
        // Default values
        const val DEFAULT_SCAN_INTERVAL = 30
        const val DEFAULT_VPS_ENDPOINT = ""
        const val DEFAULT_VPS_API_KEY = ""
    }
    
    // General settings
    fun isStealthMode(): Boolean = prefs.getBoolean(PREF_STEALTH_MODE, false)
    fun setStealthMode(enabled: Boolean) = prefs.edit().putBoolean(PREF_STEALTH_MODE, enabled).apply()
    
    fun isAutoStart(): Boolean = prefs.getBoolean(PREF_AUTO_START, false)
    fun setAutoStart(enabled: Boolean) = prefs.edit().putBoolean(PREF_AUTO_START, enabled).apply()
    
    fun isDebugMode(): Boolean = prefs.getBoolean(PREF_DEBUG_MODE, false)
    fun setDebugMode(enabled: Boolean) = prefs.edit().putBoolean(PREF_DEBUG_MODE, enabled).apply()
    
    fun getScanInterval(): Int = prefs.getInt(PREF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
    fun setScanInterval(interval: Int) = prefs.edit().putInt(PREF_SCAN_INTERVAL, interval).apply()
    
    // Detection settings
    fun isWifiEnabled(): Boolean = prefs.getBoolean(PREF_WIFI_ENABLED, true)
    fun setWifiEnabled(enabled: Boolean) = prefs.edit().putBoolean(PREF_WIFI_ENABLED, enabled).apply()
    
    fun isBluetoothEnabled(): Boolean = prefs.getBoolean(PREF_BLUETOOTH_ENABLED, true)
    fun setBluetoothEnabled(enabled: Boolean) = prefs.edit().putBoolean(PREF_BLUETOOTH_ENABLED, enabled).apply()
    
    fun isNfcEnabled(): Boolean = prefs.getBoolean(PREF_NFC_ENABLED, true)
    fun setNfcEnabled(enabled: Boolean) = prefs.edit().putBoolean(PREF_NFC_ENABLED, enabled).apply()
    
    fun isCellularEnabled(): Boolean = prefs.getBoolean(PREF_CELLULAR_ENABLED, true)
    fun setCellularEnabled(enabled: Boolean) = prefs.edit().putBoolean(PREF_CELLULAR_ENABLED, enabled).apply()
    
    // Countermeasures
    fun isCountermeasuresEnabled(): Boolean = prefs.getBoolean(PREF_COUNTERMEASURES_ENABLED, false)
    fun setCountermeasuresEnabled(enabled: Boolean) = prefs.edit().putBoolean(PREF_COUNTERMEASURES_ENABLED, enabled).apply()
    
    fun isAutoCountermeasures(): Boolean = prefs.getBoolean(PREF_AUTO_COUNTERMEASURES, false)
    fun setAutoCountermeasures(enabled: Boolean) = prefs.edit().putBoolean(PREF_AUTO_COUNTERMEASURES, enabled).apply()
    
    // VPS settings
    fun isVpsEnabled(): Boolean = prefs.getBoolean(PREF_VPS_ENABLED, false)
    fun setVpsEnabled(enabled: Boolean) = prefs.edit().putBoolean(PREF_VPS_ENABLED, enabled).apply()
    
    fun getVpsEndpoint(): String = prefs.getString(PREF_VPS_ENDPOINT, DEFAULT_VPS_ENDPOINT) ?: DEFAULT_VPS_ENDPOINT
    fun setVpsEndpoint(endpoint: String) = prefs.edit().putString(PREF_VPS_ENDPOINT, endpoint).apply()
    
    fun getVpsApiKey(): String = prefs.getString(PREF_VPS_API_KEY, DEFAULT_VPS_API_KEY) ?: DEFAULT_VPS_API_KEY
    fun setVpsApiKey(apiKey: String) = prefs.edit().putString(PREF_VPS_API_KEY, apiKey).apply()
    
    // Notification settings
    fun isNotificationsEnabled(): Boolean = prefs.getBoolean(PREF_NOTIFICATIONS_ENABLED, true)
    fun setNotificationsEnabled(enabled: Boolean) = prefs.edit().putBoolean(PREF_NOTIFICATIONS_ENABLED, enabled).apply()
    
    fun isSoundAlerts(): Boolean = prefs.getBoolean(PREF_SOUND_ALERTS, true)
    fun setSoundAlerts(enabled: Boolean) = prefs.edit().putBoolean(PREF_SOUND_ALERTS, enabled).apply()
    
    fun isVibrateAlerts(): Boolean = prefs.getBoolean(PREF_VIBRATE_ALERTS, true)
    fun setVibrateAlerts(enabled: Boolean) = prefs.edit().putBoolean(PREF_VIBRATE_ALERTS, enabled).apply()
    
    // Advanced settings
    fun isCollectLogs(): Boolean = prefs.getBoolean(PREF_COLLECT_LOGS, false)
    fun setCollectLogs(enabled: Boolean) = prefs.edit().putBoolean(PREF_COLLECT_LOGS, enabled).apply()
    
    fun isExportData(): Boolean = prefs.getBoolean(PREF_EXPORT_DATA, false)
    fun setExportData(enabled: Boolean) = prefs.edit().putBoolean(PREF_EXPORT_DATA, enabled).apply()
    
    fun isWipeOnDetection(): Boolean = prefs.getBoolean(PREF_WIPE_ON_DETECTION, false)
    fun setWipeOnDetection(enabled: Boolean) = prefs.edit().putBoolean(PREF_WIPE_ON_DETECTION, enabled).apply()
    
    // Utility methods
    fun getAllSettings(): Map<String, Any> {
        val settings = mutableMapOf<String, Any>()
        
        // General
        settings["Stealth Mode"] = isStealthMode()
        settings["Auto Start"] = isAutoStart()
        settings["Debug Mode"] = isDebugMode()
        settings["Scan Interval"] = getScanInterval()
        
        // Detection
        settings["WiFi Scanning"] = isWifiEnabled()
        settings["Bluetooth Scanning"] = isBluetoothEnabled()
        settings["NFC Scanning"] = isNfcEnabled()
        settings["Cellular Scanning"] = isCellularEnabled()
        
        // Countermeasures
        settings["Countermeasures"] = isCountermeasuresEnabled()
        settings["Auto Countermeasures"] = isAutoCountermeasures()
        
        // VPS
        settings["VPS Enabled"] = isVpsEnabled()
        settings["VPS Endpoint"] = getVpsEndpoint()
        
        // Notifications
        settings["Notifications"] = isNotificationsEnabled()
        settings["Sound Alerts"] = isSoundAlerts()
        settings["Vibrate Alerts"] = isVibrateAlerts()
        
        // Advanced
        settings["Collect Logs"] = isCollectLogs()
        settings["Export Data"] = isExportData()
        settings["Wipe on Detection"] = isWipeOnDetection()
        
        return settings
    }
    
    fun resetToDefaults() {
        prefs.edit().clear().apply()
    }
    
    fun exportSettings(): String {
        val settings = getAllSettings()
        return settings.entries.joinToString("\n") { "${it.key}: ${it.value}" }
    }
}
