package com.system.update.scanner

import android.content.Context
import android.net.wifi.ScanResult
import android.net.wifi.WifiManager
import android.util.Log
import com.system.update.core.Device
import kotlinx.coroutines.delay

class WifiScanner(private val context: Context) {
    
    private val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
    
    companion object {
        private const val TAG = "WifiScanner"
        private const val QUICK_SCAN_DURATION = 5000L
        private const val FULL_SCAN_DURATION = 15000L
    }
    
    suspend fun quickScan(): List<Device> {
        Log.d(TAG, "Starting quick WiFi scan")
        
        if (!wifiManager.isWifiEnabled) {
            Log.w(TAG, "WiFi is not enabled")
            return emptyList()
        }
        
        return try {
            performScan(QUICK_SCAN_DURATION)
        } catch (e: Exception) {
            Log.e(TAG, "Error during quick WiFi scan", e)
            emptyList()
        }
    }
    
    suspend fun fullScan(): List<Device> {
        Log.d(TAG, "Starting full WiFi scan")
        
        if (!wifiManager.isWifiEnabled) {
            Log.w(TAG, "WiFi is not enabled")
            return emptyList()
        }
        
        return try {
            performScan(FULL_SCAN_DURATION)
        } catch (e: Exception) {
            Log.e(TAG, "Error during full WiFi scan", e)
            emptyList()
        }
    }
    
    private suspend fun performScan(duration: Long): List<Device> {
        val devices = mutableListOf<Device>()
        
        // Start WiFi scan
        val scanStarted = wifiManager.startScan()
        if (!scanStarted) {
            Log.w(TAG, "Failed to start WiFi scan")
            return emptyList()
        }
        
        // Wait for scan to complete
        delay(duration)
        
        // Get scan results
        val scanResults = wifiManager.scanResults
        Log.d(TAG, "Found ${scanResults.size} WiFi networks")
        
        for (result in scanResults) {
            val device = mapScanResultToDevice(result)
            devices.add(device)
        }
        
        return devices
    }
    
    private fun mapScanResultToDevice(scanResult: ScanResult): Device {
        val name = if (scanResult.SSID.isNullOrEmpty()) {
            "Hidden Network"
        } else {
            scanResult.SSID
        }
        
        val threatLevel = calculateThreatLevel(scanResult)
        
        return Device(
            name = name,
            mac = scanResult.BSSID,
            type = "WiFi",
            signalStrength = scanResult.level,
            threatLevel = threatLevel
        )
    }
    
    private fun calculateThreatLevel(scanResult: ScanResult): Int {
        var threatLevel = 0
        
        // Check for hidden networks
        if (scanResult.SSID.isNullOrEmpty()) {
            threatLevel += 2
        }
        
        // Check for suspicious network names
        val suspiciousNames = listOf(
            "surveillance", "monitor", "hidden", "spy", "track",
            "police", "fbi", "nsa", "gov", "admin", "security"
        )
        
        val ssidLower = scanResult.SSID?.lowercase() ?: ""
        for (suspiciousName in suspiciousNames) {
            if (ssidLower.contains(suspiciousName)) {
                threatLevel += 3
                break
            }
        }
        
        // Check for weak security
        val capabilities = scanResult.capabilities
        if (capabilities.contains("WEP") || capabilities.contains("OPEN")) {
            threatLevel += 1
        }
        
        // Check for strong signal indicating proximity
        if (scanResult.level > -50) {
            threatLevel += 1
        }
        
        // Check for common AP names that could be rogue
        val roguePatterns = listOf(
            "Free WiFi", "Guest", "Public", "Open", "Internet",
            "Hotspot", "Network", "Connection"
        )
        
        for (pattern in roguePatterns) {
            if (ssidLower.contains(pattern.lowercase())) {
                threatLevel += 2
                break
            }
        }
        
        return threatLevel.coerceIn(0, 5)
    }
    
    fun isWifiEnabled(): Boolean {
        return wifiManager.isWifiEnabled
    }
    
    fun enableWifi(): Boolean {
        return try {
            wifiManager.isWifiEnabled = true
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to enable WiFi", e)
            false
        }
    }
    
    fun getConnectedNetwork(): String? {
        return try {
            val wifiInfo = wifiManager.connectionInfo
            wifiInfo?.ssid?.replace("\"", "")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get connected network", e)
            null
        }
    }
    
    fun getWifiCapabilities(): Map<String, Any> {
        return mapOf(
            "enabled" to wifiManager.isWifiEnabled,
            "connected_network" to getConnectedNetwork(),
            "scan_always_available" to wifiManager.isScanAlwaysAvailable,
            "wifi_5ghz_band_supported" to wifiManager.is5GHzBandSupported,
            "wifi_p2p_supported" to wifiManager.isP2pSupported
        )
    }
}
