package com.system.update.scanner

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.content.Context
import android.util.Log
import com.system.update.core.Device
import kotlinx.coroutines.delay
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

class BluetoothScanner(private val context: Context) {
    
    private val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private val bluetoothAdapter = bluetoothManager.adapter
    private val leScanner: BluetoothLeScanner? = bluetoothAdapter?.bluetoothLeScanner
    
    companion object {
        private const val TAG = "BluetoothScanner"
        private const val QUICK_SCAN_DURATION = 5000L
        private const val FULL_SCAN_DURATION = 15000L
    }
    
    suspend fun quickScan(): List<Device> {
        Log.d(TAG, "Starting quick Bluetooth scan")
        
        if (!isBluetoothEnabled()) {
            Log.w(TAG, "Bluetooth is not enabled")
            return emptyList()
        }
        
        return try {
            performScan(QUICK_SCAN_DURATION)
        } catch (e: Exception) {
            Log.e(TAG, "Error during quick Bluetooth scan", e)
            emptyList()
        }
    }
    
    suspend fun fullScan(): List<Device> {
        Log.d(TAG, "Starting full Bluetooth scan")
        
        if (!isBluetoothEnabled()) {
            Log.w(TAG, "Bluetooth is not enabled")
            return emptyList()
        }
        
        return try {
            performScan(FULL_SCAN_DURATION)
        } catch (e: Exception) {
            Log.e(TAG, "Error during full Bluetooth scan", e)
            emptyList()
        }
    }
    
    private suspend fun performScan(duration: Long): List<Device> {
        val devices = mutableListOf<Device>()
        
        // Scan for classic Bluetooth devices
        val classicDevices = scanClassicDevices()
        devices.addAll(classicDevices)
        
        // Scan for BLE devices
        val bleDevices = scanBleDevices(duration)
        devices.addAll(bleDevices)
        
        Log.d(TAG, "Found ${devices.size} Bluetooth devices")
        return devices
    }
    
    private fun scanClassicDevices(): List<Device> {
        val devices = mutableListOf<Device>()
        
        try {
            // Get paired devices
            val pairedDevices = bluetoothAdapter?.bondedDevices
            pairedDevices?.forEach { device ->
                val mappedDevice = mapBluetoothDeviceToDevice(device, true)
                devices.add(mappedDevice)
            }
            
            // Start discovery for nearby devices
            bluetoothAdapter?.startDiscovery()
            
        } catch (e: Exception) {
            Log.e(TAG, "Error scanning classic Bluetooth devices", e)
        }
        
        return devices
    }
    
    private suspend fun scanBleDevices(duration: Long): List<Device> {
        val devices = mutableListOf<Device>()
        
        if (leScanner == null) {
            Log.w(TAG, "BLE scanner not available")
            return devices
        }
        
        return suspendCancellableCoroutine { continuation ->
            val scanCallback = object : ScanCallback() {
                override fun onScanResult(callbackType: Int, result: ScanResult) {
                    val device = mapScanResultToDevice(result)
                    devices.add(device)
                }
                
                override fun onScanFailed(errorCode: Int) {
                    Log.e(TAG, "BLE scan failed with error code: $errorCode")
                }
            }
            
            try {
                leScanner.startScan(scanCallback)
                
                // Set a timer to stop scanning
                continuation.invokeOnCancellation {
                    leScanner.stopScan(scanCallback)
                }
                
                // Wait for scan duration
                android.os.Handler().postDelayed({
                    leScanner.stopScan(scanCallback)
                    continuation.resume(devices)
                }, duration)
                
            } catch (e: Exception) {
                Log.e(TAG, "Error starting BLE scan", e)
                continuation.resume(devices)
            }
        }
    }
    
    private fun mapBluetoothDeviceToDevice(bluetoothDevice: BluetoothDevice, isPaired: Boolean): Device {
        val name = bluetoothDevice.name ?: "Unknown Device"
        val mac = bluetoothDevice.address
        val threatLevel = calculateThreatLevel(bluetoothDevice, isPaired)
        
        return Device(
            name = name,
            mac = mac,
            type = "Bluetooth Classic",
            signalStrength = 0, // RSSI not available for classic Bluetooth
            threatLevel = threatLevel
        )
    }
    
    private fun mapScanResultToDevice(scanResult: ScanResult): Device {
        val name = scanResult.device.name ?: "Unknown BLE Device"
        val mac = scanResult.device.address
        val signalStrength = scanResult.rssi
        val threatLevel = calculateBleThreatLevel(scanResult)
        
        return Device(
            name = name,
            mac = mac,
            type = "Bluetooth LE",
            signalStrength = signalStrength,
            threatLevel = threatLevel
        )
    }
    
    private fun calculateThreatLevel(bluetoothDevice: BluetoothDevice, isPaired: Boolean): Int {
        var threatLevel = 0
        
        // Unknown devices are more suspicious
        if (bluetoothDevice.name == null) {
            threatLevel += 2
        }
        
        // Unpaired devices are more suspicious
        if (!isPaired) {
            threatLevel += 1
        }
        
        // Check for suspicious device names
        val suspiciousNames = listOf(
            "surveillance", "monitor", "hidden", "spy", "track",
            "police", "fbi", "nsa", "gov", "admin", "security", "covert"
        )
        
        val deviceName = bluetoothDevice.name?.lowercase() ?: ""
        for (suspiciousName in suspiciousNames) {
            if (deviceName.contains(suspiciousName)) {
                threatLevel += 3
                break
            }
        }
        
        // Check device class for potentially suspicious devices
        val deviceClass = bluetoothDevice.bluetoothClass
        if (deviceClass != null) {
            when (deviceClass.majorDeviceClass) {
                BluetoothClass.Device.Major.AUDIO_VIDEO -> threatLevel += 1 // Could be hidden recorder
                BluetoothClass.Device.Major.COMPUTER -> threatLevel += 1 // Could be surveillance computer
                BluetoothClass.Device.Major.UNCATEGORIZED -> threatLevel += 2 // Unknown purpose
            }
        }
        
        return threatLevel.coerceIn(0, 5)
    }
    
    private fun calculateBleThreatLevel(scanResult: ScanResult): Int {
        var threatLevel = 0
        
        // Unknown devices are suspicious
        if (scanResult.device.name == null) {
            threatLevel += 2
        }
        
        // Very strong signal indicates close proximity
        if (scanResult.rssi > -40) {
            threatLevel += 1
        }
        
        // Check for suspicious device names
        val suspiciousNames = listOf(
            "surveillance", "monitor", "hidden", "spy", "track",
            "police", "fbi", "nsa", "gov", "admin", "security", "covert"
        )
        
        val deviceName = scanResult.device.name?.lowercase() ?: ""
        for (suspiciousName in suspiciousNames) {
            if (deviceName.contains(suspiciousName)) {
                threatLevel += 3
                break
            }
        }
        
        // Check for beacons which could be used for tracking
        val scanRecord = scanResult.scanRecord
        if (scanRecord != null) {
            val serviceUuids = scanRecord.serviceUuids
            if (serviceUuids != null && serviceUuids.isNotEmpty()) {
                // iBeacon or other tracking beacons
                threatLevel += 1
            }
        }
        
        return threatLevel.coerceIn(0, 5)
    }
    
    fun isBluetoothEnabled(): Boolean {
        return bluetoothAdapter?.isEnabled == true
    }
    
    fun enableBluetooth(): Boolean {
        return try {
            bluetoothAdapter?.enable()
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to enable Bluetooth", e)
            false
        }
    }
    
    fun getBluetoothCapabilities(): Map<String, Any> {
        return mapOf(
            "enabled" to isBluetoothEnabled(),
            "le_supported" to (bluetoothAdapter?.isLeEnabled == true),
            "multiple_advertisement_supported" to (bluetoothAdapter?.isMultipleAdvertisementSupported == true),
            "offloaded_filtering_supported" to (bluetoothAdapter?.isOffloadedFilteringSupported == true),
            "offloaded_scan_batching_supported" to (bluetoothAdapter?.isOffloadedScanBatchingSupported == true)
        )
    }
}
