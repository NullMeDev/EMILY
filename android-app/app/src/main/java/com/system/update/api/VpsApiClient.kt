package com.system.update.api

import android.content.Context
import android.util.Log
import com.google.gson.Gson
import com.google.gson.JsonObject
import com.system.update.core.Device
import com.system.update.core.ScanResult
import com.system.update.core.Threat
import com.system.update.utils.PreferenceManager
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.util.concurrent.TimeUnit

data class VpsDevice(
    val id: Int,
    val name: String,
    val mac: String,
    val type: String,
    val signal_level: Int,
    val threat_level: Int,
    val first_seen: String,
    val last_seen: String,
    val client_id: String,
    val location: String?,
    val is_whitelisted: Boolean
)

data class VpsThreat(
    val id: Int,
    val client_id: String,
    val threat_id: String,
    val description: String,
    val severity: Int,
    val confidence: Double,
    val device_id: Int?,
    val status: String,
    val created_at: String,
    val updated_at: String
)

data class VpsAlert(
    val id: Int,
    val client_id: String,
    val type: String,
    val message: String,
    val severity: Int,
    val timestamp: String,
    val read: Boolean
)

data class VpsScanResult(
    val client_id: String,
    val scan_type: String,
    val duration: Long,
    val device_count: Int,
    val threat_count: Int,
    val data: String
)

data class VpsClient(
    val id: String,
    val name: String,
    val api_key: String,
    val location: String
)

class VpsApiClient(private val context: Context) {
    
    private val prefs = PreferenceManager(context)
    private val gson = Gson()
    private val client: OkHttpClient
    
    companion object {
        private const val TAG = "VpsApiClient"
        private const val TIMEOUT_SECONDS = 30L
    }
    
    init {
        client = OkHttpClient.Builder()
            .connectTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .writeTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .build()
    }
    
    fun isConnected(): Boolean {
        return prefs.isVpsEnabled() && 
               prefs.getVpsEndpoint().isNotEmpty() && 
               prefs.getVpsApiKey().isNotEmpty()
    }
    
    fun testConnection(): Boolean {
        if (!isConnected()) return false
        
        val endpoint = prefs.getVpsEndpoint()
        val request = Request.Builder()
            .url("$endpoint/health")
            .get()
            .build()
        
        return try {
            val response = client.newCall(request).execute()
            response.isSuccessful
        } catch (e: Exception) {
            Log.e(TAG, "Connection test failed", e)
            false
        }
    }
    
    fun registerClient(clientId: String, clientName: String): Boolean {
        if (!isConnected()) return false
        
        val endpoint = prefs.getVpsEndpoint()
        val apiKey = prefs.getVpsApiKey()
        
        val clientData = VpsClient(
            id = clientId,
            name = clientName,
            api_key = apiKey,
            location = "Android Device"
        )
        
        val json = gson.toJson(clientData)
        val requestBody = json.toRequestBody("application/json".toMediaType())
        
        val request = Request.Builder()
            .url("$endpoint/api/v1/clients")
            .addHeader("X-API-Key", apiKey)
            .post(requestBody)
            .build()
        
        return try {
            val response = client.newCall(request).execute()
            if (response.isSuccessful) {
                Log.d(TAG, "Client registered successfully")
                true
            } else {
                Log.e(TAG, "Failed to register client: ${response.code}")
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error registering client", e)
            false
        }
    }
    
    fun submitScanResult(scanResult: ScanResult): Boolean {
        if (!isConnected()) return false
        
        val endpoint = prefs.getVpsEndpoint()
        val apiKey = prefs.getVpsApiKey()
        val clientId = getClientId()
        
        val devicesJson = gson.toJson(scanResult.devices)
        
        val vpsScanResult = VpsScanResult(
            client_id = clientId,
            scan_type = "full",
            duration = scanResult.duration,
            device_count = scanResult.devices.size,
            threat_count = scanResult.threats.size,
            data = devicesJson
        )
        
        val json = gson.toJson(vpsScanResult)
        val requestBody = json.toRequestBody("application/json".toMediaType())
        
        val request = Request.Builder()
            .url("$endpoint/api/v1/scan-results")
            .addHeader("X-API-Key", apiKey)
            .post(requestBody)
            .build()
        
        return try {
            val response = client.newCall(request).execute()
            if (response.isSuccessful) {
                Log.d(TAG, "Scan result submitted successfully")
                true
            } else {
                Log.e(TAG, "Failed to submit scan result: ${response.code}")
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error submitting scan result", e)
            false
        }
    }
    
    fun submitThreat(threat: Threat): Boolean {
        if (!isConnected()) return false
        
        val endpoint = prefs.getVpsEndpoint()
        val apiKey = prefs.getVpsApiKey()
        val clientId = getClientId()
        
        val vpsThreat = VpsThreat(
            id = 0, // Will be auto-generated
            client_id = clientId,
            threat_id = threat.id,
            description = threat.description,
            severity = threat.severity,
            confidence = threat.confidence,
            device_id = null,
            status = "active",
            created_at = "",
            updated_at = ""
        )
        
        val json = gson.toJson(vpsThreat)
        val requestBody = json.toRequestBody("application/json".toMediaType())
        
        val request = Request.Builder()
            .url("$endpoint/api/v1/threats")
            .addHeader("X-API-Key", apiKey)
            .post(requestBody)
            .build()
        
        return try {
            val response = client.newCall(request).execute()
            if (response.isSuccessful) {
                Log.d(TAG, "Threat submitted successfully")
                true
            } else {
                Log.e(TAG, "Failed to submit threat: ${response.code}")
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error submitting threat", e)
            false
        }
    }
    
    fun getDevices(): List<VpsDevice>? {
        if (!isConnected()) return null
        
        val endpoint = prefs.getVpsEndpoint()
        val apiKey = prefs.getVpsApiKey()
        val clientId = getClientId()
        
        val request = Request.Builder()
            .url("$endpoint/api/v1/devices?client_id=$clientId")
            .addHeader("X-API-Key", apiKey)
            .get()
            .build()
        
        return try {
            val response = client.newCall(request).execute()
            if (response.isSuccessful) {
                val json = response.body?.string()
                val devices = gson.fromJson(json, Array<VpsDevice>::class.java)
                devices.toList()
            } else {
                Log.e(TAG, "Failed to get devices: ${response.code}")
                null
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error getting devices", e)
            null
        }
    }
    
    fun getThreats(): List<VpsThreat>? {
        if (!isConnected()) return null
        
        val endpoint = prefs.getVpsEndpoint()
        val apiKey = prefs.getVpsApiKey()
        val clientId = getClientId()
        
        val request = Request.Builder()
            .url("$endpoint/api/v1/threats?client_id=$clientId&status=active")
            .addHeader("X-API-Key", apiKey)
            .get()
            .build()
        
        return try {
            val response = client.newCall(request).execute()
            if (response.isSuccessful) {
                val json = response.body?.string()
                val threats = gson.fromJson(json, Array<VpsThreat>::class.java)
                threats.toList()
            } else {
                Log.e(TAG, "Failed to get threats: ${response.code}")
                null
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error getting threats", e)
            null
        }
    }
    
    fun getAlerts(): List<VpsAlert>? {
        if (!isConnected()) return null
        
        val endpoint = prefs.getVpsEndpoint()
        val apiKey = prefs.getVpsApiKey()
        val clientId = getClientId()
        
        val request = Request.Builder()
            .url("$endpoint/api/v1/alerts?client_id=$clientId&unread_only=true")
            .addHeader("X-API-Key", apiKey)
            .get()
            .build()
        
        return try {
            val response = client.newCall(request).execute()
            if (response.isSuccessful) {
                val json = response.body?.string()
                val alerts = gson.fromJson(json, Array<VpsAlert>::class.java)
                alerts.toList()
            } else {
                Log.e(TAG, "Failed to get alerts: ${response.code}")
                null
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error getting alerts", e)
            null
        }
    }
    
    private fun getClientId(): String {
        return android.provider.Settings.Secure.getString(
            context.contentResolver,
            android.provider.Settings.Secure.ANDROID_ID
        ) ?: "unknown-device"
    }
    
    fun syncData(): Boolean {
        if (!isConnected()) return false
        
        try {
            // Get latest data from VPS
            val devices = getDevices()
            val threats = getThreats()
            val alerts = getAlerts()
            
            Log.d(TAG, "Synced data: ${devices?.size ?: 0} devices, ${threats?.size ?: 0} threats, ${alerts?.size ?: 0} alerts")
            
            // TODO: Store synced data in local database
            
            return true
        } catch (e: Exception) {
            Log.e(TAG, "Error syncing data", e)
            return false
        }
    }
}
