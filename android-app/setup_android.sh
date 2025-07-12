#!/bin/bash

# EMILY Android App Setup Script
# This script sets up the Android development environment and builds the app

set -e  # Exit on any error

echo "🤖 EMILY Android App Setup"
echo "========================="

# Check if we're in the right directory
if [ ! -f "app/build.gradle" ]; then
    echo "❌ Error: Please run this script from the android-app directory"
    exit 1
fi

# Create necessary directories
echo "📁 Creating project directories..."
mkdir -p app/src/main/assets
mkdir -p app/src/main/res/drawable
mkdir -p app/src/main/res/xml

# Copy the native EMILY binary to assets
echo "📦 Copying native EMILY binary..."
if [ -f "../bin/emily-android-arm64" ]; then
    cp "../bin/emily-android-arm64" "app/src/main/assets/emily-android"
    echo "✅ Native binary copied to assets"
else
    echo "⚠️  Warning: Native binary not found. Please build it first with 'make build-android'"
fi

# Create drawable resources (placeholder icons)
echo "🎨 Creating drawable resources..."

# Create ic_launcher.xml
cat > app/src/main/res/drawable/ic_launcher.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="24dp"
    android:height="24dp"
    android:viewportWidth="24"
    android:viewportHeight="24">
    <path
        android:fillColor="#FF1976D2"
        android:pathData="M12,2C6.48,2 2,6.48 2,12s4.48,10 10,10 10,-4.48 10,-10S17.52,2 12,2zM13,17h-2v-6h2v6zM13,9h-2L11,7h2v2z"/>
</vector>
EOF

# Create ic_security.xml
cat > app/src/main/res/drawable/ic_security.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="24dp"
    android:height="24dp"
    android:viewportWidth="24"
    android:viewportHeight="24">
    <path
        android:fillColor="#FFFFFFFF"
        android:pathData="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M12,7C13.4,7 14.8,8.6 14.8,10V11H16.2V16H7.8V11H9.2V10C9.2,8.6 10.6,7 12,7M12,8.2C11.2,8.2 10.4,8.7 10.4,10V11H13.6V10C13.6,8.7 12.8,8.2 12,8.2Z"/>
</vector>
EOF

# Create ic_warning.xml
cat > app/src/main/res/drawable/ic_warning.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="24dp"
    android:height="24dp"
    android:viewportWidth="24"
    android:viewportHeight="24">
    <path
        android:fillColor="#FFF44336"
        android:pathData="M1,21H23L12,2L1,21M13,18H11V16H13V18M13,14H11V10H13V14"/>
</vector>
EOF

# Create ic_settings.xml
cat > app/src/main/res/drawable/ic_settings.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="24dp"
    android:height="24dp"
    android:viewportWidth="24"
    android:viewportHeight="24">
    <path
        android:fillColor="#FF757575"
        android:pathData="M12,15.5A3.5,3.5 0 0,1 8.5,12A3.5,3.5 0 0,1 12,8.5A3.5,3.5 0 0,1 15.5,12A3.5,3.5 0 0,1 12,15.5M19.43,12.97C19.47,12.65 19.5,12.33 19.5,12C19.5,11.67 19.47,11.34 19.43,11L21.54,9.37C21.73,9.22 21.78,8.95 21.66,8.73L19.66,5.27C19.54,5.05 19.27,4.96 19.05,5.05L16.56,6.05C16.04,5.66 15.5,5.32 14.87,5.07L14.5,2.42C14.46,2.18 14.25,2 14,2H10C9.75,2 9.54,2.18 9.5,2.42L9.13,5.07C8.5,5.32 7.96,5.66 7.44,6.05L4.95,5.05C4.73,4.96 4.46,5.05 4.34,5.27L2.34,8.73C2.22,8.95 2.27,9.22 2.46,9.37L4.57,11C4.53,11.34 4.5,11.67 4.5,12C4.5,12.33 4.53,12.65 4.57,12.97L2.46,14.63C2.27,14.78 2.22,15.05 2.34,15.27L4.34,18.73C4.46,18.95 4.73,19.03 4.95,18.95L7.44,17.94C7.96,18.34 8.5,18.68 9.13,18.93L9.5,21.58C9.54,21.82 9.75,22 10,22H14C14.25,22 14.46,21.82 14.5,21.58L14.87,18.93C15.5,18.68 16.04,18.34 16.56,17.94L19.05,18.95C19.27,19.03 19.54,18.95 19.66,18.73L21.66,15.27C21.78,15.05 21.73,14.78 21.54,14.63L19.43,12.97Z"/>
</vector>
EOF

# Create ic_logs.xml
cat > app/src/main/res/drawable/ic_logs.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="24dp"
    android:height="24dp"
    android:viewportWidth="24"
    android:viewportHeight="24">
    <path
        android:fillColor="#FF757575"
        android:pathData="M3,3H21V5H3V3M3,7H21V9H3V7M3,11H21V13H3V11M3,15H21V17H3V15M3,19H21V21H3V19Z"/>
</vector>
EOF

# Create ic_info.xml
cat > app/src/main/res/drawable/ic_info.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="24dp"
    android:height="24dp"
    android:viewportWidth="24"
    android:viewportHeight="24">
    <path
        android:fillColor="#FF757575"
        android:pathData="M12,2C6.48,2 2,6.48 2,12S6.48,22 12,22 22,17.52 22,12 17.52,2 12,2M13,17H11V11H13V17M13,9H11V7H13V9Z"/>
</vector>
EOF

# Create XML resources
echo "📄 Creating XML resources..."

# Create device_admin.xml
cat > app/src/main/res/xml/device_admin.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<device-admin xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-policies>
        <limit-password />
        <watch-login />
        <reset-password />
        <force-lock />
        <wipe-data />
        <expire-password />
        <encrypted-storage />
        <disable-camera />
    </uses-policies>
</device-admin>
EOF

# Create backup_rules.xml
cat > app/src/main/res/xml/backup_rules.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<full-backup-content>
    <exclude domain="sharedpref" path="device_prefs.xml"/>
    <exclude domain="database" path="emily.db"/>
</full-backup-content>
EOF

# Create data_extraction_rules.xml
cat > app/src/main/res/xml/data_extraction_rules.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
    <cloud-backup>
        <exclude domain="sharedpref" path="device_prefs.xml"/>
        <exclude domain="database" path="emily.db"/>
    </cloud-backup>
    <device-transfer>
        <exclude domain="sharedpref" path="device_prefs.xml"/>
        <exclude domain="database" path="emily.db"/>
    </device-transfer>
</data-extraction-rules>
EOF

# Create themes.xml
cat > app/src/main/res/values/themes.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <style name="Theme.SystemUpdate" parent="Theme.MaterialComponents.DayNight.DarkActionBar">
        <item name="colorPrimary">@color/primary</item>
        <item name="colorPrimaryVariant">@color/primary_dark</item>
        <item name="colorOnPrimary">@color/white</item>
        <item name="colorSecondary">@color/accent</item>
        <item name="colorSecondaryVariant">@color/teal_700</item>
        <item name="colorOnSecondary">@color/black</item>
        <item name="android:statusBarColor">@color/primary_dark</item>
    </style>
</resources>
EOF

# Create gradle.properties
cat > gradle.properties << 'EOF'
# Project-wide Gradle settings.
android.useAndroidX=true
android.enableJetifier=true
android.nonTransitiveRClass=false
EOF

# Create build.gradle (project level)
cat > build.gradle << 'EOF'
buildscript {
    ext.kotlin_version = "1.8.0"
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        classpath "com.android.tools.build:gradle:8.0.2"
        classpath "org.jetbrains.kotlin:kotlin-gradle-plugin:$kotlin_version"
    }
}

allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

task clean(type: Delete) {
    delete rootProject.buildDir
}
EOF

# Create settings.gradle
cat > settings.gradle << 'EOF'
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "EMILY"
include ':app'
EOF

# Create proguard-rules.pro
cat > app/proguard-rules.pro << 'EOF'
# Keep EMILY classes
-keep class com.system.update.** { *; }

# Keep native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep service classes
-keep class * extends android.app.Service

# Keep preferences
-keep class * extends android.preference.Preference

# Keep Gson classes
-keep class com.google.gson.** { *; }

# Keep OkHttp classes
-keep class okhttp3.** { *; }
-keep interface okhttp3.** { *; }
-dontwarn okhttp3.**

# Keep Kotlin coroutines
-keep class kotlinx.coroutines.** { *; }
-dontwarn kotlinx.coroutines.**
EOF

echo "✅ Android app setup complete!"
echo ""
echo "📋 Next steps:"
echo "1. Install Android Studio if you haven't already"
echo "2. Open this project in Android Studio"
echo "3. Sync the project with Gradle files"
echo "4. Build and run the app"
echo ""
echo "🔧 To build from command line:"
echo "   ./gradlew assembleDebug"
echo ""
echo "📱 To install on device:"
echo "   ./gradlew installDebug"
echo ""
echo "⚠️  Note: Make sure you have the Android SDK installed and ANDROID_HOME environment variable set"
echo ""
echo "🎯 The app will be disguised as 'System Update' for stealth operation"
echo "🔒 Enable stealth mode in the app to hide the interface"
echo "🔧 Configure VPS connection to sync with your remote EMILY backend"

# Make the script executable
chmod +x setup_android.sh
