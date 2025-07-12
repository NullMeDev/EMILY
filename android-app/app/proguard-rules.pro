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
