# Keep our protection classes
-keep class com.alaa.shieldlab.ShieldApplication { *; }
-keep class com.alaa.shieldlab.MainActivity { *; }
-keep class com.alaa.shieldlab.Enforcement { *; }
-keep class com.alaa.shieldlab.SignatureBridge { *; }
-keep class com.alaa.shieldlab.EnforcementConfig { *; }

# Keep native method bindings
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep JNI callbacks
-keep class * extends android.app.Application { *; }
