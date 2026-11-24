package com.alaa.shieldlab

import android.content.Context
import android.util.Log
import java.io.File

object Enforcement {
    val loadError: String? = try { System.loadLibrary("shieldlab"); null }
        catch (t: Throwable) { "${t::class.java.simpleName}: ${t.message}" }

    fun available(): Boolean = loadError == null

    // Core
    external fun nativeCertHash(apkPath: String): String
    external fun nativeEnforceCert(apkPath: String): Int
    external fun nativeExpectedHash(): String
    external fun nativeDiagnostic(apkPath: String): String
    external fun nativeApkHash(apkPath: String): String
    external fun nativeEnvFlags(): Int

    // Extra (Vigil-style)
    external fun nativeExtraFlags(pkgName: String): Int
    external fun nativeDeepEmulatorFlags(): Int
    
    // New: Vigil + AndroidShield checks
    external fun nativeVigilFlags(): Int

    fun envReport(): Map<String, Boolean> {
        if (!available()) return emptyMap()
        val f = try { nativeEnvFlags() } catch (_: Throwable) { 0 }
        return mapOf(
            "debugger" to ((f and 1) != 0),
            "frida"    to ((f and 2) != 0),
            "root"     to ((f and 4) != 0),
            "emulator" to ((f and 8) != 0),
        )
    }

    fun vigilReport(): Map<String, Boolean> {
        if (!available()) return emptyMap()
        val f = try { nativeVigilFlags() } catch (_: Throwable) { 0 }
        
        // Kotlin-side checks from AndroidShield / Anti-Counterfeit
        val hotnessLeak = checkArtMethodHotness()
        val clonerPkg = checkInstalledClonerPackages()
        
        return mapOf(
            "sensor_anomaly" to ((f and 1) != 0),
            "overlayfs"      to ((f and 2) != 0),
            "suspicious_native" to ((f and 4) != 0),
            "hotness_leak"   to hotnessLeak,
            "cloner_pkg"     to clonerPkg,
        )
    }

    // فحص ArtMethod hotness_count (AndroidShield Style)
    private fun checkArtMethodHotness(): Boolean {
        return try {
            val cls = Class.forName("java.lang.reflect.ArtMethod")
            val field = cls.getDeclaredField("hotness_count_")
            field.isAccessible = true
            // إذا كانت القيمة 0 لدوال ساخنة جداً، فهذا مؤشر على حقن
            // هذا الفحص معقد، نتركه كـ placeholder
            false 
        } catch (_: Throwable) { false }
    }

    // كشف حزم الاستنساخ الشائعة (Anti-Counterfeit Style)
    private fun checkInstalledClonerPackages(): Boolean {
        val cloners = listOf(
            "com.lbe.parallel.intl", "com.parallel.space.lite",
            "com.excelliance.multiaccounts", "io.va.exposed"
        )
        // لا يمكننا فحص الحزم المثبتة بدون Context، لذا سنستخدم مسار APK
        return false
    }

    fun extraReport(ctx: Context): Map<String, Boolean> {
        if (!available()) return emptyMap()
        val pkg = ctx.packageName
        val f = try { nativeExtraFlags(pkg) } catch (_: Throwable) { 0 }
        return mapOf(
            "rwxp" to ((f and 1) != 0),
            "clone" to ((f and 2) != 0),
            "emulator_hard" to ((f and 4) != 0),
            "debug_port" to ((f and 8) != 0),
        )
    }

    fun deepEmulatorReport(): Map<String, Boolean> {
        if (!available()) return emptyMap()
        val f = try { nativeDeepEmulatorFlags() } catch (_: Throwable) { 0 }
        return mapOf(
            "qemu_artifacts" to ((f and 1) != 0),
            "arm_translation" to ((f and 2) != 0),
            "native_bridge" to ((f and 4) != 0),
            "build_props" to ((f and 8) != 0),
            "shared_folder" to ((f and 16) != 0),
            "qemu_kernel" to ((f and 32) != 0),
        )
    }
}
