package com.alaa.shieldlab

import android.app.Application
import android.os.Build
import android.util.Log
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class ShieldApplication : Application() {
    private val TAG = "ShieldLab"
    val logFile: File by lazy {
        val dir = File(filesDir, ".shield").apply { mkdirs() }
        File(dir, ".diag")
    }

    override fun onCreate() {
        super.onCreate()
        try {
            log("Startup: ${EnforcementConfig.MODE}")
            val failure = runAllChecks()
            if (failure != null) {
                log("FAILED: $failure")
                handleFailure(failure)
            } else {
                log("PASSED")
            }
        } catch (t: Throwable) {
            log("EXCEPTION: ${t.message}")
            handleFailure("onCreate_exception")
        }
    }

    fun runAllChecks(): String? {
        if (!Enforcement.available()) return "native_not_loaded"
        val apk = try { SignatureBridge.getApkPath(this) } catch (t: Throwable) { return "apk_path" }

        // 1. Cert
        if (EnforcementConfig.CHECK_CERT) {
            val res = Enforcement.nativeEnforceCert(apk)
            if (res != 0) return "cert_$res"
        }

        // 2. Core Env
        val env = Enforcement.envReport()
        if (EnforcementConfig.CHECK_DEBUGGER && env["debugger"] == true) return "debugger"
        if (EnforcementConfig.CHECK_FRIDA && env["frida"] == true) return "frida"
        if (EnforcementConfig.CHECK_ROOT && env["root"] == true) return "root"
        if (EnforcementConfig.CHECK_EMULATOR && env["emulator"] == true) return "emulator"

        // 3. Extra
        val extra = Enforcement.extraReport(this)
        if (EnforcementConfig.CHECK_RWXP && extra["rwxp"] == true) return "rwxp"
        if (EnforcementConfig.CHECK_XPOSED && extra["clone"] == true) return "clone"

        // 4. Deep Emulator
        val emu = Enforcement.deepEmulatorReport()
        if (EnforcementConfig.CHECK_QEMU_ARTIFACTS && emu["qemu_artifacts"] == true) return "qemu"
        if (EnforcementConfig.CHECK_ARM_TRANSLATION && emu["arm_translation"] == true) return "arm_trans"
        if (EnforcementConfig.CHECK_BUILD_PROPS && emu["build_props"] == true) return "build_props"

        // 5. Vigil & AndroidShield (New)
        val vigil = Enforcement.vigilReport()
        if (EnforcementConfig.CHECK_SENSOR_ANOMALY && vigil["sensor_anomaly"] == true) return "sensor"
        if (EnforcementConfig.CHECK_OVERLAYFS && vigil["overlayfs"] == true) return "overlayfs"
        if (EnforcementConfig.CHECK_CLONER_PKG && vigil["cloner_pkg"] == true) return "cloner"

        return null
    }

    fun handleFailure(reason: String) {
        if (EnforcementConfig.MODE == EnforcementConfig.Mode.KILL) {
            log("KILL: $reason")
            killImmediately()
        }
    }

    private fun killImmediately() {
        try { android.os.Process.killProcess(android.os.Process.myPid()) } catch (_: Throwable) {}
        try { System.exit(1) } catch (_: Throwable) {}
        try { Runtime.getRuntime().halt(1) } catch (_: Throwable) {}
    }

    fun log(msg: String) {
        Log.d(TAG, msg)
        try { logFile.appendText("[${stamp()}] $msg\n") } catch (_: Throwable) {}
    }

    private fun stamp() = SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(Date())
}
