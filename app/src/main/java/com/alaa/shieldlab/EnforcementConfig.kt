package com.alaa.shieldlab

object EnforcementConfig {
    enum class Mode { DIAGNOSE, KILL }
    val MODE: Mode = Mode.KILL

    // Core
    const val CHECK_CERT     = true
    const val CHECK_DEBUGGER = true
    const val CHECK_FRIDA    = true
    const val CHECK_RWXP     = true
    const val CHECK_XPOSED   = true

    // Vigil & AndroidShield (جديد)
    const val CHECK_SENSOR_ANOMALY = true
    const val CHECK_OVERLAYFS      = true
    const val CHECK_CLONER_PKG     = true

    // Emulator
    const val CHECK_QEMU_ARTIFACTS = true
    const val CHECK_ARM_TRANSLATION = true
    const val CHECK_NATIVE_BRIDGE  = true
    const val CHECK_BUILD_PROPS    = true
    
    // Optional (Disable for rooted/emulator testing)
    const val CHECK_ROOT = false
    const val CHECK_EMULATOR = false
}
