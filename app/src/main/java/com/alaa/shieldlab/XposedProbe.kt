package com.alaa.shieldlab

object XposedProbe {
    data class Result(
        val xposedBridge: Boolean = false,
        val xposedHelpers: Boolean = false,
        val lsposed: Boolean = false,
        val substrate: Boolean = false,
    ) {
        fun anyFound(): Boolean = xposedBridge || xposedHelpers || lsposed || substrate
    }

    fun check(): Result {
        return Result(
            xposedBridge = tryLoad("de.robv.android.xposed.XposedBridge"),
            xposedHelpers = tryLoad("de.robv.android.xposed.XposedHelpers"),
            lsposed = tryLoad("org.lsposed.manager.util.ModuleUtil"),
            substrate = tryLoad("com.saurik.substrate.MS"),
        )
    }

    private fun tryLoad(name: String): Boolean = try {
        Class.forName(name, false, XposedProbe::class.java.classLoader)
        true
    } catch (_: Throwable) { false }
}
