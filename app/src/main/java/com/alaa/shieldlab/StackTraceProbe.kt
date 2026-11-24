package com.alaa.shieldlab

object StackTraceProbe {
    data class Result(
        val substrate: Boolean = false,
        val xposed: Boolean = false,
        val zygoteDouble: Boolean = false,
    ) {
        fun anyFound(): Boolean = substrate || xposed || zygoteDouble
    }

    fun check(): Result {
        var substrate = false
        var xposed = false
        var zygoteDouble = false

        try {
            throw Exception("probe")
        } catch (e: Exception) {
            var zygoteCount = 0
            for (elem in e.stackTrace) {
                val cls = elem.className
                val mtd = elem.methodName
                if (cls == "com.android.internal.os.ZygoteInit") {
                    zygoteCount++
                    if (zygoteCount == 2) {
                        substrate = true
                        zygoteDouble = true
                    }
                }
                if (cls == "com.saurik.substrate.MS$2" && mtd == "invoked") substrate = true
                if (cls == "de.robv.android.xposed.XposedBridge" &&
                    (mtd == "main" || mtd == "handleHookedMethod")) xposed = true
                if (cls.startsWith("de.robv.android.xposed.")) xposed = true
                if (cls.startsWith("org.lsposed.")) xposed = true
            }
        }

        return Result(substrate, xposed, zygoteDouble)
    }
}
