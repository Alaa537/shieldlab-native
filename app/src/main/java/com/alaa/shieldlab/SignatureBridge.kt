package com.alaa.shieldlab

import android.content.Context

object SignatureBridge {
    fun getApkPath(ctx: Context): String =
        ctx.packageManager.getApplicationInfo(ctx.packageName, 0).sourceDir

    fun getPackageName(ctx: Context): String = ctx.packageName
    fun getInstaller(ctx: Context): String =
        try {
            ctx.packageManager.getInstallerPackageName(ctx.packageName) ?: "unknown"
        } catch (_: Throwable) { "unknown" }
}
