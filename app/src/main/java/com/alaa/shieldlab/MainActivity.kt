package com.alaa.shieldlab

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    private val handler = Handler(Looper.getMainLooper())

    private val periodicCheck = object : Runnable {
        override fun run() {
            val app = application as? ShieldApplication ?: return
            val failure = try { app.runAllChecks() } catch (t: Throwable) {
                "periodic_exception: ${t.message}"
            }
            if (failure != null) {
                app.handleFailure(failure)
                return
            }
            handler.postDelayed(this, 5000L)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val app = application as? ShieldApplication
        if (app != null) {
            val failure = try { app.runAllChecks() } catch (t: Throwable) {
                "onCreate_exception: ${t.message}"
            }
            if (failure != null) {
                app.handleFailure(failure)
                return
            }
        }

        findViewById<TextView>(R.id.statusText).text = "✓ All checks passed"
        handler.postDelayed(periodicCheck, 5000L)
    }

    override fun onDestroy() {
        handler.removeCallbacks(periodicCheck)
        super.onDestroy()
    }
}
