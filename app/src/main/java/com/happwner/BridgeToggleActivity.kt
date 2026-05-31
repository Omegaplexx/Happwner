package com.happwner

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle

// Invisible proxy: toggles the bridge, requesting notification permission if needed
class BridgeToggleActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Already on: just turn it off and finish
        if (BridgeController.isEnabled(this)) {
            BridgeController.disable(this)
            finish()
            return
        }

        // API 33+: ask for notification permission first, then enable in the callback
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIF)
            return
        }

        // Permission already granted (or not needed): enable now
        BridgeController.enable(this)
        finish()
    }

    // Enable regardless of the result (the FGS runs even without a visible notification)
    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQ_NOTIF) {
            BridgeController.enable(this)
        }
        finish()
    }

    companion object {
        private const val REQ_NOTIF = 4021
    }
}
