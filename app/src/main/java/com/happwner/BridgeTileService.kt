package com.happwner

import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.annotation.RequiresApi

@RequiresApi(Build.VERSION_CODES.N)
class BridgeTileService : TileService() {

    override fun onTileAdded() {
        super.onTileAdded()
        updateTile()
    }

    override fun onStartListening() {
        super.onStartListening()
        updateTile()
    }

    // Tile tap: toggle on/off; if the start fails, fall back to the helper activity
    override fun onClick() {
        super.onClick()
        if (BridgeController.isEnabled(this)) {
            BridgeController.disable(this)
            updateTile()
            return
        }
        if (BridgeController.enable(this)) {
            updateTile()
            return
        }
        startToggleActivity()
    }

    // Go through an activity when the notification permission must be requested
    private fun startToggleActivity() {
        val intent = Intent(this, BridgeToggleActivity::class.java).apply {
            action = BridgeController.ACTION_TOGGLE
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        }
        // API 34+ needs a PendingIntent for startActivityAndCollapse
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val pi = PendingIntent.getActivity(
                this, 0, intent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
            startActivityAndCollapse(pi)
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }

    // Push the current state (label/icon/active) onto the tile
    private fun updateTile() {
        val tile = qsTile ?: return
        val enabled = BridgeController.isEnabled(this)
        val local = BridgeController.localizedContext(this)
        tile.state = if (enabled) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = local.getString(R.string.tile_bridge_label)
        tile.icon = Icon.createWithResource(
            this,
            if (enabled) R.drawable.ic_bridge_dns_white else R.drawable.ic_bridge_dns_off_white
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = null
        }
        try { tile.updateTile() } catch (_: Throwable) {}
    }
}
