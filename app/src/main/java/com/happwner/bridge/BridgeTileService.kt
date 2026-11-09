package com.happwner.bridge

import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.annotation.RequiresApi
import com.happwner.R
import com.happwner.data.AppLocale
import com.happwner.data.ModuleIds

@RequiresApi(Build.VERSION_CODES.N)
class BridgeTileService : TileService() {

	override fun onTileAdded() {
		super.onTileAdded()
		updateTile()
	}

	override fun onStartListening() {
		super.onStartListening()
		// A tile may start a foreground service, so the bridge comes back here too where it was left
		// on. Opening the shade is not the person asking for anything, so a refusal is not worth a
		// message: the tile itself shows what is running.
		updateTile(BridgeController.ensureServing(this, tellPerson = false))
	}

	// Tile tap: toggle on/off; if the start fails, fall back to the helper activity
	override fun onClick() {
		super.onClick()
		if (BridgeController.isOn(this)) {
			BridgeController.disable(this)
			updateTile()
			return
		}
		if (BridgeController.enable(this, tellPerson = false)) {
			updateTile(enabled = true)
			return
		}
		startToggleActivity()
	}

	// A start refused to the tile is tried again from an activity, which says why if it fails too.
	private fun startToggleActivity() {
		val intent = Intent(this, BridgeToggleActivity::class.java).apply {
			action = ModuleIds.ACTION_TOGGLE_BRIDGE
			addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
		}
		// API 34+ needs a PendingIntent for startActivityAndCollapse
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
			val pendingIntent = PendingIntent.getActivity(
				this, 0, intent,
				BridgeController.PENDING_INTENT_FLAGS
			)
			startActivityAndCollapse(pendingIntent)
		} else {
			@Suppress("DEPRECATION", "StartActivityAndCollapseDeprecated")
			startActivityAndCollapse(intent)
		}
	}

	// Push the current state (label/icon/active) onto the tile
	private fun updateTile(enabled: Boolean = BridgeController.isOn(this)) {
		val tile = qsTile ?: return
		val local = AppLocale.wrap(this)
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
