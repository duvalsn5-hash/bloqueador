package com.exemplo.bloqueador

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

class ToggleTileService : TileService() {

    override fun onStartListening() {
        updateTile(AdVpnService.running)
    }

    override fun onClick() {
        if (AdVpnService.running) {
            AdVpnService.instance?.requestStop()
            updateTile(false)
            return
        }
        if (VpnService.prepare(this) != null) {
            openApp()
            return
        }
        try {
            val i = Intent(this, AdVpnService::class.java).setAction(AdVpnService.ACTION_START)
            if (Build.VERSION.SDK_INT >= 26) startForegroundService(i) else startService(i)
            updateTile(true)
        } catch (e: Exception) {
            openApp()
        }
    }

    private fun updateTile(active: Boolean) {
        val t = qsTile ?: return
        t.state = if (active) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        t.label = "Bloqueador"
        t.updateTile()
    }

    private fun openApp() {
        val i = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= 34) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 0, i, PendingIntent.FLAG_IMMUTABLE))
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(i)
        }
    }
}
