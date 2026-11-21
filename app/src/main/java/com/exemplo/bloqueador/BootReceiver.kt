package com.exemplo.bloqueador

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        if (!Prefs.autostart(ctx)) return
        if (VpnService.prepare(ctx) != null) return  // sem permissão de VPN ainda
        val s = Intent(ctx, AdVpnService::class.java).setAction(AdVpnService.ACTION_START)
        try {
            if (Build.VERSION.SDK_INT >= 26) ctx.startForegroundService(s) else ctx.startService(s)
        } catch (e: Exception) {}
    }
}
