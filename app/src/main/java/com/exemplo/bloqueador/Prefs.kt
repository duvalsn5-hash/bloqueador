package com.exemplo.bloqueador

import android.content.Context

object Prefs {
    private fun p(c: Context) = c.getSharedPreferences("bloqueador", Context.MODE_PRIVATE)

    fun autostart(c: Context): Boolean = p(c).getBoolean("autostart", false)
    fun setAutostart(c: Context, v: Boolean) { p(c).edit().putBoolean("autostart", v).apply() }

    fun weekly(c: Context): Boolean = p(c).getBoolean("weekly", true)
    fun setWeekly(c: Context, v: Boolean) { p(c).edit().putBoolean("weekly", v).apply() }

    fun threats(c: Context): Boolean = p(c).getBoolean("threats", true)
    fun setThreats(c: Context, v: Boolean) { p(c).edit().putBoolean("threats", v).apply() }

    // Contadores salvos para não zerarem quando o Android fecha o app
    fun counters(c: Context): LongArray {
        val p = p(c)
        return longArrayOf(
            p.getLong("c_blocked", 0), p.getLong("c_threat", 0),
            p.getLong("c_allowed", 0), p.getLong("c_cache", 0)
        )
    }
    fun saveCounters(c: Context, blocked: Int, threat: Int, allowed: Int, cache: Int) {
        p(c).edit()
            .putLong("c_blocked", blocked.toLong()).putLong("c_threat", threat.toLong())
            .putLong("c_allowed", allowed.toLong()).putLong("c_cache", cache.toLong())
            .apply()
    }

    fun excluded(c: Context): Set<String> = p(c).getStringSet("excluded", emptySet())!!.toSet()
    fun setExcluded(c: Context, s: Set<String>) { p(c).edit().putStringSet("excluded", HashSet(s)).apply() }
}
