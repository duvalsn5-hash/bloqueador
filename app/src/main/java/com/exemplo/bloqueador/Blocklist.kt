package com.exemplo.bloqueador

import android.content.Context
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.nio.ByteBuffer
import java.util.Arrays

private class LongBuilder {
    private var a = LongArray(1 shl 16)
    var n = 0
        private set

    fun add(v: Long) {
        if (n == a.size) a = a.copyOf(n * 2)
        a[n++] = v
    }

    fun addAll(arr: LongArray) {
        for (v in arr) add(v)
    }

    fun build(): LongArray {
        Arrays.sort(a, 0, n)
        var m = 0
        for (i in 0 until n) {
            if (m == 0 || a[i] != a[m - 1]) {
                a[m] = a[i]
                m++
            }
        }
        return a.copyOf(m)
    }
}

object Blocklist {

    const val NONE = 0
    const val ADS = 1
    const val THREAT = 2

    private class Source(val url: String, val threat: Boolean)

    // Anúncios, rastreadores e pop-ups (threat = false) e malware/phishing (threat = true)
    private val SOURCES = listOf(
        Source("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", false),
        Source("https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", false),
        Source("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.plus.txt", false),
        Source("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/popupads.txt", false),
        Source("https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext", false),
        Source("https://phishing.army/download/phishing_army_blocklist.txt", true),
        Source("https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt", true),
        Source("https://urlhaus.abuse.ch/downloads/hostfile/", true),
        Source("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.medium.txt", true)
    )

    private val DOMAIN = Regex("^[a-z0-9_.-]+\\.[a-z0-9-]{2,}$")

    @Volatile private var ads: LongArray = LongArray(0)
    @Volatile private var threats: LongArray = LongArray(0)
    @Volatile private var customBlock: Set<String> = emptySet()
    @Volatile private var customAllow: Set<String> = emptySet()
    @Volatile var threatsEnabled: Boolean = true
    private val updating = java.util.concurrent.atomic.AtomicBoolean(false)

    val adsCount: Int get() = ads.size
    val threatCount: Int get() = threats.size
    val totalDomains: Int get() = ads.size + threats.size + customBlock.size

    private fun prefs(ctx: Context) =
        ctx.getSharedPreferences("bloqueador", Context.MODE_PRIVATE)

    fun lastUpdate(ctx: Context): Long {
        val f = File(ctx.filesDir, "ads.bin")
        return if (f.exists()) f.lastModified() else 0L
    }

    // hash FNV-1a de 64 bits: guarda cada domínio em 8 bytes (bem menos memória)
    private fun hash(s: String): Long {
        var h = -3750763034362895579L
        for (ch in s) {
            h = h xor ch.code.toLong()
            h *= 1099511628211L
        }
        return h
    }

    private fun readBin(f: File): LongArray {
        if (!f.exists()) return LongArray(0)
        val lb = ByteBuffer.wrap(f.readBytes()).asLongBuffer()
        val out = LongArray(lb.remaining())
        lb.get(out)
        return out
    }

    private fun writeBin(f: File, a: LongArray) {
        val bb = ByteBuffer.allocate(a.size * 8)
        bb.asLongBuffer().put(a)
        val tmp = File(f.path + ".tmp")
        tmp.writeBytes(bb.array())
        tmp.renameTo(f)
    }

    fun parseLine(raw: String): String? {
        var l = raw.trim()
        if (l.isEmpty() || l[0] == '#' || l[0] == '!' || l[0] == '[') return null
        if (l.startsWith("@@")) return null
        if (l.contains("badfilter") || l.contains("dnsrewrite")) return null
        val d: String
        if (l.startsWith("||")) {
            val end = l.indexOf('^')
            if (end < 0) return null
            d = l.substring(2, end)
        } else {
            val hashPos = l.indexOf('#')
            if (hashPos > 0) l = l.substring(0, hashPos).trim()
            val parts = l.split(Regex("\\s+"))
            d = when {
                parts.size >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1") -> parts[1]
                parts.size == 1 -> parts[0]
                else -> return null
            }
        }
        val x = d.lowercase().trimEnd('.')
        return if (DOMAIN.matches(x)) x else null
    }

    @Synchronized
    fun loadAll(ctx: Context) {
        val adsB = LongBuilder()
        ctx.assets.open("blocklist_base.txt").bufferedReader().useLines { lines ->
            lines.forEach { l -> parseLine(l)?.let { adsB.add(hash(it)) } }
        }
        adsB.addAll(readBin(File(ctx.filesDir, "ads.bin")))
        ads = adsB.build()
        threats = readBin(File(ctx.filesDir, "threats.bin"))
        val p = prefs(ctx)
        customBlock = p.getStringSet("block", emptySet())!!.toSet()
        customAllow = p.getStringSet("allow", emptySet())!!.toSet()
        threatsEnabled = Prefs.threats(ctx)
    }

    fun update(ctx: Context, progress: (String) -> Unit) {
        // evita duas atualizações ao mesmo tempo (manual + semanal)
        if (!updating.compareAndSet(false, true)) {
            progress("Atualização já em andamento…")
            return
        }
        try {
            doUpdate(ctx, progress)
        } finally {
            updating.set(false)
        }
    }

    private fun doUpdate(ctx: Context, progress: (String) -> Unit) {
        val adsB = LongBuilder()
        val thrB = LongBuilder()
        var adsOk = 0
        var thrOk = 0
        for ((i, s) in SOURCES.withIndex()) {
            progress("Baixando lista ${i + 1}/${SOURCES.size}…")
            try {
                val c = URL(s.url).openConnection() as HttpURLConnection
                c.connectTimeout = 15000
                c.readTimeout = 60000
                val b = if (s.threat) thrB else adsB
                c.inputStream.bufferedReader().useLines { lines ->
                    lines.forEach { l -> parseLine(l)?.let { b.add(hash(it)) } }
                }
                c.disconnect()
                if (s.threat) thrOk++ else adsOk++
            } catch (e: Exception) {
                // segue para a próxima lista
            }
        }
        val adsArr = adsB.build()
        val thrArr = thrB.build()
        val saveAds = adsOk > 0 && adsArr.size >= 1000
        val saveThr = thrOk > 0 && thrArr.size >= 100
        if (!saveAds && !saveThr) {
            progress("Falha ao baixar as listas. Verifique a internet.")
            return
        }
        if (saveAds) writeBin(File(ctx.filesDir, "ads.bin"), adsArr)
        if (saveThr) writeBin(File(ctx.filesDir, "threats.bin"), thrArr)
        loadAll(ctx)
        progress("Pronto: $adsCount anúncios/rastreadores e $threatCount ameaças na lista.")
    }

    fun normalize(input: String): String? {
        val s = input.trim().lowercase()
            .removePrefix("http://").removePrefix("https://")
            .substringBefore('/').substringBefore(':').trimEnd('.')
        return if (DOMAIN.matches(s)) s else null
    }

    fun setCustom(ctx: Context, domain: String, block: Boolean) {
        val b = HashSet(customBlock)
        val a = HashSet(customAllow)
        if (block) { b.add(domain); a.remove(domain) } else { a.add(domain); b.remove(domain) }
        prefs(ctx).edit().putStringSet("block", b).putStringSet("allow", a).apply()
        customBlock = b
        customAllow = a
    }

    private fun matches(set: Set<String>, domain: String): Boolean {
        var s = domain
        while (true) {
            if (set.contains(s)) return true
            val i = s.indexOf('.')
            if (i < 0) return false
            s = s.substring(i + 1)
        }
    }

    private fun inSet(a: LongArray, domain: String): Boolean {
        if (a.isEmpty()) return false
        var s = domain
        while (true) {
            if (Arrays.binarySearch(a, hash(s)) >= 0) return true
            val i = s.indexOf('.')
            if (i < 0) return false
            s = s.substring(i + 1)
        }
    }

    /** Retorna NONE, ADS ou THREAT. */
    fun check(name: String): Int {
        val d = name.lowercase().trimEnd('.')
        if (matches(customAllow, d)) return NONE
        if (matches(customBlock, d)) return ADS
        if (threatsEnabled && inSet(threats, d)) return THREAT
        if (inSet(ads, d)) return ADS
        return NONE
    }
}
