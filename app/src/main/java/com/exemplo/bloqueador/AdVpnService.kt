package com.exemplo.bloqueador

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.drawable.Icon
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.service.quicksettings.TileService
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.LinkedList
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class BlockedEntry(val domain: String, val threat: Boolean)

/**
 * VPN local: só o tráfego DNS (para 10.111.100.2) entra no túnel.
 * Domínios de anúncios e de ameaças recebem 0.0.0.0 / ::; as demais consultas passam por
 * um cache e são enviadas em paralelo ao DNS da própria rede (com 1.1.1.1 e 8.8.8.8 de reserva).
 */
class AdVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.exemplo.bloqueador.START"
        const val ACTION_STOP = "com.exemplo.bloqueador.STOP"
        const val ACTION_RESTART = "com.exemplo.bloqueador.RESTART"
        const val VPN_ADDRESS = "10.111.100.1"
        const val VPN_DNS = "10.111.100.2"
        private const val CHANNEL_ID = "protecao"
        private const val NOTIF_ID = 1

        @Volatile var running = false
        @Volatile var instance: AdVpnService? = null
        val blockedCount = AtomicInteger(0)
        val threatCount = AtomicInteger(0)
        val allowedCount = AtomicInteger(0)
        val cacheHits = AtomicInteger(0)
        @Volatile private var countersLoaded = false

        /** Carrega os contadores salvos (uma vez por processo). */
        fun loadCounters(ctx: android.content.Context) {
            if (countersLoaded) return
            countersLoaded = true
            val c = Prefs.counters(ctx)
            blockedCount.set(c[0].toInt())
            threatCount.set(c[1].toInt())
            allowedCount.set(c[2].toInt())
            cacheHits.set(c[3].toInt())
        }

        fun saveCounters(ctx: android.content.Context) {
            Prefs.saveCounters(ctx, blockedCount.get(), threatCount.get(), allowedCount.get(), cacheHits.get())
        }

        private val recent = LinkedList<BlockedEntry>()

        fun recordBlocked(name: String, threat: Boolean) {
            synchronized(recent) {
                val it = recent.iterator()
                while (it.hasNext()) {
                    if (it.next().domain == name) it.remove()
                }
                recent.addFirst(BlockedEntry(name, threat))
                while (recent.size > 80) recent.removeLast()
            }
        }

        fun recentSnapshot(): List<BlockedEntry> = synchronized(recent) { ArrayList(recent) }

        // Domínios mais acessados (permitidos) desde que a proteção foi ligada
        private val domainHits = ConcurrentHashMap<String, AtomicInteger>()

        fun recordDomain(name: String) {
            if (name.isEmpty()) return
            if (domainHits.size > 3000) {
                // mantém a tabela leve: descarta os que apareceram só uma vez
                domainHits.entries.removeIf { it.value.get() <= 1 }
            }
            domainHits.getOrPut(name) { AtomicInteger(0) }.incrementAndGet()
        }

        fun topDomains(n: Int): List<Pair<String, Int>> =
            domainHits.entries.map { it.key to it.value.get() }
                .sortedByDescending { it.second }
                .take(n)
    }

    private class Question(val name: String, val end: Int, val type: Int)
    private class TcpConn(var ourSeq: Long, var theirNext: Long)
    private class CacheEntry(val resp: ByteArray, val expires: Long)

    private val dnsBytes = byteArrayOf(10, 111, 100, 2)
    private val emptyBytes = ByteArray(0)
    private var tun: ParcelFileDescriptor? = null
    private val pool = Executors.newFixedThreadPool(16)
    private val racePool = Executors.newCachedThreadPool()
    private val ui = Handler(Looper.getMainLooper())
    private val writeLock = Any()
    @Volatile private var out: FileOutputStream? = null
    @Volatile private var starting = false
    @Volatile private var gen = 0
    @Volatile private var upstreams: List<InetAddress> = emptyList()
    @Volatile private var lastGood: InetAddress? = null
    private val conns = ConcurrentHashMap<Int, TcpConn>()
    private var cm: ConnectivityManager? = null
    private var netCb: ConnectivityManager.NetworkCallback? = null

    private val cache = object : LinkedHashMap<String, CacheEntry>(512, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, CacheEntry>?): Boolean =
            size > 3000
    }

    // ---------- Ciclo de vida ----------

    override fun onCreate() {
        super.onCreate()
        instance = this
        loadCounters(applicationContext)
        if (Build.VERSION.SDK_INT >= 26) {
            val ch = NotificationChannel(CHANNEL_ID, "Proteção", NotificationManager.IMPORTANCE_LOW)
            getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            requestStop()
            return START_NOT_STICKY
        }
        if (intent?.action == ACTION_RESTART) {
            // aplica mudanças (ex.: apps sem bloqueio) sem o usuário desligar e ligar
            goForeground()
            stopVpn()
            startVpn()
            return START_STICKY
        }
        goForeground()
        startVpn()
        return START_STICKY
    }

    override fun onRevoke() {
        requestStop()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpn()
        ui.removeCallbacks(notifTick)
        instance = null
        pool.shutdownNow()
        racePool.shutdownNow()
        super.onDestroy()
    }

    /** Limpa o cache de DNS (ex.: depois de bloquear um domínio). Devolve quantas respostas saíram. */
    fun clearDnsCache(): Int = synchronized(cache) {
        val n = cache.size
        cache.clear()
        n
    }

    fun requestStop() {
        stopVpn()
        ui.post {
            try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (e: Exception) {}
            stopSelf()
        }
    }

    private fun stopVpn() {
        saveCounters(applicationContext)
        gen++  // o túnel antigo, ao fechar, não derruba o serviço (importante no reinício)
        running = false
        starting = false
        closeTun()
        unregisterNet()
        notifyTile()
    }

    private fun closeTun() {
        try { tun?.close() } catch (e: Exception) {}
        tun = null
    }

    private fun notifyTile() {
        try {
            TileService.requestListeningState(this, ComponentName(this, ToggleTileService::class.java))
        } catch (e: Exception) {}
    }

    // ---------- Notificação ----------

    private fun buildNotification(): Notification {
        val stopPi = PendingIntent.getService(
            this, 1,
            Intent(this, AdVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val openPi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        val b = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, CHANNEL_ID)
        else Notification.Builder(this)
        b.setSmallIcon(R.drawable.ic_stat)
            .setContentTitle("Proteção ativa")
            .setContentText("${blockedCount.get()} anúncios e ${threatCount.get()} ameaças bloqueados")
            .setContentIntent(openPi)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .addAction(
                Notification.Action.Builder(
                    Icon.createWithResource(this, android.R.drawable.ic_menu_close_clear_cancel),
                    "Desligar", stopPi
                ).build()
            )
        if (Build.VERSION.SDK_INT < 26) b.setPriority(Notification.PRIORITY_LOW)
        return b.build()
    }

    private fun goForeground() {
        try {
            val n = buildNotification()
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
            } else {
                startForeground(NOTIF_ID, n)
            }
        } catch (e: Exception) {
            // segue sem notificação fixa
        }
    }

    private val notifTick = object : Runnable {
        override fun run() {
            if (!running) return
            saveCounters(applicationContext)
            try {
                getSystemService(NotificationManager::class.java).notify(NOTIF_ID, buildNotification())
            } catch (e: Exception) {}
            ui.postDelayed(this, 5000)
        }
    }

    // ---------- Início do túnel ----------

    private fun startVpn() {
        if (running || starting) return
        starting = true
        val my = ++gen
        Thread {
            try {
                Blocklist.loadAll(applicationContext)
                registerNet()
                val b = Builder()
                    .setSession("Bloqueador de Anúncios")
                    .setMtu(1500)
                    .addAddress(VPN_ADDRESS, 24)
                    .addDnsServer(VPN_DNS)
                    .addRoute(VPN_DNS, 32)
                try { b.addDisallowedApplication(packageName) } catch (e: Exception) {}
                for (pkg in Prefs.excluded(applicationContext)) {
                    try { b.addDisallowedApplication(pkg) } catch (e: Exception) {}
                }
                val pfd = b.establish()
                if (pfd == null || !starting) {
                    pfd?.close()
                    return@Thread
                }
                tun = pfd
                running = true
                starting = false
                notifyTile()
                ui.removeCallbacks(notifTick)
                ui.post(notifTick)
                val input = FileInputStream(pfd.fileDescriptor)
                out = FileOutputStream(pfd.fileDescriptor)
                val buf = ByteArray(32767)
                while (running) {
                    val n = input.read(buf)
                    if (n > 0) handlePacket(buf.copyOf(n)) else Thread.sleep(5)
                }
            } catch (e: Exception) {
                // encerra
            } finally {
                if (gen == my) {
                    running = false
                    starting = false
                    closeTun()
                    unregisterNet()
                    notifyTile()
                    ui.post {
                        try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (e: Exception) {}
                        stopSelf()
                    }
                }
            }
        }.also { it.start() }
    }

    // ---------- DNS da rede ----------

    private fun registerNet() {
        val m = getSystemService(ConnectivityManager::class.java) ?: return
        cm = m
        refreshUpstreams()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) { refreshUpstreams() }
            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) { refreshUpstreams() }
            override fun onLost(network: Network) { refreshUpstreams() }
        }
        try {
            m.registerNetworkCallback(
                NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    .build(),
                cb
            )
            netCb = cb
        } catch (e: Exception) {}
    }

    private fun unregisterNet() {
        try { netCb?.let { cm?.unregisterNetworkCallback(it) } } catch (e: Exception) {}
        netCb = null
    }

    private fun refreshUpstreams() {
        val m = cm ?: return
        synchronized(cache) { cache.clear() }  // rede mudou: respostas antigas podem não valer
        try {
            val ranked = ArrayList<Pair<Int, Network>>()
            for (n in m.allNetworks) {
                val c = m.getNetworkCapabilities(n) ?: continue
                if (!c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
                if (c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
                var score = when {
                    c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 0
                    c.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 1
                    c.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 2
                    else -> 3
                }
                if (!c.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) score += 10
                ranked.add(Pair(score, n))
            }
            ranked.sortBy { it.first }
            val list = ArrayList<InetAddress>()
            for ((_, n) in ranked) {
                val lp = m.getLinkProperties(n) ?: continue
                for (a in lp.dnsServers) {
                    if (a.isLoopbackAddress || a.isLinkLocalAddress || a.isAnyLocalAddress) continue
                    if (!list.contains(a)) list.add(a)
                }
            }
            for (f in listOf("1.1.1.1", "8.8.8.8")) {
                val a = InetAddress.getByName(f)
                if (!list.contains(a)) list.add(a)
            }
            upstreams = list
        } catch (e: Exception) {
            if (upstreams.isEmpty()) {
                upstreams = listOf(InetAddress.getByName("1.1.1.1"), InetAddress.getByName("8.8.8.8"))
            }
        }
    }

    private fun orderedUpstreams(): List<InetAddress> {
        var l = upstreams
        if (l.isEmpty()) {
            refreshUpstreams()
            l = upstreams
        }
        val g = lastGood
        return if (g != null && l.contains(g)) listOf(g) + l.filter { it != g } else l
    }

    // ---------- Utilitários de bytes ----------

    private fun u16(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)

    private fun u32(b: ByteArray, o: Int): Long =
        ((b[o].toLong() and 0xFF) shl 24) or ((b[o + 1].toLong() and 0xFF) shl 16) or
            ((b[o + 2].toLong() and 0xFF) shl 8) or (b[o + 3].toLong() and 0xFF)

    private fun put16(b: ByteArray, o: Int, v: Int) {
        b[o] = (v shr 8).toByte()
        b[o + 1] = v.toByte()
    }

    private fun put32(b: ByteArray, o: Int, v: Long) {
        b[o] = (v shr 24).toByte()
        b[o + 1] = (v shr 16).toByte()
        b[o + 2] = (v shr 8).toByte()
        b[o + 3] = v.toByte()
    }

    // ---------- Pacotes recebidos ----------

    private fun handlePacket(p: ByteArray) {
        if (p.size < 28) return
        if ((p[0].toInt() shr 4) != 4) return
        val ihl = (p[0].toInt() and 0x0F) * 4
        if (p.size < ihl + 8) return
        val dstIp = p.copyOfRange(16, 20)
        if (!dstIp.contentEquals(dnsBytes)) return
        val srcIp = p.copyOfRange(12, 16)
        when (p[9].toInt() and 0xFF) {
            17 -> handleUdp(p, ihl, srcIp, dstIp)
            6 -> handleTcp(p, ihl, srcIp, dstIp)
        }
    }

    private fun handleUdp(p: ByteArray, ihl: Int, srcIp: ByteArray, dstIp: ByteArray) {
        val srcPort = u16(p, ihl)
        val dstPort = u16(p, ihl + 2)
        if (dstPort != 53) return
        val udpLen = u16(p, ihl + 4)
        val end = minOf(p.size, ihl + udpLen)
        if (end - (ihl + 8) < 12) return
        val dns = p.copyOfRange(ihl + 8, end)

        val blocked = tryBlock(dns)
        if (blocked != null) {
            writePacket(buildUdpPacket(dstIp, srcIp, dstPort, srcPort, blocked))
        } else {
            pool.execute {
                val r = resolve(dns, false)
                if (r != null) writePacket(buildUdpPacket(dstIp, srcIp, dstPort, srcPort, r))
            }
        }
    }

    private fun handleTcp(p: ByteArray, ihl: Int, srcIp: ByteArray, dstIp: ByteArray) {
        if (p.size < ihl + 20) return
        val total = minOf(p.size, u16(p, 2))
        val clientPort = u16(p, ihl)
        val dstPort = u16(p, ihl + 2)
        val seq = u32(p, ihl + 4)
        val ackNum = u32(p, ihl + 8)
        val off = ((p[ihl + 12].toInt() and 0xF0) shr 4) * 4
        val flags = p[ihl + 13].toInt() and 0xFF
        val dataStart = ihl + off
        val payloadLen = maxOf(0, total - dataStart)
        val isFin = (flags and 0x01) != 0
        val isSyn = (flags and 0x02) != 0
        val isRst = (flags and 0x04) != 0
        val isAck = (flags and 0x10) != 0

        if (isRst) {
            conns.remove(clientPort)
            return
        }

        // Qualquer porta que não seja 53 (ex.: 853 do DNS privado) é recusada na hora
        if (dstPort != 53) {
            if (isSyn) sendTcp(srcIp, dstIp, clientPort, dstPort, 0, (seq + 1) and 0xFFFFFFFFL, 0x14)
            else sendTcp(srcIp, dstIp, clientPort, dstPort, ackNum, 0, 0x04)
            return
        }

        if (isSyn && !isAck) {
            val isn = System.nanoTime() and 0x7FFFFFFFL
            val c = TcpConn((isn + 1) and 0xFFFFFFFFL, (seq + 1) and 0xFFFFFFFFL)
            conns[clientPort] = c
            sendTcp(srcIp, dstIp, clientPort, 53, isn, c.theirNext, 0x12, emptyBytes, true)
            return
        }

        val c = conns[clientPort]
        if (c == null) {
            if (payloadLen > 0 || isFin) sendTcp(srcIp, dstIp, clientPort, 53, ackNum, 0, 0x04)
            return
        }

        if (payloadLen > 0) {
            var duplicate = false
            synchronized(c) {
                if (seq != c.theirNext) {
                    duplicate = true
                    sendTcp(srcIp, dstIp, clientPort, 53, c.ourSeq, c.theirNext, 0x10)
                } else {
                    c.theirNext = (seq + payloadLen) and 0xFFFFFFFFL
                }
            }
            if (duplicate) return

            val data = p.copyOfRange(dataStart, dataStart + payloadLen)
            if (data.size >= 2) {
                val len = u16(data, 0)
                if (len >= 12 && data.size >= 2 + len) {
                    val dns = data.copyOfRange(2, 2 + len)
                    val blocked = tryBlock(dns)
                    pool.execute {
                        val resp = blocked ?: resolve(dns, true)
                        if (resp != null) sendTcpData(srcIp, dstIp, clientPort, c, resp)
                    }
                    return
                }
            }
            synchronized(c) { sendTcp(srcIp, dstIp, clientPort, 53, c.ourSeq, c.theirNext, 0x10) }
            return
        }

        if (isFin) {
            synchronized(c) {
                c.theirNext = (seq + 1) and 0xFFFFFFFFL
                sendTcp(srcIp, dstIp, clientPort, 53, c.ourSeq, c.theirNext, 0x11)
                c.ourSeq = (c.ourSeq + 1) and 0xFFFFFFFFL
            }
            conns.remove(clientPort)
        }
    }

    // ---------- Resolução ----------

    private fun parseQuestion(d: ByteArray): Question? {
        var i = 12
        val sb = StringBuilder()
        while (i < d.size) {
            val len = d[i].toInt() and 0xFF
            if (len == 0) { i++; break }
            if ((len and 0xC0) != 0) return null
            if (i + 1 + len > d.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(d, i + 1, len, Charsets.US_ASCII))
            i += 1 + len
        }
        if (i + 4 > d.size) return null
        return Question(sb.toString(), i + 4, u16(d, i))
    }

    private fun tryBlock(dns: ByteArray): ByteArray? {
        val q = parseQuestion(dns) ?: return null
        val kind = Blocklist.check(q.name)
        if (kind == Blocklist.NONE) return null
        if (kind == Blocklist.THREAT) threatCount.incrementAndGet() else blockedCount.incrementAndGet()
        recordBlocked(q.name, kind == Blocklist.THREAT)
        return blockedResponse(dns, q)
    }

    private fun blockedResponse(d: ByteArray, q: Question): ByteArray {
        val answer: ByteArray? = when (q.type) {
            1 -> ByteArray(4)      // A    -> 0.0.0.0
            28 -> ByteArray(16)    // AAAA -> ::
            else -> null           // HTTPS/outros -> resposta vazia, sem erro
        }
        val r = ByteArrayOutputStream()
        r.write(d, 0, 2)
        r.write(0x80 or (d[2].toInt() and 0x01))  // QR + RD
        r.write(0x80)                              // RA
        r.write(0); r.write(1)
        r.write(0); r.write(if (answer != null) 1 else 0)
        r.write(0); r.write(0); r.write(0); r.write(0)
        r.write(d, 12, q.end - 12)
        if (answer != null) {
            r.write(0xC0); r.write(0x0C)
            r.write(0); r.write(q.type)
            r.write(0); r.write(1)
            r.write(0); r.write(0); r.write(0); r.write(60)
            r.write(0); r.write(answer.size)
            r.write(answer)
        }
        return r.toByteArray()
    }

    // ---------- Cache de DNS ----------

    private fun cacheKey(dns: ByteArray, q: Question): String {
        val cls = u16(dns, q.end - 2)
        val edns = if (u16(dns, 10) > 0) "|e" else ""
        return q.name.lowercase() + "|" + q.type + "|" + cls + edns
    }

    private fun cacheGet(key: String, dns: ByteArray): ByteArray? {
        val e = synchronized(cache) { cache[key] } ?: return null
        if (System.currentTimeMillis() > e.expires) {
            synchronized(cache) { cache.remove(key) }
            return null
        }
        val r = e.resp.copyOf()
        r[0] = dns[0]
        r[1] = dns[1]
        return r
    }

    private fun skipName(r: ByteArray, start: Int): Int {
        var i = start
        while (i < r.size) {
            val l = r[i].toInt() and 0xFF
            if (l == 0) return i + 1
            if ((l and 0xC0) == 0xC0) return i + 2
            i += 1 + l
        }
        return -1
    }

    // menor TTL entre as respostas e a autoridade; -1 se não der para saber
    private fun minTtl(r: ByteArray): Int {
        if (r.size < 12) return -1
        val qd = u16(r, 4)
        val an = u16(r, 6)
        val ns = u16(r, 8)
        var i = 12
        repeat(qd) {
            i = skipName(r, i)
            if (i < 0) return -1
            i += 4
        }
        var min = Int.MAX_VALUE
        repeat(an + ns) {
            i = skipName(r, i)
            if (i < 0 || i + 10 > r.size) return -1
            val ttl = u32(r, i + 4)
            val rd = u16(r, i + 8)
            val t = if (ttl > 86400L) 86400 else ttl.toInt()
            if (t < min) min = t
            i += 10 + rd
            if (i > r.size) return -1
        }
        return if (min == Int.MAX_VALUE) -1 else min
    }

    private fun cachePut(key: String, r: ByteArray) {
        if (r.size < 12) return
        val rcode = r[3].toInt() and 0x0F
        val truncated = (r[2].toInt() and 0x02) != 0
        if (truncated || (rcode != 0 && rcode != 3)) return
        val ttl = minTtl(r)
        if (ttl <= 0) return
        val life = minOf(ttl, 600) * 1000L
        synchronized(cache) { cache[key] = CacheEntry(r, System.currentTimeMillis() + life) }
    }

    private fun resolve(dns: ByteArray, tcp: Boolean): ByteArray? {
        val q = parseQuestion(dns)
        if (q != null) recordDomain(q.name.lowercase().trimEnd('.'))
        val key = if (q != null) cacheKey(dns, q) else null
        if (key != null) {
            val hit = cacheGet(key, dns)
            if (hit != null) {
                cacheHits.incrementAndGet()
                return hit
            }
        }
        val r = (if (tcp) forwardTcp(dns) else forward(dns)) ?: return null
        allowedCount.incrementAndGet()
        if (key != null) cachePut(key, r)
        return r
    }

    // ---------- Envio ao DNS real ----------

    private fun queryUdp(up: InetAddress, dns: ByteArray): ByteArray? {
        return try {
            DatagramSocket().use { s ->
                protect(s)
                s.soTimeout = 2500
                s.connect(up, 53)
                s.send(DatagramPacket(dns, dns.size))
                val buf = ByteArray(4096)
                val resp = DatagramPacket(buf, buf.size)
                s.receive(resp)
                lastGood = up
                buf.copyOf(resp.length)
            }
        } catch (e: Exception) {
            null
        }
    }

    // pergunta aos 2 primeiros DNS ao mesmo tempo e usa quem responder primeiro
    private fun forward(dns: ByteArray): ByteArray? {
        val ups = orderedUpstreams()
        if (ups.isEmpty()) return null
        val first = ups.take(2)
        val fut = CompletableFuture<ByteArray>()
        val left = AtomicInteger(first.size)
        for (up in first) {
            racePool.execute {
                val r = queryUdp(up, dns)
                if (r != null) fut.complete(r)
                if (left.decrementAndGet() == 0) fut.complete(emptyBytes)
            }
        }
        val res = try { fut.get(4000, TimeUnit.MILLISECONDS) } catch (e: Exception) { null }
        if (res != null && res.isNotEmpty()) return res
        for (up in ups.drop(2)) {
            val r = queryUdp(up, dns)
            if (r != null) return r
        }
        return null
    }

    private fun forwardTcp(dns: ByteArray): ByteArray? {
        for (up in orderedUpstreams()) {
            try {
                Socket().use { s ->
                    s.bind(null)
                    protect(s)
                    s.soTimeout = 3000
                    s.connect(InetSocketAddress(up, 53), 2500)
                    val o = s.getOutputStream()
                    o.write(byteArrayOf((dns.size shr 8).toByte(), dns.size.toByte()))
                    o.write(dns)
                    o.flush()
                    val inp = DataInputStream(s.getInputStream())
                    val len = inp.readUnsignedShort()
                    val buf = ByteArray(len)
                    inp.readFully(buf)
                    lastGood = up
                    return buf
                }
            } catch (e: Exception) {
                // tenta o próximo
            }
        }
        return null
    }

    // ---------- Pacotes enviados ----------

    private fun writePacket(pkt: ByteArray) {
        synchronized(writeLock) {
            try { out?.write(pkt) } catch (e: Exception) {}
        }
    }

    private fun fillIp(h: ByteArray, total: Int, proto: Int, src: ByteArray, dst: ByteArray) {
        h[0] = 0x45
        put16(h, 2, total)
        h[6] = 0x40
        h[8] = 64
        h[9] = proto.toByte()
        System.arraycopy(src, 0, h, 12, 4)
        System.arraycopy(dst, 0, h, 16, 4)
        var sum = 0
        for (i in 0 until 20 step 2) sum += u16(h, i)
        while ((sum shr 16) != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        put16(h, 10, sum.inv() and 0xFFFF)
    }

    private fun buildUdpPacket(src: ByteArray, dst: ByteArray, sp: Int, dp: Int, payload: ByteArray): ByteArray {
        val total = 20 + 8 + payload.size
        val h = ByteArray(total)
        fillIp(h, total, 17, src, dst)
        put16(h, 20, sp)
        put16(h, 22, dp)
        put16(h, 24, 8 + payload.size)
        System.arraycopy(payload, 0, h, 28, payload.size)
        return h
    }

    private fun buildTcpPacket(
        src: ByteArray, dst: ByteArray, sp: Int, dp: Int,
        seq: Long, ack: Long, flags: Int, payload: ByteArray, mss: Boolean
    ): ByteArray {
        val tcpHdr = if (mss) 24 else 20
        val tcpLen = tcpHdr + payload.size
        val total = 20 + tcpLen
        val h = ByteArray(total)
        fillIp(h, total, 6, src, dst)
        val o = 20
        put16(h, o, sp)
        put16(h, o + 2, dp)
        put32(h, o + 4, seq)
        put32(h, o + 8, ack)
        h[o + 12] = ((tcpHdr / 4) shl 4).toByte()
        h[o + 13] = flags.toByte()
        put16(h, o + 14, 65535)
        if (mss) {
            h[o + 20] = 2
            h[o + 21] = 4
            h[o + 22] = 0x05
            h[o + 23] = 0x78.toByte()
        }
        System.arraycopy(payload, 0, h, o + tcpHdr, payload.size)
        var sum = 0L
        sum += u16(src, 0) + u16(src, 2) + u16(dst, 0) + u16(dst, 2) + 6 + tcpLen
        var i = o
        while (i < total) {
            val hi = h[i].toInt() and 0xFF
            val lo = if (i + 1 < total) h[i + 1].toInt() and 0xFF else 0
            sum += (hi shl 8) or lo
            i += 2
        }
        while ((sum shr 16) != 0L) sum = (sum and 0xFFFFL) + (sum shr 16)
        put16(h, o + 16, (sum.inv() and 0xFFFFL).toInt())
        return h
    }

    // do servidor (10.111.100.2:serverPort) para o cliente
    private fun sendTcp(
        clientIp: ByteArray, serverIp: ByteArray, clientPort: Int, serverPort: Int,
        seq: Long, ack: Long, flags: Int, payload: ByteArray = emptyBytes, mss: Boolean = false
    ) {
        writePacket(buildTcpPacket(serverIp, clientIp, serverPort, clientPort, seq, ack, flags, payload, mss))
    }

    private fun sendTcpData(clientIp: ByteArray, serverIp: ByteArray, clientPort: Int, c: TcpConn, resp: ByteArray) {
        val msg = ByteArray(resp.size + 2)
        msg[0] = (resp.size shr 8).toByte()
        msg[1] = resp.size.toByte()
        System.arraycopy(resp, 0, msg, 2, resp.size)
        synchronized(c) {
            var off = 0
            while (off < msg.size) {
                val n = minOf(1360, msg.size - off)
                val chunk = msg.copyOfRange(off, off + n)
                val last = off + n >= msg.size
                sendTcp(clientIp, serverIp, clientPort, 53, c.ourSeq, c.theirNext, if (last) 0x18 else 0x10, chunk)
                c.ourSeq = (c.ourSeq + n) and 0xFFFFFFFFL
                off += n
            }
        }
    }
}
