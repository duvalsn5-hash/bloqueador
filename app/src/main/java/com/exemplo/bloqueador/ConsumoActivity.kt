package com.exemplo.bloqueador

import android.app.Activity
import android.app.AlertDialog
import android.app.AppOpsManager
import android.app.usage.NetworkStats
import android.app.usage.NetworkStatsManager
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.net.ConnectivityManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Process
import android.provider.Settings
import android.text.format.Formatter
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import java.util.Calendar

/**
 * Varredura do consumo de internet por app (NetworkStatsManager) e limpeza:
 * aponta quem mais gasta, principalmente em segundo plano, e leva às telas do Android
 * onde dá para restringir dados em segundo plano, limpar cache ou desinstalar.
 * Também mostra os domínios mais acessados pela VPN, com bloqueio em um toque.
 */
class ConsumoActivity : Activity() {

    private class AppUse(
        val uid: Int,
        val pkg: String?,
        val name: String,
        var wifi: Long = 0,
        var mobile: Long = 0,
        var background: Long = 0
    ) {
        val total: Long get() = wifi + mobile
        val bgPercent: Int get() = if (total > 0) (background * 100 / total).toInt() else 0
    }

    private var pad = 0
    private var days = 0            // 0 = hoje
    private lateinit var body: LinearLayout
    private var lastResult: List<AppUse> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        pad = (16 * resources.displayMetrics.density).toInt()

        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }
        col.addView(label(22f, true).apply { text = "Consumo de internet" })
        col.addView(label(13f).apply {
            alpha = 0.7f
            text = "Veja quais apps mais gastam internet e faça a limpeza."
        })

        val periods = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val lp = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        periods.addView(btn("Hoje") { days = 0; scan() }, lp)
        periods.addView(btn("7 dias") { days = 7; scan() }, lp)
        periods.addView(btn("30 dias") { days = 30; scan() }, lp)
        col.addView(periods)

        col.addView(btn("🧹 Fazer limpeza") { cleanup() })

        body = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        col.addView(body)

        col.addView(label(12f).apply {
            alpha = 0.6f
            gravity = Gravity.CENTER
            setPadding(0, pad, 0, 0)
            text = "Desenvolvido por Edivaldo Nascimento · Iahope-Technology"
        })

        setContentView(ScrollView(this).apply { addView(col) })
    }

    override fun onResume() {
        super.onResume()
        scan()  // volta da tela de permissão já com a varredura feita
    }

    // ---------- Permissão "Acesso ao uso" ----------

    private fun hasUsageAccess(): Boolean {
        val ops = getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
        val mode = if (Build.VERSION.SDK_INT >= 29)
            ops.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), packageName)
        else
            @Suppress("DEPRECATION")
            ops.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), packageName)
        return mode == AppOpsManager.MODE_ALLOWED
    }

    private fun showPermissionCard() {
        body.removeAllViews()
        body.addView(label(16f, true).apply { text = "Falta uma permissão" })
        body.addView(label(14f).apply {
            text = "Para ver o consumo de cada app, o Android pede que você libere o " +
                "\"Acesso ao uso\" para o Bloqueador. Na próxima tela, toque em " +
                "Bloqueador de Anúncios e ative a opção."
        })
        body.addView(btn("Permitir acesso ao uso") {
            try {
                startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
            } catch (e: Exception) {
                Toast.makeText(this, "Abra Configurações > Apps > Acesso especial > Acesso ao uso", Toast.LENGTH_LONG).show()
            }
        })
        addDomainsSection()
    }

    // ---------- Varredura ----------

    private fun periodStart(): Long {
        val c = Calendar.getInstance()
        if (days == 0) {
            c.set(Calendar.HOUR_OF_DAY, 0); c.set(Calendar.MINUTE, 0)
            c.set(Calendar.SECOND, 0); c.set(Calendar.MILLISECOND, 0)
        } else {
            c.add(Calendar.DAY_OF_YEAR, -days)
        }
        return c.timeInMillis
    }

    private fun periodName(): String = when (days) {
        0 -> "hoje"
        else -> "nos últimos $days dias"
    }

    private fun scan() {
        if (!hasUsageAccess()) {
            showPermissionCard()
            return
        }
        body.removeAllViews()
        body.addView(label(14f).apply { text = "Fazendo a varredura…" })
        val start = periodStart()
        val end = System.currentTimeMillis() + 60_000
        Thread {
            val result = try { collect(start, end) } catch (e: Exception) { null }
            runOnUiThread {
                if (isFinishing) return@runOnUiThread
                if (result == null) {
                    body.removeAllViews()
                    body.addView(label(14f).apply { text = "Não foi possível ler o consumo neste celular." })
                    addDomainsSection()
                } else {
                    lastResult = result
                    showResult(result)
                }
            }
        }.start()
    }

    private fun collect(start: Long, end: Long): List<AppUse> {
        val nsm = getSystemService(Context.NETWORK_STATS_SERVICE) as NetworkStatsManager
        val map = HashMap<Int, AppUse>()
        val types = listOf(ConnectivityManager.TYPE_WIFI, ConnectivityManager.TYPE_MOBILE)
        for (type in types) {
            val stats: NetworkStats = try {
                @Suppress("DEPRECATION")
                nsm.querySummary(type, null, start, end)
            } catch (e: Exception) {
                continue  // ex.: dados móveis sem permissão em Android antigo
            }
            val b = NetworkStats.Bucket()
            while (stats.hasNextBucket()) {
                stats.getNextBucket(b)
                val bytes = b.rxBytes + b.txBytes
                if (bytes <= 0) continue
                val use = map.getOrPut(b.uid) { describe(b.uid) }
                if (type == ConnectivityManager.TYPE_WIFI) use.wifi += bytes else use.mobile += bytes
                if (b.state != NetworkStats.Bucket.STATE_FOREGROUND) use.background += bytes
            }
            stats.close()
        }
        return map.values.filter { it.total > 0 }.sortedByDescending { it.total }
    }

    private fun describe(uid: Int): AppUse {
        when (uid) {
            NetworkStats.Bucket.UID_REMOVED -> return AppUse(uid, null, "Apps já desinstalados")
            NetworkStats.Bucket.UID_TETHERING -> return AppUse(uid, null, "Roteador / hotspot do celular")
            0 -> return AppUse(uid, null, "Sistema (root)")
            Process.SYSTEM_UID -> return AppUse(uid, null, "Sistema Android")
        }
        val pm = packageManager
        val pkgs = try { pm.getPackagesForUid(uid) } catch (e: Exception) { null }
        if (pkgs.isNullOrEmpty()) return AppUse(uid, null, "App do sistema (uid $uid)")
        val pkg = pkgs.first()
        val label = try {
            pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
        } catch (e: Exception) { pkg }
        val name = if (pkgs.size > 1) "$label (+${pkgs.size - 1})" else label
        return AppUse(uid, pkg, name)
    }

    private fun fmt(b: Long): String = Formatter.formatShortFileSize(this, b)

    private fun showResult(list: List<AppUse>) {
        body.removeAllViews()
        val wifi = list.sumOf { it.wifi }
        val mobile = list.sumOf { it.mobile }
        val bg = list.sumOf { it.background }
        body.addView(label(17f, true).apply { text = "Total ${periodName()}: ${fmt(wifi + mobile)}" })
        body.addView(label(14f).apply {
            text = "Wi-Fi: ${fmt(wifi)}  ·  Dados móveis: ${fmt(mobile)}\n" +
                "Em segundo plano: ${fmt(bg)}"
        })

        if (list.isEmpty()) {
            body.addView(label(14f).apply { text = "Nenhum consumo registrado ${periodName()}." })
        } else {
            body.addView(label(15f, true).apply {
                setPadding(0, pad, 0, 0)
                text = "Apps que mais consomem (toque para agir)"
            })
            val top = list.first().total.coerceAtLeast(1)
            for (u in list.take(40)) body.addView(appRow(u, top))
        }
        addDomainsSection()
    }

    private fun appRow(u: AppUse, top: Long): View {
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, pad / 2, 0, pad / 2)
            isClickable = true
            setOnClickListener { appActions(u) }
        }
        val heavyBg = u.background > 50L * 1024 * 1024 && u.bgPercent >= 50
        box.addView(label(15f, true).apply {
            setPadding(0, 0, 0, 0)
            text = (if (heavyBg) "⚠ " else "") + "${u.name} — ${fmt(u.total)}"
        })
        box.addView(ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            max = 1000
            progress = (u.total * 1000 / top).toInt()
        })
        box.addView(label(12f).apply {
            setPadding(0, 0, 0, 0)
            alpha = 0.75f
            text = "Wi-Fi ${fmt(u.wifi)} · Móvel ${fmt(u.mobile)} · Segundo plano ${u.bgPercent}%"
            if (heavyBg) setTextColor(Color.rgb(200, 110, 0))
        })
        return box
    }

    // ---------- Ações sobre um app ----------

    private fun appActions(u: AppUse) {
        val pkg = u.pkg
        if (pkg == null) {
            Toast.makeText(this, "Este item é do sistema e não pode ser alterado.", Toast.LENGTH_SHORT).show()
            return
        }
        val opts = arrayOf(
            "Restringir dados em segundo plano",
            "Limpar cache / forçar parada",
            "Desinstalar"
        )
        AlertDialog.Builder(this)
            .setTitle("${u.name} — ${fmt(u.total)}")
            .setItems(opts) { _, which ->
                when (which) {
                    0 -> openAppSettings(pkg,
                        "Toque em \"Dados móveis e Wi-Fi\" (ou \"Uso de dados\") e desative \"Dados em segundo plano\".")
                    1 -> openAppSettings(pkg,
                        "Toque em \"Armazenamento e cache\" > \"Limpar cache\", ou em \"Forçar parada\".")
                    2 -> try {
                        startActivity(Intent(Intent.ACTION_DELETE, Uri.parse("package:$pkg")))
                    } catch (e: Exception) {
                        openAppSettings(pkg, "Toque em \"Desinstalar\".")
                    }
                }
            }
            .setNegativeButton("Fechar", null)
            .show()
    }

    private fun openAppSettings(pkg: String, hint: String) {
        Toast.makeText(this, hint, Toast.LENGTH_LONG).show()
        try {
            startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$pkg")))
        } catch (e: Exception) {
            Toast.makeText(this, "Não foi possível abrir as configurações do app.", Toast.LENGTH_SHORT).show()
        }
    }

    // ---------- Limpeza ----------

    private fun cleanup() {
        val suspects = lastResult.filter { it.pkg != null && it.background > 10L * 1024 * 1024 && it.bgPercent >= 40 }
            .sortedByDescending { it.background }
            .take(8)
        val removed = AdVpnService.instance?.clearDnsCache() ?: 0

        val msg = StringBuilder()
        msg.append(if (AdVpnService.running)
            "✔ Cache de DNS do Bloqueador limpo ($removed respostas).\n\n"
        else
            "✔ Proteção desligada: não havia cache de DNS para limpar.\n\n")

        if (!hasUsageAccess()) {
            msg.append("Libere o \"Acesso ao uso\" para eu apontar os apps que gastam internet escondido.")
        } else if (suspects.isEmpty()) {
            msg.append("Nenhum app está gastando muita internet em segundo plano ${periodName()}. Tudo certo!")
        } else {
            msg.append("Estes apps gastam internet mesmo sem você usar (segundo plano). " +
                "Toque em \"Ver apps\" e restrinja os dados em segundo plano de cada um:\n\n")
            for (s in suspects) msg.append("• ${s.name}: ${fmt(s.background)} em segundo plano\n")
        }

        val d = AlertDialog.Builder(this)
            .setTitle("Limpeza")
            .setMessage(msg.toString())
            .setNegativeButton("Fechar", null)
        if (suspects.isNotEmpty()) {
            d.setPositiveButton("Ver apps") { _, _ -> pickSuspect(suspects) }
        }
        d.setNeutralButton("Economia de dados") { _, _ -> openDataSaver() }
        d.show()
    }

    private fun pickSuspect(list: List<AppUse>) {
        AlertDialog.Builder(this)
            .setTitle("Restringir segundo plano")
            .setItems(list.map { "${it.name} (${fmt(it.background)})" }.toTypedArray()) { _, i ->
                val p = list[i].pkg ?: return@setItems
                openAppSettings(p,
                    "Toque em \"Dados móveis e Wi-Fi\" (ou \"Uso de dados\") e desative \"Dados em segundo plano\".")
            }
            .setNegativeButton("Fechar", null)
            .show()
    }

    private fun openDataSaver() {
        Toast.makeText(this, "Ative a \"Economia de dados\" para limitar todos os apps em segundo plano.", Toast.LENGTH_LONG).show()
        val tries = listOf(
            Intent("android.settings.DATA_SAVER_SETTINGS"),
            Intent(Settings.ACTION_DATA_USAGE_SETTINGS),
            Intent(Settings.ACTION_WIRELESS_SETTINGS)
        )
        for (i in tries) {
            try { startActivity(i); return } catch (e: Exception) {}
        }
    }

    // ---------- Domínios mais acessados ----------

    private fun addDomainsSection() {
        body.addView(label(15f, true).apply {
            setPadding(0, pad, 0, 0)
            text = "Domínios mais acessados (toque para bloquear)"
        })
        val top = AdVpnService.topDomains(30)
        if (top.isEmpty()) {
            body.addView(label(13f).apply {
                alpha = 0.7f
                text = if (AdVpnService.running)
                    "Ainda sem dados. Use o celular um pouco e volte aqui."
                else
                    "Ative a proteção para ver quais sites os apps mais acessam."
            })
            return
        }
        body.addView(label(12f).apply {
            alpha = 0.6f
            text = "Contagem desde que a proteção foi ligada."
        })
        for ((domain, count) in top) {
            body.addView(label(14f).apply {
                text = "$domain — $count acessos"
                setPadding(0, pad / 3, 0, pad / 3)
                setOnClickListener { confirmBlock(domain) }
            })
        }
    }

    private fun confirmBlock(domain: String) {
        AlertDialog.Builder(this)
            .setTitle("Bloquear $domain?")
            .setMessage("Esse domínio e seus subdomínios serão bloqueados em todos os apps. " +
                "Se algum app parar de funcionar, libere em \"Últimos bloqueados\".")
            .setPositiveButton("Bloquear") { _, _ ->
                Blocklist.setCustom(applicationContext, domain, true)
                AdVpnService.instance?.clearDnsCache()
                Toast.makeText(this, "$domain bloqueado.", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }

    // ---------- Helpers de interface ----------

    private fun label(size: Float, bold: Boolean = false): TextView = TextView(this).apply {
        textSize = size
        if (bold) setTypeface(typeface, Typeface.BOLD)
        setPadding(0, pad / 4, 0, pad / 4)
    }

    private fun btn(t: String, action: () -> Unit): Button = Button(this).apply {
        text = t
        setOnClickListener { action() }
    }
}
