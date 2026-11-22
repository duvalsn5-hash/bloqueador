package com.exemplo.bloqueador

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.Gravity
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : Activity() {

    private lateinit var status: TextView
    private lateinit var counter: TextView
    private lateinit var info: TextView
    private lateinit var toggle: Button
    private lateinit var input: EditText

    private val handler = Handler(Looper.getMainLooper())
    private val tick = object : Runnable {
        override fun run() {
            refresh()
            handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AdVpnService.loadCounters(applicationContext)
        val pad = (20 * resources.displayMetrics.density).toInt()

        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }

        fun label(size: Float, bold: Boolean = false): TextView = TextView(this).apply {
            textSize = size
            if (bold) setTypeface(typeface, Typeface.BOLD)
            setPadding(0, pad / 3, 0, pad / 3)
        }

        fun btn(t: String, action: () -> Unit): Button = Button(this).apply {
            text = t
            setOnClickListener { action() }
        }

        fun sw(t: String, checked: Boolean, action: (Boolean) -> Unit): Switch = Switch(this).apply {
            text = t
            isChecked = checked
            setPadding(0, pad / 3, 0, pad / 3)
            setOnCheckedChangeListener { _, v -> action(v) }
        }

        col.addView(label(24f, true).apply { text = "Bloqueador de Anúncios" })
        status = label(18f, true)
        col.addView(status)
        counter = label(14f)
        col.addView(counter)

        toggle = btn("Ativar") { onToggle() }
        col.addView(toggle)
        col.addView(btn("Atualizar listas agora") { updateLists() })
        col.addView(btn("Últimos bloqueados (liberar)") { showRecent() })
        col.addView(btn("Apps sem bloqueio") { showApps() })
        col.addView(btn("📊 Consumo de internet e limpeza") {
            startActivity(Intent(this, ConsumoActivity::class.java))
        })

        col.addView(sw("Bloquear sites perigosos (malware e phishing)", Prefs.threats(this)) { v ->
            Prefs.setThreats(this, v)
            Blocklist.threatsEnabled = v
        })
        col.addView(sw("Iniciar ao ligar o celular", Prefs.autostart(this)) { v ->
            Prefs.setAutostart(this, v)
        })
        col.addView(sw("Atualizar listas toda semana", Prefs.weekly(this)) { v ->
            Prefs.setWeekly(this, v)
            UpdateJobService.schedule(this, v)
        })

        col.addView(label(15f, true).apply { text = "Domínio personalizado" })
        input = EditText(this).apply {
            hint = "exemplo.com"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            setSingleLine()
        }
        col.addView(input)

        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val lp = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        row.addView(btn("Bloquear") { applyCustom(true) }, lp)
        row.addView(btn("Liberar") { applyCustom(false) }, lp)
        col.addView(row)

        info = label(14f).apply { alpha = 0.75f }
        col.addView(info)

        col.addView(label(13f).apply {
            alpha = 0.6f
            text = "Importante: no Chrome, desative \"Usar DNS seguro\" " +
                "(Configurações > Privacidade e segurança), senão ele ignora o bloqueio. " +
                "Em Configurações do Android > DNS privado, deixe em Automático ou Desativado."
        })

        col.addView(label(13f).apply {
            alpha = 0.7f
            gravity = Gravity.CENTER
            setPadding(0, pad, 0, 0)
            text = "Desenvolvido por Edivaldo Nascimento\n· Iahope-Technology ·\n" +
                "Versão ${BuildConfig.VERSION_NAME}  ·  © 2026 Iahope-Technology"
        })

        setContentView(ScrollView(this).apply { addView(col) })

        Thread { Blocklist.loadAll(applicationContext) }.start()
        UpdateJobService.schedule(this, Prefs.weekly(this))
        askNotifications()
    }

    private fun askNotifications() {
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 2)
        }
    }

    private fun onToggle() {
        if (AdVpnService.running) {
            startService(Intent(this, AdVpnService::class.java).setAction(AdVpnService.ACTION_STOP))
        } else {
            val i = VpnService.prepare(this)
            if (i != null) startActivityForResult(i, 1) else startVpn()
        }
    }

    private fun startVpn() {
        startService(Intent(this, AdVpnService::class.java).setAction(AdVpnService.ACTION_START))
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1 && resultCode == RESULT_OK) startVpn()
    }

    private fun updateLists() {
        info.text = "Iniciando…"
        Thread {
            Blocklist.update(applicationContext) { m -> runOnUiThread { info.text = m } }
        }.start()
    }

    private fun applyCustom(block: Boolean) {
        val d = Blocklist.normalize(input.text.toString())
        if (d == null) {
            Toast.makeText(this, "Domínio inválido", Toast.LENGTH_SHORT).show()
            return
        }
        Blocklist.setCustom(applicationContext, d, block)
        info.text = if (block) "$d (e subdomínios) será bloqueado." else "$d (e subdomínios) foi liberado."
        input.text.clear()
    }

    private fun showRecent() {
        val list = AdVpnService.recentSnapshot()
        if (list.isEmpty()) {
            Toast.makeText(this, "Nenhum domínio bloqueado ainda", Toast.LENGTH_SHORT).show()
            return
        }
        val arr = list.map { if (it.threat) "⚠ " + it.domain else it.domain }.toTypedArray()
        AlertDialog.Builder(this)
            .setTitle("Últimos bloqueados (⚠ = ameaça). Toque para liberar")
            .setItems(arr) { _, which -> confirmRelease(list[which].domain) }
            .setNegativeButton("Fechar", null)
            .show()
    }

    private fun confirmRelease(domain: String) {
        AlertDialog.Builder(this)
            .setTitle("Liberar $domain?")
            .setMessage("Esse domínio e seus subdomínios deixarão de ser bloqueados.")
            .setPositiveButton("Liberar") { _, _ ->
                Blocklist.setCustom(applicationContext, domain, false)
                info.text = "$domain liberado."
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }

    private fun showApps() {
        val pm = packageManager
        val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val apps = pm.queryIntentActivities(launcher, 0)
            .map { it.activityInfo.packageName to it.loadLabel(pm).toString() }
            .filter { it.first != packageName }
            .distinctBy { it.first }
            .sortedBy { it.second.lowercase() }
        val selected = HashSet(Prefs.excluded(this))
        val names = apps.map { it.second }.toTypedArray()
        val checked = BooleanArray(apps.size) { selected.contains(apps[it].first) }
        AlertDialog.Builder(this)
            .setTitle("Apps sem bloqueio")
            .setMultiChoiceItems(names, checked) { _, i, isChecked ->
                if (isChecked) selected.add(apps[i].first) else selected.remove(apps[i].first)
            }
            .setPositiveButton("Salvar") { _, _ ->
                Prefs.setExcluded(this, selected)
                if (AdVpnService.running) {
                    startService(Intent(this, AdVpnService::class.java).setAction(AdVpnService.ACTION_RESTART))
                    Toast.makeText(this, "Salvo e aplicado.", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this, "Salvo. Vale quando a proteção for ativada.", Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }

    private fun refresh() {
        if (AdVpnService.running) {
            status.text = "● Proteção ATIVA"
            status.setTextColor(Color.rgb(46, 160, 67))
            toggle.text = "Desativar"
        } else {
            status.text = "○ Proteção desativada"
            status.setTextColor(Color.rgb(220, 70, 70))
            toggle.text = "Ativar"
        }
        val last = Blocklist.lastUpdate(this)
        val lastTxt = if (last > 0)
            SimpleDateFormat("dd/MM/yyyy HH:mm", Locale("pt", "BR")).format(Date(last))
        else "nunca (lista básica)"
        counter.text = "Anúncios bloqueados: ${AdVpnService.blockedCount.get()}  ·  " +
            "Ameaças: ${AdVpnService.threatCount.get()}\n" +
            "Permitidos: ${AdVpnService.allowedCount.get()}  ·  Do cache: ${AdVpnService.cacheHits.get()}\n" +
            "Na lista: ${Blocklist.adsCount} anúncios e ${Blocklist.threatCount} ameaças\n" +
            "Listas atualizadas: $lastTxt"
    }

    override fun onResume() {
        super.onResume()
        handler.post(tick)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(tick)
    }
}
