package com.exemplo.bloqueador

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context

class UpdateJobService : JobService() {

    override fun onStartJob(params: JobParameters): Boolean {
        Thread {
            try { Blocklist.update(applicationContext) { } } catch (e: Exception) {}
            jobFinished(params, false)
        }.start()
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean = true

    companion object {
        private const val JOB_ID = 77

        fun schedule(ctx: Context, enabled: Boolean) {
            val js = ctx.getSystemService(Context.JOB_SCHEDULER_SERVICE) as JobScheduler
            if (!enabled) {
                js.cancel(JOB_ID)
                return
            }
            if (js.allPendingJobs.any { it.id == JOB_ID }) return
            val info = JobInfo.Builder(JOB_ID, ComponentName(ctx, UpdateJobService::class.java))
                .setPeriodic(7L * 24 * 60 * 60 * 1000)
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_UNMETERED)
                .setPersisted(true)
                .build()
            js.schedule(info)
        }
    }
}
