package dev.busung.s25uroot

import android.app.Application
import android.os.SystemClock
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

enum class InstallPhase {
    Checking,
    Ready,
    Downloading,
    Exploiting,
    LoadingKernelSu,
    Installed,
    Failed,
}

data class InstallUiState(
    val phase: InstallPhase = InstallPhase.Checking,
    val message: String = "",
    val probeOutput: String = "",
    val log: String = "",
) {
    val busy: Boolean
        get() = phase in setOf(
            InstallPhase.Checking,
            InstallPhase.Downloading,
            InstallPhase.Exploiting,
            InstallPhase.LoadingKernelSu,
        )

}

data class TargetCatalogUiState(
    val loading: Boolean = false,
    val profiles: List<TargetProfile> = emptyList(),
    val error: String? = null,
)

private data class CommandResult(val code: Int, val output: String)

/**
 * Payloads are truncated to a fixed release size, so a rebuild of a target --
 * or a different target padded to the same size -- has exactly the length of
 * whatever is already staged, and would keep running in its place.
 */
internal fun stagedFileIsCurrent(staged: File, source: File): Boolean {
    if (!staged.exists()) return false
    val stagedDigest = sha256OrNull(staged) ?: return false
    return stagedDigest == sha256OrNull(source)
}

private fun sha256OrNull(file: File): String? = runCatching {
    file.inputStream().use { input ->
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(8192)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            digest.update(buffer, 0, count)
        }
        digest.digest().joinToString("") { "%02x".format(it) }
    }
}.getOrNull()

class InstallViewModel(application: Application) : AndroidViewModel(application) {
    private val app = application
    private val repository = PayloadRepository(application)
    private val historyStore = InstallHistoryStore(application)
    private val mutableState = MutableStateFlow(InstallUiState())
    private val mutableHistory = MutableStateFlow(historyStore.closeInterruptedRuns())
    private val mutableTargetCatalog = MutableStateFlow(TargetCatalogUiState())
    private var discoveryJob: Job? = null
    private var installJob: Job? = null
    private var activeHistoryEntry: InstallHistoryEntry? = null

    @Volatile
    private var activeRunShizuku: Boolean? = null
    val state: StateFlow<InstallUiState> = mutableState.asStateFlow()
    val history: StateFlow<List<InstallHistoryEntry>> = mutableHistory.asStateFlow()
    val targetCatalog: StateFlow<TargetCatalogUiState> = mutableTargetCatalog.asStateFlow()

    init {
        refresh()
    }

    fun refresh() {
        if (installJob?.isActive == true) return
        mutableHistory.value = historyStore.load()
        discoveryJob?.cancel()
        discoveryJob = viewModelScope.launch(Dispatchers.IO) {
            val probe = NativeProbe.run()
            if (detectInstalled()) {
                mutableState.value = InstallUiState(
                    phase = InstallPhase.Installed,
                    message = app.getString(R.string.status_ksu_active),
                    probeOutput = probe,
                    log = probe,
                )
                return@launch
            }
            try {
                val profile = repository.resolveTarget(DeviceSnapshot.current())
                mutableState.value = InstallUiState(
                    phase = InstallPhase.Ready,
                    message = app.getString(R.string.status_not_installed),
                    probeOutput = probe,
                    log = "$probe\n${app.getString(R.string.log_profile, profile.profileId)}",
                )
            } catch (error: Throwable) {
                mutableState.value = InstallUiState(
                    phase = InstallPhase.Failed,
                    message = app.getString(R.string.status_support_failed),
                    probeOutput = probe,
                    log = "$probe\n[-] ${error.message ?: error.javaClass.simpleName}",
                )
            }
        }
    }

    fun deleteHistoryEntries(ids: Collection<String>) {
        val runningId = activeHistoryEntry?.id
        val toDelete = ids.filterNot { it == runningId }
        if (toDelete.isEmpty()) return
        toDelete.forEach(historyStore::delete)
        mutableHistory.value = mutableHistory.value.filterNot { it.id in toDelete }
    }

    fun loadTargetCatalog() {
        if (mutableTargetCatalog.value.loading) return
        viewModelScope.launch(Dispatchers.IO) {
            mutableTargetCatalog.value = TargetCatalogUiState(loading = true)
            mutableTargetCatalog.value = try {
                TargetCatalogUiState(
                    profiles = repository.loadTargets().sortedWith(
                        compareBy(
                            TargetProfile::displayName,
                            TargetProfile::profileId,
                        ),
                    ),
                )
            } catch (error: Throwable) {
                TargetCatalogUiState(error = error.message ?: error.javaClass.simpleName)
            }
        }
    }

    fun install(profileId: String? = null) {
        if (installJob?.isActive == true || mutableState.value.phase == InstallPhase.Installed) return
        discoveryJob?.cancel()
        installJob = viewModelScope.launch(Dispatchers.IO) {
            mutableState.value = InstallUiState(
                phase = InstallPhase.Checking,
                probeOutput = mutableState.value.probeOutput,
            )
            startHistory()
            // Freeze the transport for the whole run so a mid-run preference
            // change cannot mix Shizuku and standalone execution between the
            // exploit and the KernelSU staging steps.
            activeRunShizuku = AppPreferences.shizukuMode(app)
            try {
                if (shizukuEnabled()) {
                    appendLog(app.getString(R.string.log_shizuku_prepare))
                    if (!ShizukuController.isRunning() && !ShizukuController.pingUntilRunning()) {
                        error(app.getString(R.string.error_shizuku_unavailable))
                    }
                    if (!ShizukuController.isGranted() && !ShizukuController.requestPermission()) {
                        error(app.getString(R.string.error_shizuku_permission))
                    }
                    appendLog(app.getString(R.string.log_shizuku_permission))
                }
                setPhase(InstallPhase.Checking, app.getString(R.string.status_checking_github))
                val profile = if (profileId == null) {
                    repository.resolveTarget(DeviceSnapshot.current())
                } else {
                    repository.resolveTarget(profileId)
                }
                appendLog(app.getString(R.string.log_profile, profile.profileId))
                updateHistoryProfile(profile.profileId)

                setPhase(InstallPhase.Downloading, app.getString(R.string.status_downloading_payload))
                val payloads = repository.download(profile) { appendLog("[*] $it") }
                appendLog(app.getString(R.string.log_download_verified))

                if (profile.requiresShellContext) {
                    // Tracefs-class exploits leak kernel memory through
                    // tracefs, which SELinux only exposes to u:r:shell:s0.
                    // Bootstrap wireless ADB; the session itself switches
                    // adbd to stable TCP 5555 and shuts wireless debugging
                    // down right after, so the whole choreography rides
                    // loopback and survives Wi-Fi band switches.
                    appendLog(app.getString(R.string.log_adb_connecting))
                    WirelessAdbSession.open(app).use { adb ->
                        appendLog(
                            if (adb.viaTcp5555) TRANSPORT_STABLE_5555
                            else TRANSPORT_WIRELESS_DEBUGGING,
                        )
                        setPhase(InstallPhase.Exploiting, app.getString(R.string.status_exploit_running))
                        executeExploitOverAdb(adb, payloads)

                        setPhase(InstallPhase.LoadingKernelSu, app.getString(R.string.status_ksu_loading))
                        loadKernelSuOverAdb(adb, payloads)
                    }
                } else {
                    // App-context route: the exploit runs directly from the
                    // app process, no ADB involved at any point.
                    setPhase(InstallPhase.Exploiting, app.getString(R.string.status_exploit_running))
                    executeExploit(payloads.exploit)

                    setPhase(InstallPhase.LoadingKernelSu, app.getString(R.string.status_ksu_loading))
                    installKernelSu(payloads)
                }

                setPhase(InstallPhase.Installed, app.getString(R.string.status_ksu_active))
                appendLog(app.getString(R.string.log_install_complete))
                finishHistory(InstallRunResult.Succeeded)
            } catch (error: Throwable) {
                appendLog("[-] ${error.message ?: error.javaClass.simpleName}")
                setPhase(InstallPhase.Failed, app.getString(R.string.status_install_failed))
                finishHistory(InstallRunResult.Failed)
            } finally {
                activeRunShizuku = null
            }
        }
    }

    private suspend fun executeExploit(payload: File) {
        val shizuku = shizukuEnabled()
        val logFile = if (shizuku) File(SHIZUKU_LOG_PATH) else File(app.filesDir, "exploit.log")
        if (shizuku) {
            ShizukuController.exec(arrayOf("rm", "-f", SHIZUKU_LOG_PATH)).waitFor()
        } else {
            logFile.delete()
        }
        val helper = helperFile()
        if (!shizuku) {
            require(helper.canExecute()) { app.getString(R.string.error_helper_unavailable) }
        }
        val logPrefix = mutableState.value.log
        val bootToken = currentBootToken()
        val process = if (shizuku) {
            val stagedPayload = shizukuStage(payload, SHIZUKU_PAYLOAD_PATH, "755")
            ShizukuController.exec(
                arrayOf("/system/bin/sh", "-c", "true"),
                shizukuEnvironment(bootToken, stagedPayload.absolutePath, helper.absolutePath),
            )
        } else {
            val processBuilder = ProcessBuilder(
                helper.absolutePath,
                "--run-payload",
                payload.absolutePath,
                helper.absolutePath,
                logFile.absolutePath,
            ).redirectErrorStream(true)
            processBuilder.environment().apply {
                put("EXPLOIT_ATTEMPTS", EXPLOIT_ATTEMPTS)
                put("P0_ATTEMPT_TIMEOUT_SEC", P0_ATTEMPT_TIMEOUT_SEC)
                put("EXPLOIT_ATTEMPT_TIMEOUT_SEC", EXPLOIT_ATTEMPT_TIMEOUT_SEC)
                cachedP0Offset(bootToken)?.let { put(P0_OFFSET_ENV, it) }
            }
            processBuilder.start()
        }
        val captured = StringBuilder()
        val readLog: () -> String = if (shizuku) {
            { drainProcessOutput(process, captured) }
        } else {
            // Keep draining stdout while polling: if the helper fills the OS
            // pipe buffer it blocks on write and stops making log progress,
            // which would trip the stall detector spuriously.
            { drainProcessOutput(process, captured); logFile.readTextIfPresent() }
        }

        try {
            val startedAt = SystemClock.elapsedRealtime()
            var lastProgressAt = startedAt
            var lastRawLog = ""
            while (process.isAlive) {
                val rawLog = readLog()
                if (rawLog != lastRawLog) {
                    cacheP0Offset(bootToken, rawLog)
                    publishExploitLog(logPrefix, rawLog)
                    lastRawLog = rawLog
                    lastProgressAt = SystemClock.elapsedRealtime()
                }
                val now = SystemClock.elapsedRealtime()
                require(now - lastProgressAt < EXPLOIT_STALL_MILLIS) {
                    app.getString(R.string.error_exploit_stalled)
                }
                require(now - startedAt < EXPLOIT_TOTAL_MILLIS) {
                    app.getString(R.string.error_exploit_timeout)
                }
                delay(if (shizuku) SHIZUKU_LOG_POLL_INTERVAL else LOG_POLL_INTERVAL)
            }

            val exitCode = process.waitFor()
            val rawLog = readLog()
            cacheP0Offset(bootToken, rawLog)
            publishExploitLog(logPrefix, rawLog)
            // Both transports drain into `captured` during the poll loop, so
            // this never blocks on a child still holding the pipe open.
            val earlyOutput = captured.toString().trim()
            require(exitCode == 0) {
                app.getString(
                    R.string.error_payload_exit,
                    exitCode,
                    earlyOutput.takeIf(String::isNotBlank)?.let { " ($it)" } ?: "",
                )
            }
            require(rawLog.contains("exploit completed") && rawLog.contains("done=1 root=1")) {
                app.getString(R.string.error_success_marker)
            }
        } finally {
            if (process.isAlive) {
                process.destroy()
                delay(500.milliseconds)
                if (process.isAlive) process.destroyForcibly()
            }
        }
        appendLog(app.getString(R.string.log_bootstrap_root))
    }

    private fun drainProcessOutput(process: Process, buffer: StringBuilder): String {
        return try {
            drainStream(process.inputStream, buffer)
            drainStream(process.errorStream, buffer)
            buffer.toString()
        } catch (_: Throwable) {
            buffer.toString()
        }
    }

    private fun drainStream(stream: InputStream, buffer: StringBuilder) {
        val data = ByteArray(4096)
        while (stream.available() > 0) {
            val count = stream.read(data)
            if (count <= 0) break
            buffer.append(String(data, 0, count, Charsets.UTF_8))
        }
    }

    private fun publishExploitLog(prefix: String, rawLog: String) {
        mutableState.value = mutableState.value.copy(
            log = listOf(prefix, stripAnsi(rawLog))
                .filter(String::isNotBlank)
                .joinToString("\n"),
        )
        updateHistoryLog()
    }

    private suspend fun installKernelSu(payloads: VerifiedPayloads) {
        if (shizukuEnabled()) {
            shizukuStage(payloads.kernelSu, SHIZUKU_KSUD_PATH, "755")
            shizukuStage(payloads.kernelSu, SHIZUKU_KSUD_STAGE_PATH, "755")
            appendLog(app.getString(R.string.log_ksu_staged))
        } else {
            val source = shellQuote(payloads.kernelSu.absolutePath)
            val stageCommand =
                "/system/bin/cp $source $SHIZUKU_KSUD_PATH && " +
                    "/system/bin/cp $source $SHIZUKU_KSUD_STAGE_PATH && " +
                    "/system/bin/chmod 755 $SHIZUKU_KSUD_PATH $SHIZUKU_KSUD_STAGE_PATH"
            val stage = runHelper("-c", stageCommand)
            require(stage.code == 0) { app.getString(R.string.error_ksu_stage, stage.output) }
            appendLog(app.getString(R.string.log_ksu_staged))
        }

        val lateLoad = runHelper("--late-load")
        require(lateLoad.code == 0) {
            app.getString(R.string.error_ksu_verify, lateLoad.code, lateLoad.output)
        }
        if (lateLoad.output.isNotBlank()) appendLog(lateLoad.output)
        storeInstallReceipt()
        appendLog(app.getString(R.string.log_ksu_control_verified))
    }

    // ---------------------------------------------------------------------
    // Shell-context route (tracefs-class targets). The whole choreography
    // runs over one WirelessAdbSession that is already riding stable TCP
    // 5555 when we get here.
    // ---------------------------------------------------------------------

    /** Stages and streams the exploit over the ADB session (shell uid). */
    private suspend fun executeExploitOverAdb(adb: WirelessAdbSession, payloads: VerifiedPayloads) {
        val profile = payloads.profile
        val bootToken = currentBootToken()
        val logPrefix = mutableState.value.log

        adb.remove(SHIZUKU_LOG_PATH)
        adb.push(payloads.exploit, SHIZUKU_PAYLOAD_PATH, executable = true)
        val helper = repository.extractRootHelper(profile) ?: nativeHelperFile()
        adb.push(helper, SHIZUKU_HELPER_PATH, executable = true)
        appendLog(app.getString(R.string.log_adb_staged))

        val env = buildList {
            add("EXPLOIT_ATTEMPTS=$EXPLOIT_ATTEMPTS")
            add("RMG_MANAGER_PACKAGE=${BuildConfig.APPLICATION_ID}")
            add("P0_ATTEMPT_TIMEOUT_SEC=$P0_ATTEMPT_TIMEOUT_SEC")
            add("EXPLOIT_ATTEMPT_TIMEOUT_SEC=$EXPLOIT_ATTEMPT_TIMEOUT_SEC")
            profile.slideSource?.let { add("SLIDE_SOURCE=$it") }
            cachedP0Offset(bootToken)?.let { add("$P0_OFFSET_ENV=$it") }
        }.joinToString(" ")

        // Foreground of an open shell: adbd kills a backgrounded process
        // the moment its shell stream closes. The helper forks the payload
        // into its own session and streams a live log to stdout, so reading
        // its stream directly yields real-time progress.
        var streamed = ""
        val command = "$env ${SHIZUKU_HELPER_PATH} --run-payload " +
            "${SHIZUKU_PAYLOAD_PATH} ${SHIZUKU_HELPER_PATH} $SHIZUKU_LOG_PATH"
        adb.runStreaming(command) { accumulated ->
            if (accumulated != streamed) {
                streamed = accumulated
                cacheP0Offset(bootToken, accumulated)
                publishExploitLog(logPrefix, accumulated)
            }
        }

        val rawLog = streamed.ifBlank { adb.readLog(SHIZUKU_LOG_PATH) }
        cacheP0Offset(bootToken, rawLog)
        publishExploitLog(logPrefix, rawLog)
        require(rawLog.contains("exploit completed")) {
            app.getString(R.string.error_success_marker)
        }
        appendLog(app.getString(R.string.log_bootstrap_root))
    }

    /** Stages ksud, verifies KernelSU is live, late-loads if it is not. */
    private fun loadKernelSuOverAdb(adb: WirelessAdbSession, payloads: VerifiedPayloads) {
        adb.push(payloads.kernelSu, SHIZUKU_KSUD_PATH, executable = true)
        adb.push(payloads.kernelSu, SHIZUKU_KSUD_STAGE_PATH, executable = true)
        appendLog(app.getString(R.string.log_ksu_staged))

        val loaded = adb.shell("grep -i kernelsu /proc/modules 2>/dev/null")
        if (!loaded.output.contains("kernelsu")) {
            val lateLoad = adb.shell("${SHIZUKU_HELPER_PATH} --late-load")
            require(lateLoad.exitCode == 0) {
                app.getString(R.string.error_ksu_verify, lateLoad.exitCode, lateLoad.output)
            }
            if (lateLoad.output.isNotBlank()) appendLog(lateLoad.output)
        } else {
            appendLog("[+] KernelSU already loaded (supervisor auto-triggered)")
        }
        storeInstallReceipt()
        appendLog(app.getString(R.string.log_ksu_control_verified))
        AdbKeyManager(app) // ensure key material exists for root-on-boot
    }

    // ---------------------------------------------------------------------
    // Module activation through the app's OWN KernelSU su grant — never a
    // com.android.shell grant, never wireless ADB.
    // ---------------------------------------------------------------------

    /**
     * Mounts KernelSU modules and restarts zygote so Zygisk-based modules
     * (LSPosed, ...) inject into fresh processes. Causes a short soft
     * reboot: lockscreen reappears; kernel, root and modules persist.
     */
    fun applyModules() {
        runModulePipeline()
    }

    /** Manual trigger from the start screen: mount + soft-reboot via ksud. */
    fun softReboot() {
        runModulePipeline()
    }

    private fun runModulePipeline() {
        if (installJob?.isActive == true) return
        viewModelScope.launch(Dispatchers.IO) {
            val ownedEntry = activeHistoryEntry == null
            if (ownedEntry) startHistory() // module runs must leave a trace
            var succeeded = false
            try {
                appendLog(app.getString(R.string.log_modules_applying))
                succeeded = applyModulesViaSu()
            } catch (error: Throwable) {
                appendLog("[-] ${error.message ?: error.javaClass.simpleName}")
            } finally {
                if (ownedEntry) {
                    finishHistory(if (succeeded) InstallRunResult.Succeeded else InstallRunResult.Failed)
                }
            }
        }
    }

    private data class SuResult(val exitCode: Int, val output: String)

    /**
     * Runs a command through KernelSU's su as THIS app process. Requires
     * the Root My Galaxy package to be granted root in KernelSU Manager.
     *
     * Exit codes are UNRELIABLE here: `su -c` keeps the stdout pipe open
     * via its daemon child, so a perfectly successful command often only
     * ends when the watchdog fires. Callers must therefore judge success
     * by the returned OUTPUT, never by exitCode. Null = spawn failure only.
     */
    private fun runSu(command: String, timeoutMs: Long = SU_TIMEOUT_MS): SuResult? {
        val started = System.currentTimeMillis()
        val result = runCatching {
            val process = ProcessBuilder("/system/bin/su", "-c", command)
                .redirectErrorStream(true)
                .start()
            java.util.concurrent.Executors.newSingleThreadExecutor().use { watchdog ->
                watchdog.submit {
                    Thread.sleep(timeoutMs)
                    process.destroyForcibly()
                }
                val output = process.inputStream.bufferedReader().readText()
                val exitCode = runCatching { process.exitValue() }.getOrDefault(-1)
                SuResult(exitCode, output)
            }
        }.getOrNull()
        Log.i(
            APPLY_LOG_TAG,
            "runSu('${command.take(48)}') -> " +
                (result?.let { "exit=${it.exitCode} out[${it.output.length}]=${it.output.take(60)}" } ?: "SPAWN-FAILURE"),
        )
        return result
    }

    /**
     * Full ksud lifecycle + zygote restart using the app-owned su grant.
     * Returns false when su itself is not usable.
     */
    private fun applyModulesViaSu(): Boolean {
        // First su call may block on KernelSU's interactive grant prompt;
        // give the user one beat to answer, then bail out.
        var id = runSu("id", SU_CHECK_TIMEOUT_MS)
        if (id == null || !id.output.contains("uid=0")) {
            Thread.sleep(3_000)
            id = runSu("id", SU_CHECK_TIMEOUT_MS)
        }
        if (id == null || !id.output.contains("uid=0")) {
            appendLog("[!] app-owned su unavailable - grant root to this app in KernelSU Manager and retry")
            return false
        }
        appendLog("[+] app su granted - running ksud lifecycle locally")

        // ONE detached root script chains all three ksud stages and writes
        // stage markers into the APP's own filesDir, which we then read
        // locally with zero su calls. Static script text, no shell variables.
        val applyDir = File(app.filesDir, "apply").apply { mkdirs() }
        val doneFile = File(applyDir, "done")
        val progressFile = File(applyDir, "progress")
        val ksudLogFile = File(applyDir, "ksud.log")
        doneFile.delete()
        progressFile.delete()
        val script = """
            rm -f %DONE% %PROG%
            : > %LOG%
            timeout 60 /data/adb/ksud post-fs-data >> %LOG% 2>&1 </dev/null; echo pfd >> %PROG%
            timeout 60 /data/adb/ksud services >> %LOG% 2>&1 </dev/null; echo svc >> %PROG%
            timeout 60 /data/adb/ksud boot-completed >> %LOG% 2>&1 </dev/null; echo bc >> %PROG%
            sync
            echo ALL > %DONE%
            chmod 666 %DONE% %PROG% %LOG% 2>/dev/null
            """.trimIndent()
            .replace("%DONE%", doneFile.absolutePath)
            .replace("%PROG%", progressFile.absolutePath)
            .replace("%LOG%", ksudLogFile.absolutePath)
        val fired = runSu("setsid sh -c '$script' &", STAGE_FIRE_TIMEOUT_MS)
        if (fired == null) {
            appendLog("[!] ksud lifecycle failed to start")
            return false
        }

        // Local poll of the marker files - no su involvement during wait.
        val startedAt = System.currentTimeMillis()
        while (System.currentTimeMillis() - startedAt < MODULE_WAIT_MILLIS) {
            if (doneFile.exists() && doneFile.readText().contains("ALL")) break
            Thread.sleep(500)
        }
        if (!doneFile.exists()) {
            appendLog("[!] ksud lifecycle timed out (see apply/ksud.log in app data)")
            return false
        }
        val stages = if (progressFile.exists()) progressFile.readText().trim().replace("\n", " → ") else "unknown"
        appendLog("[*] ksud lifecycle done in ${(System.currentTimeMillis() - startedAt) / 1000}s [$stages]")

        // While we hold root: whitelist this app's ADB key for every adbd
        // transport and switch adbd to stable TCP 5555. From then on the
        // app reaches adbd without wireless debugging, mDNS or rotating
        // ports. Restarting adbd drops any live wireless session, so this
        // runs over the su channel and is the LAST step before the kill.
        val keyLine = AdbKeyManager(app).adbKeyFileLine()
        val harden = runSu(
            "mkdir -p /data/misc/adb; touch /data/misc/adb/adb_keys; " +
                "grep -qF '$keyLine' /data/misc/adb/adb_keys 2>/dev/null || echo '$keyLine' >> /data/misc/adb/adb_keys; " +
                "setprop service.adb.tcp.port 5555; " +
                "(stop adbd; start adbd) >/dev/null 2>&1; " +
                "sleep 1; getprop service.adb.tcp.port",
            SU_CHECK_TIMEOUT_MS,
        )
        if (harden != null && harden.output.trim().endsWith("5555")) {
            appendLog("[+] stable adbTCP enabled - adbd on port 5555, key whitelisted")
        } else {
            appendLog("[!] stable adbTCP setup failed${harden?.let { ": getprop=${it.output.trim().takeLast(40)}" } ?: " (timeout)"}")
        }

        // Restart zygote so Zygisk modules inject. The kill takes the
        // framework (and this app) down with it: fire detached, report now.
        runSu(
            "setsid sh -c 'for p in \$(pidof zygote64) \$(pidof zygote); do kill -9 \$p 2>/dev/null; done' &",
            STAGE_FIRE_TIMEOUT_MS,
        )
        appendLog(app.getString(R.string.log_modules_zygote_restarted))
        return true
    }


    private fun detectInstalled(): Boolean {
        if (NativeProbe.isKernelSuActive()) return true
        val bootToken = currentBootToken() ?: return false
        val receipt = app.getSharedPreferences(INSTALL_RECEIPT, Application.MODE_PRIVATE)
        return receipt.getString(RECEIPT_BOOT_TOKEN, null) == bootToken &&
            receipt.getBoolean(RECEIPT_VERIFIED, false)
    }

    private fun storeInstallReceipt() {
        val bootToken = currentBootToken() ?: error(app.getString(R.string.error_boot_id))
        val stored = app.getSharedPreferences(INSTALL_RECEIPT, Application.MODE_PRIVATE)
            .edit()
            .putString(RECEIPT_BOOT_TOKEN, bootToken)
            .putBoolean(RECEIPT_VERIFIED, true)
            .commit()
        require(stored) { app.getString(R.string.error_receipt) }
    }

    private fun currentBootToken(): String? = runCatching {
        File("/proc/sys/kernel/random/boot_id")
            .readText(Charsets.US_ASCII)
            .trim()
            .takeIf(String::isNotBlank)
    }.getOrNull()

    private fun cachedP0Offset(bootToken: String?): String? {
        if (bootToken == null) return null
        val stored = app.getSharedPreferences(P0_CACHE, Application.MODE_PRIVATE)
        if (stored.getString(P0_CACHE_BOOT_TOKEN, null) != bootToken) return null
        return stored.getString(P0_CACHE_OFFSET, null)
    }

    private fun cacheP0Offset(bootToken: String?, log: String) {
        if (bootToken == null) return
        val match = P0_OFFSET_PATTERN.findAll(log).lastOrNull() ?: return
        val offset = match.groupValues[1].toLongOrNull(16) ?: return
        if (offset !in 0..P0_OFFSET_MAX || offset and P0_OFFSET_MASK != 0L) return
        val value = "0x${offset.toString(16)}"
        val stored = app.getSharedPreferences(P0_CACHE, Application.MODE_PRIVATE)
        if (stored.getString(P0_CACHE_BOOT_TOKEN, null) == bootToken &&
            stored.getString(P0_CACHE_OFFSET, null) == value
        ) return
        stored.edit()
            .putString(P0_CACHE_BOOT_TOKEN, bootToken)
            .putString(P0_CACHE_OFFSET, value)
            .apply()
    }

    private fun helperFile(): File =
        if (shizukuEnabled()) {
            shizukuStage(nativeHelperFile(), SHIZUKU_HELPER_PATH, "755")
        } else {
            nativeHelperFile()
        }

    private fun nativeHelperFile() = File(app.applicationInfo.nativeLibraryDir, "libcve43499root.so")

    private fun shizukuEnabled(): Boolean = activeRunShizuku ?: AppPreferences.shizukuMode(app)

    private fun shizukuStage(source: File, target: String, mode: String): File {
        val staged = File(target)
        if (stagedFileIsCurrent(staged, source)) return staged
        try {
            ShizukuController.writeFile(target, mode, source.inputStream())
        } catch (error: Throwable) {
            throw IllegalStateException(
                app.getString(R.string.error_shizuku_stage, target, error.message.orEmpty()),
                error,
            )
        }
        return staged
    }

    private fun shizukuEnvironment(
        bootToken: String?,
        payloadPath: String,
        helperPath: String,
    ): Array<String> = buildList {
        add("EXPLOIT_ATTEMPTS=$EXPLOIT_ATTEMPTS")
        add("P0_ATTEMPT_TIMEOUT_SEC=$P0_ATTEMPT_TIMEOUT_SEC")
        add("EXPLOIT_ATTEMPT_TIMEOUT_SEC=$EXPLOIT_ATTEMPT_TIMEOUT_SEC")
        add("CVE43499_ROOT_HELPER=$helperPath")
        add("LD_PRELOAD=$payloadPath")
        cachedP0Offset(bootToken)?.let { add("$P0_OFFSET_ENV=$it") }
    }.toTypedArray()

    /**
     * Runs the bootstrap helper for a short management command. Unlike the
     * exploit run there is no log file to poll, so output is drained inline
     * and a hard deadline guards against a helper that never exits — without
     * this, a hung `--late-load` leaves the install stuck in LoadingKernelSu
     * indefinitely.
     */
    private suspend fun runHelper(vararg arguments: String): CommandResult {
        val helper = helperFile()
        val process = if (shizukuEnabled()) {
            ShizukuController.exec(arrayOf(helper.absolutePath) + arguments)
        } else {
            ProcessBuilder(listOf(helper.absolutePath) + arguments)
                .redirectErrorStream(true)
                .start()
        }
        val captured = StringBuilder()
        val startedAt = SystemClock.elapsedRealtime()
        try {
            while (process.isAlive) {
                drainProcessOutput(process, captured)
                require(SystemClock.elapsedRealtime() - startedAt < HELPER_TIMEOUT_MILLIS) {
                    app.getString(
                        R.string.error_helper_timeout,
                        captured.toString().trim().takeIf(String::isNotBlank)
                            ?.let { ": $it" } ?: "",
                    )
                }
                delay(HELPER_POLL_INTERVAL)
            }
            drainProcessOutput(process, captured)
            val exitCode = process.waitFor()
            return CommandResult(exitCode, stripAnsi(captured.toString().trim()))
        } finally {
            if (process.isAlive) {
                process.destroy()
                delay(500.milliseconds)
                if (process.isAlive) process.destroyForcibly()
            }
        }
    }

    private fun shellQuote(value: String) = "'${value.replace("'", "'\\''")}'"

    private fun setPhase(phase: InstallPhase, message: String) {
        mutableState.value = mutableState.value.copy(phase = phase, message = message)
        appendLog("[*] $message")
    }

    private fun appendLog(line: String) {
        val cleanLine = stripAnsi(line).trim()
        if (cleanLine.isBlank()) return
        mutableState.value = mutableState.value.copy(
            log = (mutableState.value.log + "\n" + cleanLine).trim(),
        )
        updateHistoryLog()
    }

    private fun startHistory() {
        val entry = historyStore.create()
        activeHistoryEntry = entry
        publishHistory(entry)
    }

    private fun updateHistory(transform: (InstallHistoryEntry) -> InstallHistoryEntry) {
        val entry = activeHistoryEntry ?: return
        val updated = transform(entry)
        activeHistoryEntry = updated
        historyStore.save(updated)
        publishHistory(updated)
    }

    private fun updateHistoryLog() =
        updateHistory { it.copy(log = mutableState.value.log) }

    private fun updateHistoryProfile(profileId: String) =
        updateHistory { it.copy(profileId = profileId) }

    private fun finishHistory(result: InstallRunResult) {
        updateHistory { entry ->
            entry.copy(
                completedAtMillis = System.currentTimeMillis(),
                result = result,
                log = mutableState.value.log,
            )
        }
        activeHistoryEntry = null
    }

    private fun publishHistory(entry: InstallHistoryEntry) {
        mutableHistory.value = (mutableHistory.value.filterNot { it.id == entry.id } + entry)
            .sortedByDescending(InstallHistoryEntry::startedAtMillis)
    }

    private fun File.readTextIfPresent(): String = if (exists()) readText() else ""

    companion object {
        private const val EXPLOIT_ATTEMPTS = "24"
        private const val P0_ATTEMPT_TIMEOUT_SEC = "45"
        private const val EXPLOIT_ATTEMPT_TIMEOUT_SEC = "120"
        private const val EXPLOIT_STALL_MILLIS = 90_000L
        private const val EXPLOIT_TOTAL_MILLIS = 900_000L
        private const val HELPER_TIMEOUT_MILLIS = 120_000L
        private const val INSTALL_RECEIPT = "install_receipt"
        private const val RECEIPT_BOOT_TOKEN = "kernel_boot_id"
        private const val RECEIPT_VERIFIED = "verified"
        private const val P0_CACHE = "p0_cache"
        private const val P0_CACHE_BOOT_TOKEN = "kernel_boot_id"
        private const val P0_CACHE_OFFSET = "offset"
        private const val P0_OFFSET_ENV = "SLIDE_P0_OFFSET"
        private const val P0_OFFSET_MAX = 0x1f0000L
        private const val P0_OFFSET_MASK = 0xffffL
        private const val SHIZUKU_LOG_PATH = "/data/local/tmp/ksu-exploit.log"
        private const val TRANSPORT_STABLE_5555 = "[*] transport: stable adbTCP 127.0.0.1:5555"
        private const val TRANSPORT_WIRELESS_DEBUGGING = "[*] transport: wireless debugging (dynamic port)"
        private const val SU_TIMEOUT_MS = 90_000L
        private const val SU_CHECK_TIMEOUT_MS = 20_000L
        private const val STAGE_FIRE_TIMEOUT_MS = 10_000L
        private const val MODULE_WAIT_MILLIS = 90_000L
        private const val APPLY_LOG_TAG = "RmgApply"
        private const val SHIZUKU_HELPER_PATH = "/data/local/tmp/ksu-helper"
        private const val SHIZUKU_PAYLOAD_PATH = "/data/local/tmp/ksu-payload"
        private const val SHIZUKU_KSUD_PATH = "/data/local/tmp/ksud-s25u-kdp"
        private const val SHIZUKU_KSUD_STAGE_PATH = "/data/local/tmp/.ksud-stage"
        private val LOG_POLL_INTERVAL = 250.milliseconds
        private val HELPER_POLL_INTERVAL = 250.milliseconds
        private val SHIZUKU_LOG_POLL_INTERVAL = 1.seconds
        private val ANSI_ESCAPE = Regex("\u001B\\[[0-?]*[ -/]*[@-~]")
        private val P0_OFFSET_PATTERN = Regex(
            "slide-kaslr-ok[^\\n]*slide=([0-9a-fA-F]{16})",
        )

        private fun stripAnsi(value: String): String = ANSI_ESCAPE.replace(value, "").replace("\r", "")
    }
}
