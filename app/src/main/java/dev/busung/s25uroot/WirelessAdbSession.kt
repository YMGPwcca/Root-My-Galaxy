package dev.busung.s25uroot

import android.content.Context
import android.os.SystemClock
import android.util.Log
import java.io.Closeable
import java.io.File
import java.net.SocketTimeoutException

private const val TAG = "WirelessAdbSession"

/**
 * A live connection to the device's own adbd over wireless debugging.
 *
 * Encapsulates the full bring-up sequence (enable wireless debugging, discover
 * the dynamic connect port via mDNS, authenticate with the paired ADB key) and
 * exposes push/shell operations. All commands run in the `u:r:shell:s0`
 * context, which is what the tracefs exploit route requires — no PC needed.
 *
 * Use [open] to create and connect a session, then [close] when done.
 */
class WirelessAdbSession private constructor(
    private val client: LocalAdbClient,
    /** True when this session rides the stable adbTCP 5555 listener. */
    val viaTcp5555: Boolean = false,
) : Closeable {

    /** Pushes a local file to the device and marks it executable. */
    fun push(localFile: File, remotePath: String, executable: Boolean = false) {
        client.push(localFile, remotePath)
        if (executable) {
            val chmod = client.shell("chmod 755 '$remotePath'")
            check(chmod.exitCode == 0) { "chmod 755 $remotePath failed: ${chmod.output}" }
        }
        Log.d(TAG, "pushed ${localFile.name} -> $remotePath")
    }

    /** Runs a shell command and returns its combined output. */
    fun shell(command: String): LocalAdbClient.ShellResult = client.shell(command)

    /**
     * Runs [command] as root via the exploit's root daemon.
     *
     * The ADB shell runs in `u:r:shell:s0`, which SELinux denies for
     * privileged operations (`setprop ctl.*`, killing root-owned zygote,
     * mounting modules). The root helper's client mode forwards the command
     * to the persistent root daemon (`/data/local/tmp/temp_su.sock`), which
     * executes it as uid 0 / `u:r:kernel:s0`.
     *
     * The daemon execs `sh -c "<command>"`, so [command] is escaped for a
     * double-quoted root shell. Requires the daemon to be alive (same boot as
     * the exploit — root is volatile across reboots).
     */
    fun shellAsRoot(
        command: String,
        helperPath: String = DEFAULT_HELPER_PATH,
    ): LocalAdbClient.ShellResult {
        val escaped = command
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("$", "\\$")
            .replace("`", "\\`")
        return client.shell("$helperPath -c \"$escaped\"")
    }

    /**
     * Runs [command] inside a single ADB shell that stays open for the
     * command's full lifetime, streaming its stdout chunk-by-chunk via
     * [onOutput] and returning the accumulated output.
     *
     * adbd kills a backgrounded process the instant its shell stream closes,
     * so a long-running exploit (up to 15 minutes) must run in the foreground
     * of an *open* shell. The root helper's `--run-payload` mode already forks
     * the payload into its own session (so it survives) and streams the live
     * log to stdout via a foreground supervisor, so streaming the helper's
     * stdout directly yields real-time progress.
     */
    fun runStreaming(
        command: String,
        shouldStop: () -> Boolean = { false },
        onOutput: (String) -> Unit,
    ): String {
        val accumulated = StringBuilder()
        client.shellStreaming(command, shouldStop = shouldStop) { chunk ->
            accumulated.append(chunk)
            onOutput(accumulated.toString())
        }
        return accumulated.toString()
    }

    /**
     * Switches adbd to stable TCP mode on port 5555 (no root needed — adbd
     * performs the change itself). The current session dies with the
     * restart; call this LAST, right before closing. Future sessions use
     * the stable port via the fast path in [open].
     */
    fun switchToTcp5555(): Boolean = client.requestTcpMode(5555)

    /** Removes a remote file, ignoring errors. */
    fun remove(remotePath: String) {
        client.shell("rm -f '$remotePath'")
    }

    /** Reads the current contents of a remote file (empty string if missing). */
    fun readLog(remotePath: String): String =
        client.shell("cat '$remotePath' 2>/dev/null").output

    override fun close() {
        runCatching { client.close() }
    }

    companion object {
        /** Default path of the staged root helper (client mode -> root daemon). */
        const val DEFAULT_HELPER_PATH = "/data/local/tmp/ksu-helper"

        /**
         * Enables wireless debugging (if needed and permitted), discovers the
         * connect port, and authenticates. Throws if the session cannot be
         * established — callers treat this as the "wireless ADB required" gate.
         */
        fun open(
            context: Context,
            portDiscoveryTimeoutMs: Long = 60_000,
            depth: Int = 0,
        ): WirelessAdbSession {
            val keyManager = AdbKeyManager(context)

            // Fast path: stable adbTCP on port 5555, enabled by a previous
            // rooted apply (service.adb.tcp.port + whitelisted app key).
            // Loopback never drops and the port never rotates — prefer it
            // whenever it answers, and skip wireless debugging entirely.
            runCatching {
                val tcp = LocalAdbClient("127.0.0.1", 5555, keyManager)
                tcp.connect()
                Log.i(TAG, "connected via stable adbTCP 127.0.0.1:5555")
                AppPreferences.setAdbPaired(context, true) // proven trusted
                // Wireless debugging served its purpose (or was left on
                // earlier): drop it now so band switches / Wi-Fi churn can
                // never tear the transport down mid-run. Non-fatal.
                disableWirelessAdb(tcp)
                return WirelessAdbSession(tcp, viaTcp5555 = true)
            }.onFailure { Log.d(TAG, "no adbTCP on 5555 (${it.message}); using wireless debugging") }

            // 1. Ensure wireless debugging is on.
            if (!AdbPairing.isWirelessAdbEnabled(context)) {
                check(AdbPairing.enableWirelessAdb(context)) {
                    "Wireless debugging is off and could not be enabled " +
                        "(grant WRITE_SECURE_SETTINGS via `adb install -g`)"
                }
            }

            // 2. Discover the dynamic connect port via mDNS.
            val port = discoverPort(context, portDiscoveryTimeoutMs)
            check(port > 0) { "Wireless-debugging connect port not found via mDNS" }
            // 3. Connect + authenticate with the paired key.
            val client = LocalAdbClient("127.0.0.1", port, keyManager)
            try {
                client.connect()
            } catch (e: SocketTimeoutException) {
                // adbd kept re-challenging: our key is NOT authorized
                // (phone-side forget). Verdict: not paired.
                AppPreferences.setAdbPaired(context, false)
                throw e
            }
            AppPreferences.setAdbPaired(context, true) // proven trusted
            Log.d(TAG, "connected to local adbd")

            // 4. Upgrade to stable TCP 5555 BEFORE any long work (the
            // exploit streams for minutes; wireless debugging can drop
            // mid-stream with Wi-Fi churn). adbd restarts itself on 5555,
            // killing this bootstrap session — reconnect there with retries
            // (first ever connect may wait for the on-screen approval
            // dialog). If the upgrade fails, fall back: either the original
            // session still works (no OKAY) or we re-bring-up wireless.
            val ok = runCatching { client.requestTcpMode(5555) }.getOrDefault(false)
            if (ok) {
                client.close()
                // Human dialog-approval latency: the on-screen "Allow USB
                // debugging?" prompt appears during this window. Give the
                // user a real budget (120s), not a 25s sprint.
                repeat(120) {
                    runCatching {
                        val tcp = LocalAdbClient("127.0.0.1", 5555, keyManager)
                        tcp.connect()
                        Log.i(TAG, "upgraded to stable adbTCP 127.0.0.1:5555")
                        // Bootstrap done: wireless debugging is now a
                        // liability (any band switch kills it mid-exploit).
                        // Shut it off immediately; everything rides 5555.
                        disableWirelessAdb(tcp)
                        return WirelessAdbSession(tcp, viaTcp5555 = true)
                    }
                    Thread.sleep(1_000)
                }
                // 5555 never answered (dialog denied/ignored): rebuild
                // wireless debugging — exactly ONE extra attempt, then give
                // up instead of cycling forever.
                if (depth == 0) {
                    Log.w(TAG, "tcpip upgrade failed - re-bringing up wireless debugging")
                    return open(context, portDiscoveryTimeoutMs, depth = 1)
                }
                error("adbd did not come up on TCP 5555 and the wireless debugging re-bootstrap was already tried once")
            }
            return WirelessAdbSession(client)
        }

        private fun discoverPort(context: Context, timeoutMs: Long): Int {
            val deadline = SystemClock.elapsedRealtime() + timeoutMs
            while (SystemClock.elapsedRealtime() < deadline) {
                val port = AdbPairing.discoverConnectPort(context, timeoutMs = 10_000)
                if (port > 0) return port
                Thread.sleep(2_000)
            }
            return -1
        }

        /**
         * Lightweight truth probe: can our key authenticate against the
         * current wireless-debugging listener right now?
         * true = trusted, false = rejected (e.g. phone-side revoke),
         * null = inconclusive (wireless debugging off, no pairing offer).
         * Never pops dialogs, never mutates state — callers persist.
         */
        fun probePairing(context: Context): Boolean? {
            if (!AdbPairing.isWirelessAdbEnabled(context)) return null
            val port = AdbPairing.discoverConnectPort(context, timeoutMs = 6_000)
            if (port <= 0) return null
            val client = LocalAdbClient("127.0.0.1", port, AdbKeyManager(context))
            return try {
                client.connect()
                client.close()
                true
            } catch (e: SocketTimeoutException) {
                false // adbd kept re-challenging: key not authorized
            } catch (t: Throwable) {
                false // TLS rejection / transport gone: not trusted
            }
        }

        /**
         * Turns the wireless-debugging listener off over an open 5555
         * session. The stable `service.adb.tcp.port` listener is
         * independent of the wireless-debugging switch, so this never
         * drops our own transport — it only removes the fragile dynamic
         * listener that band switching tears down.
         */
        private fun disableWirelessAdb(client: LocalAdbClient) {
            runCatching {
                client.shell("settings put global adb_wifi_enabled 0")
                Log.i(TAG, "wireless debugging disabled - stable TCP 5555 only")
            }.onFailure { Log.w(TAG, "could not disable wireless debugging: ${it.message}") }
        }

    }
}
