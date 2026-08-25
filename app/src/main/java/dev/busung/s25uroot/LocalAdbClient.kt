package dev.busung.s25uroot

import android.content.Context
import android.util.Log
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.Signature
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLSocket

private const val TAG = "LocalAdbClient"

/**
 * Minimal ADB protocol client for connecting to the device's own adbd
 * over wireless debugging (TLS). Provides shell access in the
 * u:r:shell:s0 context without a PC.
 *
 * Supports both STLS (wireless debugging, Android 11+) and legacy
 * RSA-token authentication.
 */
class LocalAdbClient(
    private val host: String,
    private val port: Int,
    private val keyManager: AdbKeyManager,
) : Closeable {
    private lateinit var socket: Socket
    private lateinit var plainInput: DataInputStream
    private lateinit var plainOutput: DataOutputStream
    private var useTls = false
    private lateinit var tlsSocket: SSLSocket
    private lateinit var tlsInput: DataInputStream
    private lateinit var tlsOutput: DataOutputStream

    // A dedicated reader thread drains complete ADB messages into this queue.
    // Reads are never interrupted mid-message, so long-lived streaming shells
    // (the exploit runs up to 15 minutes) cannot corrupt the stream when the
    // caller polls with a timeout.
    private val messageQueue = LinkedBlockingQueue<AdbMessage>()

    /**
     * Monotonically increasing local stream ids. Reusing id 1 for every
     * stream made a late CLSE/OKAY from a PREVIOUS stream
     * indistinguishable from the current one except by timing heuristics;
     * unique ids let messages be routed by identity instead.
     */
    private val lastLocalId = java.util.concurrent.atomic.AtomicInteger(0)

    private fun allocateLocalId(): Int = lastLocalId.incrementAndGet()
    @Volatile private var readerError: Throwable? = null
    private var readerThread: Thread? = null

    // A WRTE consumed by writeSync while hunting for its OKAY ack (adbd can
    // interleave sync-protocol data before the ack). The push final-response
    // loop checks this slot first so the result is never lost.
    private var pendingMessage: AdbMessage? = null

    private val inputStream get() = if (useTls) tlsInput else plainInput
    private val outputStream get() = if (useTls) tlsOutput else plainOutput

    /**
     * Connects and authenticates to adbd.
     */
    fun connect() {
        socket = Socket()
        socket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
        socket.tcpNoDelay = true
        socket.soTimeout = READ_TIMEOUT_MS
        plainInput = DataInputStream(socket.getInputStream().buffered())
        plainOutput = DataOutputStream(socket.getOutputStream().buffered())

        write(A_CNXN, A_VERSION, A_MAXDATA, "host::features=cmd,shell_v2")
        var message = read()

        if (message.command == A_STLS) {
            // Wireless debugging: upgrade to TLS
            write(A_STLS, A_STLS_VERSION, 0)
            val sslContext = keyManager.sslContext
            tlsSocket = sslContext.socketFactory.createSocket(socket, host, port, true) as SSLSocket
            tlsSocket.startHandshake()
            Log.d(TAG, "TLS handshake succeeded")
            tlsInput = DataInputStream(tlsSocket.inputStream)
            tlsOutput = DataOutputStream(tlsSocket.outputStream)
            useTls = true
            message = read()
        } else if (message.command == A_AUTH && message.arg0 == ADB_AUTH_TOKEN) {
            // Legacy RSA auth
            val sig = signToken(message.data!!)
            writeBytes(A_AUTH, ADB_AUTH_SIGNATURE, 0, sig)
            message = read()
            if (message.command != A_CNXN) {
                writeBytes(A_AUTH, ADB_AUTH_RSAPUBLICKEY, 0, keyManager.adbPublicKey)
                message = read()
            }
        }

        if (message.command != A_CNXN) error("ADB connection failed: 0x${message.command.toString(16)}")
        Log.d(TAG, "Connected: ${String(message.data ?: ByteArray(0))}")

        // The connection is up: disable the handshake read timeout so the
        // reader thread can block indefinitely across long silent periods
        // (the exploit log only grows when new content appears), then start
        // draining messages on a background thread.
        runCatching { socket.soTimeout = 0 }
        runCatching { if (useTls) tlsSocket.soTimeout = 0 }
        startReader()
    }

    private fun startReader() {
        readerThread = Thread({
            try {
                while (true) {
                    messageQueue.put(read())
                }
            } catch (t: Throwable) {
                readerError = t
                // Teardown interrupts this thread; a plain queue.put would
                // throw InterruptedException again from inside the catch and
                // kill the whole process. Clear the flag and never rethrow.
                Thread.interrupted()
                runCatching { messageQueue.put(POISON) }
            }
        }, "adb-reader").apply { isDaemon = true; start() }
    }

    /**
     * Returns the next complete ADB message. Blocks indefinitely when
     * [timeoutMs] is 0; otherwise returns after at most [timeoutMs] by
     * throwing [SocketTimeoutException]. Never splits a message across
     * timeouts.
     */
    private fun nextMessage(timeoutMs: Long = 0): AdbMessage {
        val msg = if (timeoutMs <= 0) {
            messageQueue.take()
        } else {
            messageQueue.poll(timeoutMs, TimeUnit.MILLISECONDS)
                ?: throw SocketTimeoutException("No ADB message within ${timeoutMs}ms")
        }
        if (msg === POISON) {
            throw readerError ?: IOException("ADB reader stopped")
        }
        return msg
    }

    /**
     * Returns the next ADB message belonging to stream [localId]. Messages
     * for any other stream are residue from an earlier operation and are
     * dropped — identity routing, not timing.
     */
    private fun nextMessageFor(localId: Int, timeoutMs: Long = 0): AdbMessage {
        while (true) {
            val msg = nextMessage(timeoutMs)
            if (msg.arg1 == localId) return msg
            Log.d(TAG, "dropping stale message for stream ${msg.arg1} (want $localId)")
        }
    }

    /**
     * Drains any messages left over from a previous stream.
     *
     * The ADB transport is a single multiplexed byte stream feeding one shared
     * queue, but this client runs only one operation at a time. When an
     * operation finishes it sends CLSE and returns immediately, while adbd's
     * final replies (its own CLSE, or trailing OKAY flow-control acks) can
     * arrive *after* we have moved on. Those stale messages then sit in the
     * queue and the next operation consumes them, shifting its whole message
     * sequence by one (the classic symptom: an OKAY turning up where only
     * WRTE/CLSE are valid). Draining with a short poll before opening a new
     * stream discards that residue.
     */
    private fun drainStaleMessages(context: String) {
        var drained = 0
        while (true) {
            val msg = messageQueue.poll(150, TimeUnit.MILLISECONDS) ?: break
            if (msg === POISON) {
                throw readerError ?: IOException("ADB reader stopped")
            }
            drained++
            Log.w(
                TAG,
                "[$context] drained stale message cmd=${cmdName(msg.command)} " +
                    "arg0=${msg.arg0} arg1=${msg.arg1} len=${msg.data?.size ?: 0}",
            )
        }
        if (drained > 0) {
            Log.w(TAG, "[$context] drained $drained stale message(s) before opening new stream")
        }
    }

    private fun cmdName(command: Int): String = when (command) {
        A_CNXN -> "CNXN"
        A_AUTH -> "AUTH"
        A_OPEN -> "OPEN"
        A_OKAY -> "OKAY"
        A_CLSE -> "CLSE"
        A_WRTE -> "WRTE"
        A_STLS -> "STLS"
        else -> "0x${command.toString(16)}"
    }
    /**
     * Asks adbd to restart itself listening on TCP [port] — the protocol
     * equivalent of `adb tcpip <port>`. Delegated privilege: adbd performs
     * the property change itself, so NO root is required, only an already
     * authenticated session. The connection drops as adbd restarts.
     */
    fun requestTcpMode(port: Int): Boolean {
        drainStaleMessages("tcpip")
        Log.i(TAG, "requesting tcpip:$port (adbd will restart)")
        val localId = allocateLocalId()
        return try {
            write(A_OPEN, localId, 0, "tcpip:$port")
            val message = nextMessageFor(localId)
            message.command == A_OKAY
        } catch (t: Throwable) {
            // adbd tears the stream down mid-handshake when it restarts;
            // that is expected and usually means success.
            Log.d(TAG, "tcpip: stream ended (${t.javaClass.simpleName})")
            true
        }
    }
    /**
     * Executes a shell command and returns the output.
     */
    fun shell(command: String): ShellResult {
        val localId = allocateLocalId()
        drainStaleMessages("shell")
        Log.d(TAG, "shell: OPEN ${command.take(120)}")
        // The raw ADB `shell:` service does not propagate the command's exit
        // code (it always closes cleanly). Wrap the command so the exit code
        // is echoed on a marker line we can parse — otherwise a denied
        // setprop or a failed binary looks like success.
        val wrapped = "sh -c '${command.replace("'", "'\\''")}; echo __ADB_EXIT__=$?'"
        write(A_OPEN, localId, 0, "shell:$wrapped")
        var message = nextMessageFor(localId)
        val output = StringBuilder()

        when (message.command) {
            A_OKAY -> {
                while (true) {
                    message = nextMessageFor(localId)
                    val remoteId = message.arg0
                    if (message.command == A_WRTE) {
                        if (message.data != null && message.data.isNotEmpty()) {
                            output.append(String(message.data))
                        }
                        write(A_OKAY, localId, remoteId)
                    } else if (message.command == A_CLSE) {
                        write(A_CLSE, localId, remoteId)
                        break
                    } else if (message.command == A_OKAY) {
                        // Benign flow-control ack (e.g. for our own CLSE/WRTE);
                        // nothing to do.
                        Log.d(TAG, "shell: stray OKAY ignored (arg0=${message.arg0})")
                    } else {
                        error("Unexpected message in shell: ${cmdName(message.command)} arg0=${message.arg0}")
                    }
                }
            }
            A_CLSE -> {
                write(A_CLSE, localId, message.arg0)
            }
            else -> error("Unexpected response to OPEN: ${cmdName(message.command)}")
        }
        val raw = output.toString()
        // Extract the exit code from the marker line and strip it from output.
        val markerIdx = raw.lastIndexOf("__ADB_EXIT__=")
        var exitCode = 0
        var body = raw
        if (markerIdx >= 0) {
            val codeStr = raw.substring(markerIdx + "__ADB_EXIT__=".length)
                .lineSequence().firstOrNull()?.trim()
            exitCode = codeStr?.toIntOrNull() ?: 0
            body = raw.substring(0, markerIdx)
        }
        Log.d(TAG, "shell: done, exit=$exitCode, ${body.length} chars")
        return ShellResult(exitCode, body.trim())
    }

    /**
     * Executes a shell command and streams its output chunk-by-chunk via
     * [onOutput], keeping the ADB shell open for the command's full lifetime.
     *
     * This is required for long-running commands (the exploit runs up to 15
     * minutes): adbd kills a backgrounded process the moment its shell stream
     * closes, so the command must run in the foreground of an open shell.
     *
     * The root helper only writes to the transport when new log content
     * appears, so the stream can go silent for minutes during allocator
     * searches. This method therefore uses a short per-read timeout and
     * retries until either [overallTimeoutMs] elapses or no output arrives for
     * [stallTimeoutMs]. Returns the accumulated output when the command
     * finishes.
     */
    fun shellStreaming(
        command: String,
        overallTimeoutMs: Long = 15 * 60 * 1000L,
        stallTimeoutMs: Long = 5 * 60 * 1000L,
        shouldStop: () -> Boolean = { false },
        onOutput: (String) -> Unit,
    ): ShellResult {
        val localId = allocateLocalId()
        drainStaleMessages("shellStreaming")
        Log.d(TAG, "shellStreaming: OPEN ${command.take(120)}")
        write(A_OPEN, localId, 0, "shell:$command")
        var message = nextMessageFor(localId)
        val output = StringBuilder()
        val deadline = System.currentTimeMillis() + overallTimeoutMs
        var lastOutputAt = System.currentTimeMillis()

        when (message.command) {
            A_OKAY -> {
                // The remote id is constant for the whole stream; capture
                // it once so timeout paths can close the remote command.
                val streamRemoteId = message.arg0
                while (true) {
                    val now = System.currentTimeMillis()
                    if (now > deadline) {
                        Log.w(TAG, "shellStreaming overall timeout reached")
                        runCatching { write(A_CLSE, localId, streamRemoteId) }
                        break
                    }
                    if (now - lastOutputAt > stallTimeoutMs) {
                        Log.w(TAG, "shellStreaming stall timeout reached")
                        runCatching { write(A_CLSE, localId, streamRemoteId) }
                        break
                    }
                    if (shouldStop()) {
                        Log.d(TAG, "shellStreaming: early stop requested")
                        write(A_CLSE, localId, streamRemoteId)
                        break
                    }
                    // Poll the reader queue with a short timeout so we can
                    // re-check the deadline/stall bounds without blocking
                    // forever. nextMessage never splits a message across
                    // timeouts, so the stream stays intact.
                    message = try {
                        nextMessageFor(localId, 1000)
                    } catch (e: SocketTimeoutException) {
                        continue
                    }
                    if (message.command == A_WRTE) {
                        if (message.data != null && message.data.isNotEmpty()) {
                            val chunk = String(message.data)
                            output.append(chunk)
                            onOutput(chunk)
                            lastOutputAt = System.currentTimeMillis()
                        }
                        write(A_OKAY, localId, streamRemoteId)
                    } else if (message.command == A_CLSE) {
                        write(A_CLSE, localId, streamRemoteId)
                        break
                    } else if (message.command == A_OKAY) {
                        // Benign flow-control ack; nothing to do.
                        Log.d(TAG, "shellStreaming: stray OKAY ignored (arg0=${message.arg0})")
                    } else {
                        error("Unexpected message in shellStreaming: ${cmdName(message.command)} arg0=${message.arg0}")
                    }
                }
            }
            A_CLSE -> {
                write(A_CLSE, localId, message.arg0)
            }
            else -> error("Unexpected response to OPEN: ${cmdName(message.command)}")
        }
        Log.d(TAG, "shellStreaming: done, ${output.length} chars")
        return ShellResult(0, output.toString().trim())
    }

    /**
     * Pushes a file via the ADB sync protocol.
     */
    fun push(localFile: File, remotePath: String, mode: Int = 0b111101101) {
        val localId = allocateLocalId()
        drainStaleMessages("push")
        Log.d(TAG, "push: OPEN sync: ${localFile.name} -> $remotePath (${localFile.length()} bytes)")
        write(A_OPEN, localId, 0, "sync:")
        var message = nextMessageFor(localId)
        if (message.command != A_OKAY) error("Failed to open sync: ${cmdName(message.command)}")
        val remoteId = message.arg0

        // SEND
        val pathWithMode = "$remotePath,$mode"
        val sendPayload = ByteBuffer.allocate(8 + pathWithMode.length).order(ByteOrder.LITTLE_ENDIAN)
        sendPayload.put("SEND".toByteArray())
        sendPayload.putInt(pathWithMode.length)
        sendPayload.put(pathWithMode.toByteArray())
        writeSync(localId, remoteId, sendPayload.array())

        // DATA chunks
        val fileBytes = localFile.readBytes()
        val chunkSize = 64 * 1024
        var offset = 0
        while (offset < fileBytes.size) {
            val len = minOf(chunkSize, fileBytes.size - offset)
            val dataPayload = ByteBuffer.allocate(8 + len).order(ByteOrder.LITTLE_ENDIAN)
            dataPayload.put("DATA".toByteArray())
            dataPayload.putInt(len)
            dataPayload.put(fileBytes, offset, len)
            writeSync(localId, remoteId, dataPayload.array())
            offset += len
        }

        // DONE
        val donePayload = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
        donePayload.put("DONE".toByteArray())
        donePayload.putInt((System.currentTimeMillis() / 1000).toInt())
        writeSync(localId, remoteId, donePayload.array())

        // Read final response. adbd may interleave OKAY flow-control acks
        // before the WRTE carrying the sync result; skip them. A result WRTE
        // already consumed by writeSync is replayed from pendingMessage.
        var sawResult = false
        while (!sawResult) {
            message = pendingMessage ?: nextMessageFor(localId)
            pendingMessage = null
            when (message.command) {
                A_WRTE -> {
                    write(A_OKAY, localId, message.arg0)
                    if (message.data != null && message.data.size >= 4) {
                        val status = String(message.data, 0, 4)
                        if (status == "FAIL") {
                            val failLen = ByteBuffer.wrap(message.data, 4, 4).order(ByteOrder.LITTLE_ENDIAN).int
                            val failMsg = if (message.data.size > 8) {
                                String(message.data, 8, minOf(failLen, message.data.size - 8))
                            } else "unknown"
                            error("ADB push failed: $failMsg")
                        }
                    }
                    sawResult = true
                }
                A_OKAY -> {
                    // Flow-control ack; keep waiting for the result WRTE.
                }
                A_CLSE -> {
                    // Sync closed without an explicit result WRTE; treat as
                    // success only if no FAIL was seen (adbd closes after OKAY).
                    sawResult = true
                }
                else -> error("Unexpected message in push: ${cmdName(message.command)} arg0=${message.arg0}")
            }
        }
        write(A_CLSE, localId, remoteId)
        Log.d(TAG, "push: done $remotePath")
    }

    private fun writeSync(localId: Int, remoteId: Int, payload: ByteArray) {
        writeBytes(A_WRTE, localId, remoteId, payload)
        // adbd acks each WRTE with OKAY, but may also interleave its own WRTE
        // (sync protocol data) before the ack; skip anything that is not the
        // ack we are waiting for, up to a small bound.
        repeat(8) {
            val ack = nextMessage()
            when (ack.command) {
                A_OKAY -> return
                A_WRTE -> {
                    // adbd sent data (e.g. an early sync response) before our
                    // ack; ack it, stash it for the final-response loop, and
                    // keep waiting for the OKAY.
                    write(A_OKAY, localId, ack.arg0)
                    pendingMessage = ack
                }
                else -> error("Sync write not acknowledged: ${cmdName(ack.command)} arg0=${ack.arg0}")
            }
        }
        error("Sync write not acknowledged after 8 interleaved messages")
    }

    private fun signToken(token: ByteArray): ByteArray {
        val sig = Signature.getInstance("SHA1withRSA")
        sig.initSign(keyManager.privateKey)
        sig.update(token)
        return sig.sign()
    }

    private data class AdbMessage(
        val command: Int,
        val arg0: Int,
        val arg1: Int,
        val data: ByteArray?,
    )

    private fun writeBytes(command: Int, arg0: Int, arg1: Int, data: ByteArray) {
        writeRaw(command, arg0, arg1, data)
    }

    private fun write(command: Int, arg0: Int, arg1: Int) {
        writeRaw(command, arg0, arg1, null)
    }

    private fun write(command: Int, arg0: Int, arg1: Int, data: String) {
        writeRaw(command, arg0, arg1, "$data\u0000".toByteArray())
    }

    private fun writeRaw(command: Int, arg0: Int, arg1: Int, payload: ByteArray?) {
        val length = payload?.size ?: 0
        val checksum = payload?.sumOf { it.toInt() and 0xFF } ?: 0
        val magic = command xor -0x1
        val header = ByteBuffer.allocate(HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN)
        header.putInt(command)
        header.putInt(arg0)
        header.putInt(arg1)
        header.putInt(length)
        header.putInt(checksum)
        header.putInt(magic)
        outputStream.write(header.array())
        if (payload != null) outputStream.write(payload)
        outputStream.flush()
    }

    private fun read(): AdbMessage {
        val header = ByteArray(HEADER_SIZE)
        inputStream.readFully(header)
        val buf = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN)
        val command = buf.int
        val arg0 = buf.int
        val arg1 = buf.int
        val dataLength = buf.int
        val checksum = buf.int
        val magic = buf.int
        // Protocol invariants: a malformed or hostile transport must be
        // REJECTED here, not trusted to resynchronize later.
        if (magic != command.inv()) {
            throw IOException("ADB bad magic 0x${magic.toString(16)} for command 0x${command.toString(16)}")
        }
        if (dataLength < 0 || dataLength > A_MAXDATA) {
            throw IOException("ADB absurd data length $dataLength")
        }
        val data = if (dataLength > 0) {
            val d = ByteArray(dataLength)
            inputStream.readFully(d)
            // Some vendor adbds ship a zero checksum field; accept that,
            // but a WRONG non-zero checksum means bit corruption.
            val actual = d.sumOf { it.toInt() and 0xFF }
            if (checksum != 0 && checksum != actual) {
                throw IOException("ADB checksum mismatch: header=$checksum actual=$actual")
            }
            d
        } else null
        return AdbMessage(command, arg0, arg1, data)
    }

    override fun close() {
        try { plainInput.close() } catch (_: Throwable) {}
        try { plainOutput.close() } catch (_: Throwable) {}
        try { socket.close() } catch (_: Exception) {}
        if (useTls) {
            try { tlsInput.close() } catch (_: Throwable) {}
            try { tlsOutput.close() } catch (_: Throwable) {}
            try { tlsSocket.close() } catch (_: Exception) {}
        }
        // Closing the socket unblocks the reader thread's readFully, which
        // then pushes POISON and exits.
        readerThread?.interrupt()
    }

    data class ShellResult(val exitCode: Int, val output: String)

    companion object {
        private const val CONNECT_TIMEOUT_MS = 10_000
        private const val READ_TIMEOUT_MS = 120_000
        private const val HEADER_SIZE = 24

        /** Sentinel pushed by the reader thread when it stops. */
        private val POISON = AdbMessage(0, 0, 0, null)

        private const val A_CNXN = 0x4e584e43
        private const val A_AUTH = 0x48545541
        private const val A_OPEN = 0x4e45504f
        private const val A_OKAY = 0x59414b4f
        private const val A_CLSE = 0x45534c43
        private const val A_WRTE = 0x45545257
        private const val A_STLS = 0x534c5453

        private const val A_VERSION = 0x01000000
        private const val A_MAXDATA = 256 * 1024
        private const val A_STLS_VERSION = 0x01000000

        private const val ADB_AUTH_TOKEN = 1
        private const val ADB_AUTH_SIGNATURE = 2
        private const val ADB_AUTH_RSAPUBLICKEY = 3

        /**
         * Convenience: connect, run a shell command, close.
         */
        fun shellOnce(host: String, port: Int, keyManager: AdbKeyManager, command: String): ShellResult {
            return LocalAdbClient(host, port, keyManager).use { client ->
                client.connect()
                client.shell(command)
            }
        }
    }
}
