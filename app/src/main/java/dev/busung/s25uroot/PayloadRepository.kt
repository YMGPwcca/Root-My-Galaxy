package dev.busung.s25uroot

import android.content.Context
import android.system.Os
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.io.InputStream
import org.json.JSONObject

data class VerifiedPayloads(
    val profile: TargetProfile,
    val exploit: File,
    val kernelSu: File,
)

/**
 * Serves target profiles and payload binaries from two layers:
 *
 *  1. **Bundled** — a manifest and its artifacts ship inside the APK's
 *     assets, so the app can always install for known devices with no
 *     network at all.
 *  2. **Network** — the upstream payload repository manifest is fetched
 *     (commit-pinned), cached to disk on success, and merged under the
 *     bundled entries. New firmware published upstream shows up in the
 *     profile picker without an app update.
 */
class PayloadRepository(private val context: Context) {

    fun loadTargets(): List<TargetProfile> {
        val bundled = runCatching { parseBundledManifest() }.getOrElse { emptyList() }
        val remote = try {
            fetchRemoteTargets()
        } catch (error: Throwable) {
            // Fresh OFFLINE install: no cache exists yet. Bundled profiles
            // alone still allow installing for known devices — only surface
            // the network failure when there is nothing to install from.
            loadTargetsFromCache() ?: run {
                if (bundled.isNotEmpty()) emptyList<TargetProfile>() else throw error
            }
        }
        // Bundled wins id collisions; remote-only profiles are appended.
        val merged = bundled.associateBy { it.profileId }.toMutableMap()
        remote.forEach { profile -> merged.putIfAbsent(profile.profileId, profile) }
        require(merged.isNotEmpty()) { context.getString(R.string.repo_no_profile) }
        return merged.values.toList()
    }

    fun resolveTarget(snapshot: DeviceSnapshot): TargetProfile =
        resolveTarget(snapshot, allowCached = false)

    /**
     * Boot-time resolution tolerates stale data: prefer the live catalog,
     * fall back to the last cached network manifest, then to bundled.
     */
    fun resolveTarget(snapshot: DeviceSnapshot, allowCached: Boolean): TargetProfile {
        return try {
            pick(loadTargets()) { it.matches(snapshot) }
        } catch (error: Throwable) {
            if (!allowCached) throw error
            pick(loadTargetsFromCache().orEmpty()) { it.matches(snapshot) }
        }
    }

    fun resolveTarget(profileId: String): TargetProfile {
        return try {
            pick(loadTargets()) { it.profileId == profileId }
        } catch (error: Throwable) {
            pick(loadTargetsFromCache().orEmpty()) { it.profileId == profileId }
        }
    }

    private inline fun pick(
        profiles: List<TargetProfile>,
        predicate: (TargetProfile) -> Boolean,
    ): TargetProfile = profiles.firstOrNull(predicate)
        ?: error(context.getString(R.string.repo_no_profile))

    private fun parseBundledManifest(): List<TargetProfile> {
        val bytes = context.assets.open(BUNDLED_MANIFEST_ASSET).use { it.readBytes() }
        return SupportManifest.parse(bytes).targets.map { profile ->
            profile.copy(
                bundled = true,
                sourceRevision = "apk-${BuildConfig.VERSION_CODE}",
            )
        }
    }

    private fun fetchRemoteTargets(): List<TargetProfile> {
        val commit = resolveMainCommit()
        val manifestBytes = downloadBytes(rawUrl(commit, MANIFEST_PATH), MAX_MANIFEST_BYTES)
        cacheManifest(manifestBytes, commit)
        return SupportManifest.parse(manifestBytes).targets.map { profile ->
            profile.copy(
                exploit = pinArtifact(profile.exploit, commit),
                kernelSu = pinArtifact(profile.kernelSu, commit),
                sourceRevision = commit,
            )
        }
    }

    private fun pinArtifact(artifact: RemoteArtifact, commit: String): RemoteArtifact {
        val source = when (val raw = artifact.source) {
            is ArtifactSource.Bundled -> raw
            is ArtifactSource.Remote -> ArtifactSource.Remote(pinArtifactUrl(raw.url, commit))
        }
        return artifact.copy(source = source)
    }

    private fun cacheManifest(bytes: ByteArray, commit: String) {
        runCatching {
            manifestCacheFile.writeBytes(bytes)
            File(context.filesDir, CACHE_COMMIT_FILE).writeText(commit, Charsets.US_ASCII)
        }
    }

    /**
     * Restores the last-good network manifest. The commit stored alongside
     * it re-pins every artifact URL and restores sourceRevision, so the
     * offline path keeps the same integrity properties as the live path
     * instead of silently degrading to mutable main-branch URLs.
     */
    private fun loadTargetsFromCache(): List<TargetProfile>? = runCatching {
        val file = manifestCacheFile
        if (!file.isFile) return null
        val profiles = SupportManifest.parse(file.readBytes()).targets
        val commit = File(context.filesDir, CACHE_COMMIT_FILE)
            .takeIf { it.isFile }
            ?.readText(Charsets.US_ASCII)
            ?.trim()
        if (commit == null || !commit.matches(Regex("[0-9a-f]{40}"))) return profiles
        profiles.map { profile ->
            profile.copy(
                exploit = pinArtifact(profile.exploit, commit),
                kernelSu = pinArtifact(profile.kernelSu, commit),
                sourceRevision = commit,
            )
        }
    }.getOrNull()

    private val manifestCacheFile: File
        get() = File(context.filesDir, "cached-targets-v3.json")

    fun download(profile: TargetProfile, onProgress: (String) -> Unit): VerifiedPayloads {
        val directory = payloadDirectory(profile).apply { mkdirs() }
        discardStaleStaging(directory, profile.sourceRevision)
        val exploit = obtainArtifact(
            artifact = profile.exploit,
            destination = File(directory, EXPLOIT_FILE_NAME),
            label = context.getString(R.string.artifact_exploit),
            onProgress = onProgress,
        )
        val kernelSu = obtainArtifact(
            artifact = profile.kernelSu,
            destination = File(directory, KSUD_FILE_NAME),
            label = context.getString(R.string.artifact_kernelsu),
            onProgress = onProgress,
        )
        return VerifiedPayloads(profile, exploit, kernelSu)
    }

    /**
     * Extracts the per-profile bundled root helper used by the tracefs
     * choreography (shell-context route and boot-time pipeline). It is an
     * APK asset rather than a feed artifact: it ships with, and refreshes
     * alongside, the app itself. Returns null for profiles without one.
     */
    fun extractRootHelper(profile: TargetProfile): File? {
        val assetPath = "artifacts/${profile.profileId}/cve-2026-43499-root"
        return runCatching {
            // The helper refreshes with the APP, not with the feed: version
            // the extracted file so an app update always replaces it.
            val target = File(
                context.filesDir,
                "root-helper-${profile.profileId}-v${BuildConfig.VERSION_CODE}",
            )
            if (!target.isFile || target.length() == 0L) {
                context.filesDir.listFiles { file ->
                    file.name.startsWith("root-helper-${profile.profileId}-v")
                }?.forEach { it.delete() }
                context.assets.open(assetPath).use { input ->
                    target.outputStream().use { output -> input.copyTo(output) }
                }
                Os.chmod(target.absolutePath, 0b111101101)
            }
            target
        }.getOrNull()
    }

    /**
     * Payloads are staged per profile. Whenever the origin revision moves
     * (new upstream commit, app update rebundling artifacts), previously
     * staged files must not be reused: releases are padded to fixed sizes,
     * so a same-length stale binary is indistinguishable from the real one
     * by size alone.
     */
    private fun discardStaleStaging(directory: File, revision: String?) {
        if (revision == null) return
        val marker = File(directory, REVISION_MARKER)
        if (marker.isFile && marker.readText(Charsets.US_ASCII).trim() == revision) return
        directory.listFiles()?.forEach { it.delete() }
        marker.writeText(revision, Charsets.US_ASCII)
    }

    /** Bundled artifacts come from APK assets; everything else over HTTP. */
    private fun obtainArtifact(
        artifact: RemoteArtifact,
        destination: File,
        label: String,
        onProgress: (String) -> Unit,
    ): File = when (val source = artifact.source) {
        is ArtifactSource.Bundled -> extractBundled(
            assetPath = source.assetPath,
            destination = destination,
            expected = artifact.size,
            label = label,
        )
        is ArtifactSource.Remote -> downloadArtifact(
            url = source.url,
            destination = destination,
            expected = artifact.size,
            label = label,
            onProgress = onProgress,
        )
    }

    private fun extractBundled(
        assetPath: String,
        destination: File,
        expected: Long,
        label: String,
    ): File {
        if (destination.isFile && destination.length() == expected) return destination
        val temporary = File(destination.parentFile, "${destination.name}.part")
        try {
            context.assets.open(assetPath).use { input ->
                copyExactly(input, temporary, expected, label)
            }
            Os.chmod(temporary.absolutePath, 0b100100100)
            promote(temporary, destination, label)
        } catch (error: Throwable) {
            temporary.delete()
            throw IllegalStateException("$label: bundled asset '$assetPath' unavailable", error)
        }
        return destination
    }

    private fun downloadArtifact(
        url: String,
        destination: File,
        expected: Long,
        label: String,
        onProgress: (String) -> Unit,
    ): File {
        if (destination.isFile && destination.length() == expected) return destination
        val temporary = File(destination.parentFile, "${destination.name}.part")
        try {
            val connection = open(url)
            connection.inputStream.use { input ->
                copyExactly(input, temporary, expected, label)
                onProgress("$label ${(expected / 1024)} KiB")
            }
            connection.disconnect()
            Os.chmod(temporary.absolutePath, 0b100100100)
            promote(temporary, destination, label)
        } catch (error: Throwable) {
            temporary.delete()
            throw error
        }
        return destination
    }

    private fun copyExactly(
        input: InputStream,
        temporary: File,
        expected: Long,
        label: String,
    ) {
        FileOutputStream(temporary).use { output ->
            var copied = 0L
            val buffer = ByteArray(BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                copied += count
                require(copied <= expected) {
                    "$label: larger than expected ($copied > $expected)"
                }
                output.write(buffer, 0, count)
            }
            require(copied == expected) {
                "$label: size mismatch ($copied != $expected)"
            }
        }
    }

    private fun promote(temporary: File, destination: File, label: String) {
        if (!temporary.renameTo(destination)) {
            destination.delete()
            check(temporary.renameTo(destination)) { "$label: staging failed" }
        }
    }

    internal fun payloadDirectory(profile: TargetProfile): File =
        File(context.filesDir, "payloads/${profile.profileId}")

    private fun resolveMainCommit(): String {
        val response = downloadBytes(COMMIT_API_URL, MAX_COMMIT_RESPONSE_BYTES)
        val commit = JSONObject(response.toString(Charsets.UTF_8))
            .getJSONObject("object")
            .getString("sha")
        require(commit.matches(Regex("[0-9a-f]{40}"))) { context.getString(R.string.repo_commit_invalid) }
        return commit
    }

    private fun rawUrl(commit: String, path: String) = "$RAW_REPOSITORY/$commit/$path"

    private fun pinArtifactUrl(url: String, commit: String): String {
        require(url.startsWith(MUTABLE_RAW_PREFIX)) { context.getString(R.string.repo_url_invalid) }
        return "$RAW_REPOSITORY/$commit/${url.removePrefix(MUTABLE_RAW_PREFIX)}"
    }

    private fun downloadBytes(url: String, maximum: Int): ByteArray {
        val connection = open(url)
        val bytes = connection.inputStream.use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                require(output.size() + count <= maximum) {
                    context.getString(R.string.repo_response_too_large)
                }
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
        connection.disconnect()
        return bytes
    }

    private fun open(url: String): HttpURLConnection =
        (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15_000
            readTimeout = 60_000
            instanceFollowRedirects = true
            setRequestProperty("User-Agent", "S25URoot/${BuildConfig.VERSION_NAME}")
            connect()
            require(responseCode == HttpURLConnection.HTTP_OK) { "HTTP $responseCode" }
        }

    companion object {
        private const val BUNDLED_MANIFEST_ASSET = "support/targets-v3.json"
        private const val MANIFEST_PATH = "support/targets-v3.json"
        private const val EXPLOIT_FILE_NAME = "cve-2026-43499-app.so"
        private const val KSUD_FILE_NAME = "ksud-s25u-kdp"
        private const val REVISION_MARKER = ".source-revision"
        private const val CACHE_COMMIT_FILE = "cached-targets-v3.commit"
        private const val COMMIT_API_URL =
            "https://api.github.com/repos/BuSung-dev/Root-My-Galaxy-Payloads/git/ref/heads/main"
        private const val RAW_REPOSITORY =
            "https://raw.githubusercontent.com/BuSung-dev/Root-My-Galaxy-Payloads"
        private const val MUTABLE_RAW_PREFIX = "$RAW_REPOSITORY/main/"
        private const val MAX_COMMIT_RESPONSE_BYTES = 16 * 1024
        private const val MAX_MANIFEST_BYTES = 256 * 1024
        private const val BUFFER_SIZE = 64 * 1024
    }
}
