package dev.busung.s25uroot

import org.json.JSONArray
import org.json.JSONObject

/**
 * Where a single payload binary comes from. A remote artifact is fetched
 * over HTTP and pinned to the payload repository commit it was resolved
 * against; a bundled artifact is extracted from the APK's own assets.
 */
sealed class ArtifactSource {
    data class Remote(val url: String) : ArtifactSource()
    data class Bundled(val assetPath: String) : ArtifactSource()
}

data class RemoteArtifact(
    val source: ArtifactSource,
    val size: Long,
)

data class TargetProfile(
    val profileId: String,
    val displayName: String,
    val models: Set<String>,
    val kernelVersions: Set<String>,
    val exploit: RemoteArtifact,
    val kernelSu: RemoteArtifact,
    /**
     * Kernel address-leak strategy used by the exploit build. Profiles
     * leaking through tracefs need a shell-uid context (wireless ADB);
     * profiles without a slide source run directly from the app process.
     */
    val slideSource: String? = null,
    /**
     * Firmware build tags the payload is validated against (e.g.
     * "S911BXXU9FZDP"), matched against the device fingerprint. Empty set
     * = no firmware constraint, which keeps upstream profiles (that do
     * not ship the field) matching exactly as before.
     */
    val firmwares: Set<String> = emptySet(),
    /** True when set: bundled entries win manifest merges over remote ones. */
    val bundled: Boolean = false,
    /**
     * Identifies the exact origin of this profile's binaries (payload repo
     * commit for network profiles, APK build for bundled ones). Staged
     * payloads are invalidated whenever it changes, so a same-size rebuild
     * can never keep running in place of the current release.
     */
    val sourceRevision: String? = null,
) {
    init {
        require(models.isNotEmpty()) { "Payload must support at least one model" }
        require(kernelVersions.isNotEmpty()) { "Payload must support at least one kernel version" }
    }

    /** Exploit needs a shell context (wireless ADB bootstrap) to leak. */
    val requiresShellContext: Boolean
        get() = slideSource.equals("tracefs", ignoreCase = true)

    fun matchesDevice(snapshot: DeviceSnapshot): Boolean =
        models.any { it.equals(snapshot.model, ignoreCase = true) }


    fun matchesKernelVersion(snapshot: DeviceSnapshot): Boolean =
        snapshot.kernelVersion in kernelVersions

    /**
     * Firmware-specific payloads (kernel offsets baked for one build) must
     * never run on a different build just because model and kernel match.
     */
    fun matchesFirmware(snapshot: DeviceSnapshot): Boolean =
        // The app only ships Samsung payloads, and Samsung's firmware
        // build tag is exposed cleanly via ro.boot.bootloader /
        // ro.build.PDA — no fingerprint parsing, no prefix-collision
        // surface. Empty set on the profile = no firmware constraint.
        firmwares.isEmpty() ||
            firmwares.any { it.equals(snapshot.firmwareTag, ignoreCase = true) }


    fun matches(snapshot: DeviceSnapshot): Boolean =
        matchesDevice(snapshot) && matchesKernelVersion(snapshot) && matchesFirmware(snapshot)

    val supportedModels: String
        get() = models.joinToString()

    val supportedKernelVersions: String
        get() = kernelVersions.joinToString()
}

data class SupportManifest(
    val schemaVersion: Int,
    val targets: List<TargetProfile>,
) {
    companion object {
        fun parse(bytes: ByteArray): SupportManifest {
            val root = JSONObject(bytes.toString(Charsets.UTF_8))
            val schemaVersion = root.getInt("schemaVersion")
            require(schemaVersion == 3) { "Unsupported support manifest schema" }
            val payloadsJson = root.getJSONArray("payloads")
            val payloads = buildList {
                for (index in 0 until payloadsJson.length()) {
                    val payload = payloadsJson.getJSONObject(index)
                    add(
                        TargetProfile(
                            profileId = payload.getString("payloadId"),
                            displayName = payload.getString("displayName"),
                            models = payload.getJSONArray("models").strings(),
                            kernelVersions = payload.getJSONArray("kernelVersions").strings(),
                            exploit = parseArtifact(payload.getJSONObject("exploit")),
                            kernelSu = parseArtifact(payload.getJSONObject("kernelsu")),
                            firmwares = payload.optJSONArray("firmwares")?.strings() ?: emptySet(),
                            slideSource = payload.optString("slideSource").takeIf { it.isNotEmpty() }.also {
                                // Fail closed: an unknown slide source must
                                // reject the profile instead of silently
                                // running it from the wrong context.
                                require(it == null || it.equals("tracefs", ignoreCase = true)) {
                                    "Unsupported slideSource '$it' in profile ${payload.getString("payloadId")}"
                                }
                            },
                        ),
                    )
                }
            }
            return SupportManifest(schemaVersion, payloads)
        }

        private fun parseArtifact(artifact: JSONObject): RemoteArtifact {
            val size = artifact.getLong("size")
            return when {
                artifact.has("asset") -> RemoteArtifact(
                    source = ArtifactSource.Bundled(artifact.getString("asset")),
                    size = size,
                )
                else -> RemoteArtifact(
                    source = ArtifactSource.Remote(artifact.getString("url")),
                    size = size,
                )
            }
        }

        private fun JSONArray.strings(): Set<String> = buildSet {
            for (index in 0 until length()) add(getString(index))
        }
    }
}
