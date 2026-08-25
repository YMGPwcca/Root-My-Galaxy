package dev.busung.s25uroot

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TargetProfileTest {
    private val profile = TargetProfile(
        profileId = "galaxy-s25-series-kernel-6.6.98",
        displayName = "Galaxy S25 series",
        models = setOf("SM-S931B", "SM-S938N"),
        kernelVersions = setOf("6.6.98"),
        exploit = RemoteArtifact(ArtifactSource.Remote("https://example.invalid/exploit"), 1),
        kernelSu = RemoteArtifact(ArtifactSource.Remote("https://example.invalid/ksud"), 1),
    )

    @Test
    fun matchesRegionalS25OnSameKernelVersion() {
        assertTrue(profile.matches(snapshot("SM-S931B", "6.6.98-android15-8-build-a")))
        assertTrue(profile.matches(snapshot("SM-S938N", "6.6.98-android15-8-build-b")))
    }

    @Test
    fun firmwarePinnedProfileRejectsOtherFirmwareBuilds() {
        // Model + kernel alone must NOT select a payload whose kernel
        // offsets were built for one specific firmware build.
        val pinned = profile.copy(
            models = setOf("SM-S911B"),
            kernelVersions = setOf("5.15.189"),
            firmwares = setOf("S911BXXU9FZDP"),
        )
        assertTrue(
            pinned.matches(
                snapshot(
                    "SM-S911B",
                    "5.15.189",
                    fingerprint = "samsung/dm1qdm1q/16/BP4A.251205.006/S911BXXU9FZDP/dm1q:16/user/release-keys",
                ),
            ),
        )
        assertFalse(
            pinned.matches(
                snapshot(
                    "SM-S911B",
                    "5.15.189",
                    fingerprint = "samsung/dm1qdm1q/16/BP4A.250305.005/S911BXXU6FYD8/dm1q:16/user/release-keys",
                ),
            ),
        )
    }

    @Test
    fun rejectsUnlistedModelOrKernelVersion() {
        assertFalse(profile.matches(snapshot("SM-S928B", "6.6.98-android15-8-build")))
        assertFalse(profile.matches(snapshot("SM-S938N", "6.6.102-android15-8-build")))
    }

    private fun snapshot(
        model: String,
        kernelRelease: String,
        fingerprint: String = "samsung/example",
    ) = DeviceSnapshot(
        manufacturer = "samsung",
        model = model,
        device = "unused",
        kernelRelease = kernelRelease,
        kernelVersionInfo = "#1 SMP PREEMPT",
        machine = "aarch64",
        buildId = "BP4A.251205.006.S938BCZG1",
        fingerprint = fingerprint,
        androidRelease = "16",
        sdk = 36,
        abi = "arm64-v8a",
        pageSize = 4096,
    )
}
