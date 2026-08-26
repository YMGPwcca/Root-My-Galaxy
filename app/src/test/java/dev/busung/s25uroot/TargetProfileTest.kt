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
        // offsets were built for one specific firmware build. The match
        // is on the Samsung firmware tag (ro.boot.bootloader /
        // ro.build.PDA) — not the fingerprint.
        val pinned = profile.copy(
            models = setOf("SM-S911B"),
            kernelVersions = setOf("5.15.189"),
            firmwares = setOf("S911BXXU9FZDP"),
        )
        assertTrue(
            pinned.matches(
                snapshot(
                    "SM-S911B",
                    "5.15.189-android13-8-33413713-abS911BXXU9FZDP",
                    firmwareTag = "S911BXXU9FZDP",
                ),
            ),
        )
        assertFalse(
            pinned.matches(
                snapshot(
                    "SM-S911B",
                    "5.15.189-android13-8-33413713-abS911BXXU6FYD8",
                    firmwareTag = "S911BXXU6FYD8",
                ),
            ),
        )
    }

    @Test
    fun emptyFirmwareSetAcceptsAnyBuild() {
        // Profiles without a firmwares[] constraint keep matching on
        // model + kernel alone — the same contract the app shipped
        // before firmware pinning was introduced.
        assertTrue(profile.matches(snapshot("SM-S931B", "6.6.98-android15-8-build", firmwareTag = "S931BXXU6ABC1")))
    }

    @Test
    fun rejectsUnlistedModelOrKernelVersion() {
        assertFalse(profile.matches(snapshot("SM-S928B", "6.6.98-android15-8-build")))
    }

    private fun snapshot(
        model: String,
        kernelRelease: String,
        firmwareTag: String = "",
    ) = DeviceSnapshot(
        manufacturer = "samsung",
        model = model,
        device = "unused",
        kernelRelease = kernelRelease,
        kernelVersionInfo = "#1 SMP PREEMPT",
        machine = "aarch64",
        buildId = "BP4A.251205.006.S938BCZG1",
        fingerprint = "samsung/example",
        firmwareTag = firmwareTag,
        androidRelease = "16",
        sdk = 36,
        abi = "arm64-v8a",
        pageSize = 4096,
    )
}
