package dev.busung.s25uroot

import android.os.Build
import android.system.Os
import android.system.OsConstants

data class DeviceSnapshot(
    val manufacturer: String,
    val model: String,
    val device: String,
    val kernelRelease: String,
    val kernelVersionInfo: String,
    val machine: String,
    val buildId: String,
    val fingerprint: String,
    /**
     * Samsung firmware build tag, sourced from `ro.boot.bootloader` (which
     * mirrors `ro.build.PDA` on every Samsung Galaxy build). e.g.
     * "S911BXXU9FZDP". Used as the canonical input to firmware matching
     * so the `BUILD:USER` segment inside Build.FINGERPRINT never has to
     * be parsed. The app only ships payloads for Samsung devices.
     */
    val firmwareTag: String,
    val androidRelease: String,
    val sdk: Int,
    val abi: String,
    val pageSize: Long,
) {
    val kernelVersion: String
        get() = kernelRelease.takeWhile { it.isDigit() || it == '.' }

    val kernelVersionFull: String
        get() = listOf(kernelRelease, kernelVersionInfo, machine)
            .filter(String::isNotBlank)
            .joinToString(" ")

    companion object {
        fun current(): DeviceSnapshot {
            val uname = Os.uname()
            return DeviceSnapshot(
                manufacturer = Build.MANUFACTURER,
                model = Build.MODEL,
                device = Build.DEVICE,
                kernelRelease = uname.release,
                kernelVersionInfo = uname.version,
                machine = uname.machine,
                buildId = Build.DISPLAY,
                fingerprint = Build.FINGERPRINT,
                // ro.boot.bootloader / ro.build.PDA are the canonical
                // Samsung firmware build tag, already in the exact form
                // the manifest's firmwares[] entries expect. Read via
                // reflection so the hidden SystemProperties API stays out
                // of the public compile surface.
                firmwareTag = readSystemProperty("ro.boot.bootloader")
                    .ifEmpty { readSystemProperty("ro.build.PDA") },
                androidRelease = Build.VERSION.RELEASE,
                sdk = Build.VERSION.SDK_INT,
                abi = Build.SUPPORTED_ABIS.firstOrNull().orEmpty(),
                pageSize = Os.sysconf(OsConstants._SC_PAGESIZE),
            )
        }

        private fun readSystemProperty(key: String): String = runCatching {
            Class.forName("android.os.SystemProperties")
                .getMethod("get", String::class.java, String::class.java)
                .invoke(null, key, "") as String
        }.getOrDefault("")
    }
}
