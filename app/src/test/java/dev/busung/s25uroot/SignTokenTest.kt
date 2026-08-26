package dev.busung.s25uroot

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.RSAPublicKey

/**
 * Proves signToken() produces exactly what adbd verifies:
 * RSASSA-PKCS1-v1_5 over DigestInfo(SHA-1) || raw token — the token IS the
 * digest (BoringSSL RSA_verify(NID_sha1, token)), NOT a double hash.
 */
class SignTokenTest {

    @Test
    fun signatureRecoversDigestInfoOverRawToken() {
        val keyPair = KeyPairGenerator.getInstance("RSA")
            .apply { initialize(2048) }
            .generateKeyPair()
        val token = ByteArray(20) { it.toByte() } // 0x00..0x13, token-sized

        val signature = LocalAdbClient.signToken(keyPair.private, token)

        // Raw math: m = sig^e mod n, then strip PKCS#1 v1.5 type-1 padding.
        val public = keyPair.public as RSAPublicKey
        val recovered = BigInteger(1, signature)
            .modPow(public.publicExponent, public.modulus)
        val keyLength = (public.modulus.bitLength() + 7) / 8
        var raw = recovered.toByteArray()
        if (raw.size > keyLength) raw = raw.copyOfRange(1, raw.size) // sign byte
        val em = ByteArray(keyLength - raw.size) + raw
        // Encoded block: 00 01 FF..FF 00 || digestInfo — the leading 00 is
        // implicit after the BigInteger round-trip when byte 0x01 < 0x80.
        assertEquals(0, em[0].toInt())
        assertEquals(1, em[1].toInt())
        var i = 2
        while (em[i] == 0xFF.toByte()) i++
        assertEquals(0, em[i].toInt())

        val digestInfo = byteArrayOf(
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03,
            0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
        ) + token
        assertEquals(digestInfo.toList(), em.copyOfRange(i + 1, em.size).toList())

        // Regression tripwire: the broken double-hash variant must differ.
        val wrong = Signature.getInstance("SHA1withRSA").apply {
            initSign(keyPair.private)
            update(token)
        }.sign()
        assertFalse(signature.contentEquals(wrong))
    }
}
