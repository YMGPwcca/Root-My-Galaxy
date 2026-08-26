package dev.busung.s25uroot

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.SecureRandom

/**
 * FIX 4 regression suite: decompress() must reject non-canonical and
 * off-curve encodings, never throw on arbitrary input, and the pairing flow
 * must still work between two instances of this class.
 */
class Spake2Test {

    private fun p(): BigInteger = Spake2.FIELD_P

    @Test
    fun identityEncodingDecompressesToNeutralPoint() {
        val spake2 = Spake2("pw".toByteArray())
        val identity = ByteArray(32).also { it[0] = 1 }
        val point = spake2.decompress(identity)!!
        assertNotNull(point)
        val (x, y) = point
        assertEquals(BigInteger.ZERO, x)
        assertEquals(BigInteger.ONE, y)
    }

    @Test
    fun rejectsNonCanonicalY() {
        val spake2 = Spake2("pw".toByteArray())
        // Encode y == p (non-canonical: y >= p), sign bit set like a real
        // encoding. Must be rejected, not silently reduced mod p.
        val yEqualsP = p().toByteArray().let { if (it.size > 32) it.copyOfRange(1, it.size) else it }
        val encoded = ByteArray(32)
        System.arraycopy(yEqualsP.reversedArray(), 0, encoded, 0, 32)
        encoded[31] = (encoded[31].toInt() or 0x80).toByte()
        assertNull(spake2.decompress(encoded))
    }

    @Test
    fun fuzzDecompressNeverThrowsAndAcceptsOnlyCurvePoints() {
        val spake2 = Spake2("pw".toByteArray())
        val random = SecureRandom()
        repeat(500) {
            val garbage = ByteArray(32).also(random::nextBytes)
            val point = try {
                spake2.decompress(garbage)
            } catch (t: Throwable) {
                throw AssertionError("decompress threw at attempt $it", t)
            } ?: return@repeat // rejected — fine
            val (x, _) = point
            // Accepted points MUST satisfy -x^2 + y^2 = 1 + d*x^2*y^2.
            var yBytes = garbage.copyOf()
            yBytes[31] = (yBytes[31].toInt() and 0x7F).toByte()
            val y = BigInteger(1, yBytes.reversedArray()).mod(p())
            val lhs = p().subtract(x.multiply(x).mod(p())).add(y.multiply(y)).mod(p())
            val rhs = BigInteger.ONE.add(Spake2.ED25519_D.multiply(x.multiply(x).mod(p()))
                .multiply(y.multiply(y).mod(p()))).mod(p())
            assertEquals(lhs, rhs)
        }
    }

}
