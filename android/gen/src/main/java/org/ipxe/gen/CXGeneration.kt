package org.ipxe.gen

import org.spongycastle.crypto.engines.AESEngine
import org.spongycastle.crypto.prng.EntropySource
import org.spongycastle.crypto.prng.EntropySourceProvider
import org.spongycastle.crypto.prng.drbg.CTRSP800DRBG
import java.nio.ByteBuffer
import java.util.*
import kotlin.experimental.and
import kotlin.experimental.inv
import kotlin.experimental.or


private const val UUID_BYTES_LEN = 16


/**
 * Instantiate a Type 1 Generator as defined by sections 3.1 and 3.2 of the CX specification.
 */
fun cxGen1(seed: ByteArray): CXGenerator<Type1> {
    return CXGenerator(
        FixedDRBG(
            Type1, Seed.fromBytes(
                Type1, seed
            )
        )
    )
}

/**
 * Instantiate a Type 2 Generator as defined by sections 3.1 and 3.1 of the CX specification.
 */
fun cxGen2(seed: ByteArray): CXGenerator<Type2> {
    return CXGenerator(
        FixedDRBG(
            Type2, Seed.fromBytes(
                Type2, seed
            )
        )
    )
}


/**
 * Representation of Generator Types as specified by section 3.1 of the CX specification.
 * @param keySize [Int] AES cypher key size (bits).
 * @param securityStrength [Int] Required security strength (bits).
 * @param entropyInputLen [Int] Required entropy input length (bits).
 * @param nonceLen [Int] Required nonce length (bits).
 * @param maxIterations [Int] Maximum number of permitted generator iterations.
 */
sealed class GeneratorType(
    val keySize: Int,
    val securityStrength: Int,
    val entropyInputLen: Int,
    val nonceLen: Int,
    val maxIterations: Int
) {
    val seedLen: Int = entropyInputLen + nonceLen
}

object Type1 : GeneratorType(
    128, 128, 16, 8, 2048
)

object Type2 : GeneratorType(
    256, 256, 32, 16, 2048
)


/**
 * Contact Identifier Generator as described by section 3 of the CX specification.
 *
 * This should be instantiated via one of the public helper functions e.g. [cxGen1] to ensure the
 * correct ownership and usage of the underlying generator and seed values (hence the `internal`
 * constructor).
 */
class CXGenerator<T : GeneratorType> internal constructor(private val rng: FixedDRBG<T>) {
    fun iterate(): UUID {
        // Generate next bytes to base Contact Identifier on
        val bytes = ByteArray(UUID_BYTES_LEN)
        rng.generate(bytes)
        // Set fixed bits for version 4 UUID
        bytes[8] = (bytes[8] and 0xc0.toByte().inv()).or(0x80.toByte()) // clock_seq_hi_and_reserved
        bytes[6] = (bytes[6] and 0xf0.toByte().inv()).or(0x40.toByte()) // time_hi_and_version
        // Instantiate a Java UUID - no direct constructor from a single ByteArray is provided,
        // instead the API for manual UUID instantiation requires specifying two Long values
        val buf = ByteBuffer.wrap(bytes) // Wrap in a ByteBuffer to avoid manual parsing of Longs
        val high = buf.long // e.g. side-effectful buf.getLong() advances internal state of buf
        val low = buf.long
        return UUID(high, low)
    }
}


/**
 * Represents a seed value constructed from some fixed entropy and a nonce value as described in
 * section 3 of the CX specification. The primary role of this class is to ensure the invariants
 * specified for seed length, entropy length and nonce length are upheld.
 */
class Seed<T : GeneratorType> internal constructor(
    type: T,
    val entropyInput: ByteArray,
    val nonce: ByteArray
) {
    init {
        if (entropyInput.size != type.entropyInputLen) {
            throw IllegalArgumentException(
                "entropyInput length must match the value specified by the Generator Type"
            )
        }
        if (nonce.size != type.nonceLen) {
            throw IllegalArgumentException(
                "nonce length must match the value specified by the Generator Type"
            )
        }
    }

    companion object {
        /**
         * Instantiate a [Seed] from a complete seed value from which [entropyInput] and [nonce]
         * will be parsed according to the given [GeneratorType].
         */
        fun <T : GeneratorType> fromBytes(type: T, seed: ByteArray): Seed<T> {
            if (seed.size != type.seedLen) {
                throw IllegalArgumentException(
                    "seed length must match the value specified by the Generator Type"
                )
            }
            return Seed(
                type,
                seed.copyOfRange(0, type.entropyInputLen),
                seed.copyOfRange(type.entropyInputLen, type.seedLen)
            )
        }
    }
}


class GeneratorExhaustedException(message: String) : Exception(message)


/**
 * DRBG with a fixed entropy source and maximum iteration limit as specified by section 3 of the
 * CX specification.
 */
class FixedDRBG<T : GeneratorType> internal constructor(
    private val type: T,
    private val seed: Seed<T>
) {
    private val entropySource =
        FixedEntropySourceProvider(seed.entropyInput).get(seed.entropyInput.size * 8)
    private var currentIterations = 0

    private val rng = when (type as GeneratorType) {
        Type1 -> {
            CTRSP800DRBG(
                AESEngine(),
                type.securityStrength,
                type.securityStrength,
                entropySource,
                null,
                seed.nonce
            )
        }
        Type2 -> {
            CTRSP800DRBG(
                AESEngine(),
                type.securityStrength,
                type.securityStrength,
                entropySource,
                null,
                seed.nonce
            )
        }
    }

    /**
     * Populate a passed in array with randomly generated data.
     *
     * @throws [GeneratorExhaustedException] If the iteration limit for [type] has been reached.
     */
    fun generate(output: ByteArray) {
        if (currentIterations >= type.maxIterations) {
            throw GeneratorExhaustedException("${type.maxIterations} iteration limit reached")
        }
        currentIterations += 1
        rng.generate(output, null, false)
    }
}


class EntropySourceExhaustedException(message: String) : Exception(message)


/**
 * Generates 'entropy' from a pre-determined sequence of bytes. Intended to satisfy the
 * [EntropySource] interface required by the SpongyCastle PRNGs whilst with a pre-computed
 * entropy input as per the CX specification.
 */
class FixedEntropySourceProvider constructor(private val bytes: ByteArray) : EntropySourceProvider {

    /**
     * Create an [EntropySource] that 'generates' entropy as sequential [bitsRequired] size chunks
     * from [bytes].
     *
     * @param bitsRequired [Int] Number of bits to return in each generated 'chunk' of entropy.
     * @throws [IllegalArgumentException] If [bitsRequired] is > than the available number of bits.
     */
    override fun get(bitsRequired: Int): EntropySource {
        val nBytes = bitsRequired / 8
        if (nBytes > bytes.size) {
            throw IllegalArgumentException(
                "bitsRequired must be less than the number of bits available in the source data: "
                        + "bitsRequired=$bitsRequired, available=${bytes.size * 8}"
            )
        }

        return object : EntropySource {
            var nextBytesIndex = 0
            override fun isPredictionResistant(): Boolean {
                return false
            }

            /**
             * @throws [EntropySourceExhaustedException]
             */
            override fun getEntropy(): ByteArray {
                val rv = ByteArray(nBytes)
                try {
                    System.arraycopy(bytes, nextBytesIndex, rv, 0, rv.size)
                } catch (e: IndexOutOfBoundsException) {
                    throw EntropySourceExhaustedException("Available entropy bytes already requested")
                }
                nextBytesIndex += nBytes
                return rv
            }

            override fun entropySize(): Int {
                return bitsRequired
            }
        }
    }
}