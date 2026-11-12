package de.host.sodtmobile.utils

import android.util.Base64
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec

@RunWith(RobolectricTestRunner::class)
class EncryptionManagerTest {

    private lateinit var managerA: EncryptionManager
    private lateinit var managerB: EncryptionManager

    @Before
    fun setUp() {
        managerA = EncryptionManager()
        managerB = EncryptionManager()
    }

    @After
    fun tearDown() {
        managerA.close()
        managerB.close()
    }

    @Test
    fun createEcdhKeyPair_generatesValidBase64PublicKey() {
        val remoteId: UByte = 2u
        val base64Key = managerA.createEcdhKeyPair(remoteId)

        assertNotNull(base64Key)
        assertTrue(base64Key.isNotEmpty())

        val decoded = Base64.decode(base64Key, Base64.NO_WRAP)
        assertTrue("Decoded key bytes must not be empty", decoded.isNotEmpty())
    }

    @Test
    fun keyExchange_betweenTwoClients_derivesMatchingSharedSecretsAndPhrases() {
        val clientAId: UByte = 2u
        val clientBId: UByte = 3u

        // Step 1: Both parties generate ECDH keypairs for each other
        val pubKeyA = managerA.createEcdhKeyPair(clientBId)
        val pubKeyB = managerB.createEcdhKeyPair(clientAId)

        // Verify initial state: neither has session keys yet
        assertFalse(managerA.hasClientSessionKeyFor(clientBId))
        assertFalse(managerB.hasClientSessionKeyFor(clientAId))

        // Step 2: Both parties complete the key exchange
        managerA.generateAndStoreAesSessionKeyFromKeyExchange(clientBId, pubKeyB)
        managerB.generateAndStoreAesSessionKeyFromKeyExchange(clientAId, pubKeyA)

        // Step 3: Verify session keys exist
        assertTrue(managerA.hasClientSessionKeyFor(clientBId))
        assertTrue(managerB.hasClientSessionKeyFor(clientAId))

        // Step 4: Verify that the derived shared phrases are identical
        val phraseA = managerA.getSharedPhraseForClient(clientBId)
        val phraseB = managerB.getSharedPhraseForClient(clientAId)

        assertNotNull(phraseA)
        assertNotNull(phraseB)
        assertEquals("Both clients must derive identical shared phrases", phraseA, phraseB)

        // Verify phrase format (e.g. "XX-XX-XX-XX-XX")
        val phraseRegex = Regex("^[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}$")
        assertTrue("Phrase $phraseA must match XX-XX-XX-XX-XX format", phraseRegex.matches(phraseA!!))
    }

    @Test
    fun encryptAndDecryptAesGcm_successfulRoundTrip() {
        val clientAId: UByte = 2u
        val clientBId: UByte = 3u

        val pubKeyA = managerA.createEcdhKeyPair(clientBId)
        val pubKeyB = managerB.createEcdhKeyPair(clientAId)

        managerA.generateAndStoreAesSessionKeyFromKeyExchange(clientBId, pubKeyB)
        managerB.generateAndStoreAesSessionKeyFromKeyExchange(clientAId, pubKeyA)

        // Create packet to encrypt
        val packet = SodtPackets.PingPong(code = 100)
        val encryptedData = managerA.encryptAesGcm(clientBId, packet)

        assertNotNull("Encryption should produce non-null payload", encryptedData)

        // Wire packet format: sourceId (1 byte) + targetId (1 byte) + encryptedData
        val wirePacket = byteArrayOf(clientAId.toByte(), clientBId.toByte()) + encryptedData!!
        assertEquals(
            "Encrypted wire packet must equal SodtConstants.FULL_MESSAGE_SIZE",
            SodtConstants.FULL_MESSAGE_SIZE,
            wirePacket.size,
        )

        // Client B decrypts packet from Client A
        val decryptedData = managerB.decryptAesGcm(clientAId, wirePacket)
        assertNotNull("Decryption should succeed", decryptedData)

        // Verify content
        val contentLength = ((decryptedData!![1].toInt() and 0xFF) shl 8 or (decryptedData[0].toInt() and 0xFF))
        val jsonPayload = String(decryptedData.slice(2 until (2 + contentLength)).toByteArray(), Charsets.UTF_8)
        assertTrue(jsonPayload.contains("\"type\":\"pingpong\""))
        assertTrue(jsonPayload.contains("\"code\":100"))
    }

    @Test
    fun decryptAesGcm_failsWithTamperedCiphertext() {
        val clientAId: UByte = 2u
        val clientBId: UByte = 3u

        val pubKeyA = managerA.createEcdhKeyPair(clientBId)
        val pubKeyB = managerB.createEcdhKeyPair(clientAId)

        managerA.generateAndStoreAesSessionKeyFromKeyExchange(clientBId, pubKeyB)
        managerB.generateAndStoreAesSessionKeyFromKeyExchange(clientAId, pubKeyA)

        val packet = SodtPackets.PingPong(code = 100)
        val encryptedData = managerA.encryptAesGcm(clientBId, packet)!!
        val wirePacket = byteArrayOf(clientAId.toByte(), clientBId.toByte()) + encryptedData

        // Tamper with a byte in ciphertext
        wirePacket[50] = (wirePacket[50].toInt() xor 0xFF).toByte()

        val decrypted = managerB.decryptAesGcm(clientAId, wirePacket)
        assertNull("Tampered message should fail GCM authentication and return null", decrypted)
    }

    @Test
    fun decryptAesGcm_failsWithWrongKey() {
        val clientAId: UByte = 2u
        val clientBId: UByte = 3u

        val pubKeyA = managerA.createEcdhKeyPair(clientBId)
        val pubKeyB = managerB.createEcdhKeyPair(clientAId)
        managerA.generateAndStoreAesSessionKeyFromKeyExchange(clientBId, pubKeyB)
        managerB.generateAndStoreAesSessionKeyFromKeyExchange(clientAId, pubKeyA)

        // Manager C has a different key
        val managerC = EncryptionManager()
        managerC.createEcdhKeyPair(clientAId)
        managerC.generateAndStoreAesSessionKeyFromKeyExchange(clientAId, pubKeyA)

        val packet = SodtPackets.PingPong(code = 100)
        val encryptedData = managerA.encryptAesGcm(clientBId, packet)!!
        val wirePacket = byteArrayOf(clientAId.toByte(), clientBId.toByte()) + encryptedData

        val decrypted = managerC.decryptAesGcm(clientAId, wirePacket)
        assertNull("Decryption with mismatched key should fail and return null", decrypted)
        managerC.close()
    }

    @Test(expected = IllegalArgumentException::class)
    fun decryptAesGcm_throwsOnInvalidSize() {
        val shortPacket = ByteArray(100)
        managerA.decryptAesGcm(2u, shortPacket)
    }

    @Test(expected = IllegalArgumentException::class)
    fun encryptAesGcm_throwsWhenSessionKeyMissing() {
        val packet = SodtPackets.PingPong(code = 100)
        managerA.encryptAesGcm(99u, packet)
    }

    @Test
    fun removeSessionKey_clearsSessionData() {
        val clientBId: UByte = 3u
        managerA.createEcdhKeyPair(clientBId)
        val pubKeyB = managerB.createEcdhKeyPair(2u)
        managerA.generateAndStoreAesSessionKeyFromKeyExchange(clientBId, pubKeyB)

        assertTrue(managerA.hasClientSessionKeyFor(clientBId))
        assertNotNull(managerA.getSharedPhraseForClient(clientBId))

        managerA.removeSessionKey(clientBId)

        assertFalse(managerA.hasClientSessionKeyFor(clientBId))
        assertNull(managerA.getSharedPhraseForClient(clientBId))
    }

    @Test
    fun parsePemPublicKey_parsesValidECPublicKey() {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
        val keyPair = kpg.generateKeyPair()

        val base64Key = Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP)
        val pem = """-----BEGIN PUBLIC KEY-----
$base64Key
-----END PUBLIC KEY-----"""

        val parsedKey = managerA.parsePemPublicKey(pem)
        assertNotNull(parsedKey)
        assertArrayEquals(keyPair.public.encoded, parsedKey!!.encoded)
    }

    @Test
    fun verifySignature_validAndInvalidSignatures() {
        // Generate Server ECDSA identity keypair
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
        val serverIdentityKeyPair = kpg.generateKeyPair()

        val serverCertPem = """-----BEGIN PUBLIC KEY-----
${Base64.encodeToString(serverIdentityKeyPair.public.encoded, Base64.NO_WRAP)}
-----END PUBLIC KEY-----"""

        // Client initiates discovery by creating its ECDH keypair for SERVER_ID
        val clientEcdhPubBase64 = managerA.createEcdhKeyPair(SodtConstants.SERVER_ID)
        val clientEcdhPubBytes = Base64.decode(clientEcdhPubBase64, Base64.NO_WRAP)

        // Server generates its own ECDH keypair
        val serverEcdhKeyPair = kpg.generateKeyPair()
        val serverEcdhPubBytes = serverEcdhKeyPair.public.encoded
        val serverEcdhPubBase64 = Base64.encodeToString(serverEcdhPubBytes, Base64.NO_WRAP)

        val assignedClientId: UByte = 5u
        val toSign = clientEcdhPubBytes + serverEcdhPubBytes + assignedClientId.toByte()

        // Sign with SHA256withECDSA (IEEE P1363 format: 64 bytes r||s)
        val signer = Signature.getInstance("SHA256withECDSAinP1363Format")
        signer.initSign(serverIdentityKeyPair.private)
        signer.update(toSign)
        val p1363Signature = signer.sign()

        val validDiscoveryPayload = SodtPackets.DiscoveryPayload(
            id = assignedClientId,
            code = 200,
            publicKey = serverEcdhPubBase64,
            signature = Base64.encodeToString(p1363Signature, Base64.DEFAULT),
        )

        assertTrue(
            "Signature verification should succeed for valid server signature",
            managerA.verifySignature(serverCertPem, validDiscoveryPayload),
        )

        // Corrupt signature
        val corruptedSignature = p1363Signature.clone()
        corruptedSignature[0] = (corruptedSignature[0].toInt() xor 0xFF).toByte()
        val invalidDiscoveryPayload = validDiscoveryPayload.copy(
            signature = Base64.encodeToString(corruptedSignature, Base64.DEFAULT),
        )

        assertFalse(
            "Signature verification must fail for corrupted signature",
            managerA.verifySignature(serverCertPem, invalidDiscoveryPayload),
        )
    }
}
