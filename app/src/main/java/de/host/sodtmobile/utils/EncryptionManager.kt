package de.host.sodtmobile.utils

import android.security.keystore.KeyProtection
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.SecureRandom

import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement
import javax.crypto.SecretKey
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The `EncryptionManager` class handles encryption and decryption operations for secure communication.
 * It supports AES encryption for client-server and client-client communication
 * Additionally, it provides methods for ECDH key exchange to
 * derive shared secrets for symmetric encryption.
 *
 * Key Features:
 * - AES encryption with GCM mode for secure data transfer.
 * - ECDH key exchange for deriving shared secrets between clients.
 * - Management of session keys using Android KeyStore.
 * - Management of shared phrases for client to client key exchange verification.
 */
class EncryptionManager() {

    private val logTag = "EncryptionManager"
    private val ecCurve = "secp256r1"
    private val aesAlgorithm = "AES/Gcm/NoPadding"

    /**
     * KeyStore for storing aes session keys.
     */
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }
    private val keyStoreAlias = "sodt_aes_session_key"
    private val ecdhSessionKeyGenerators = mutableMapOf<UByte, KeyPair>()
    private val sharedPhraseMap = mutableMapOf<UByte, String>()

    private fun storeSessionKey(clientId: UByte, secretKey: SecretKey) {
        val alias = keyStoreAlias + clientId
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias)
        }
        val protection = KeyProtection.Builder(
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .build()
        keyStore.setEntry(alias, KeyStore.SecretKeyEntry(secretKey), protection)
    }

    private fun getSessionKey(clientId: UByte): SecretKey? {
        val alias = keyStoreAlias + clientId
        if (!keyStore.containsAlias(alias)) return null
        return keyStore.getKey(alias, null) as? SecretKey
    }

    fun removeSessionKey(clientId: UByte) {
        val alias = keyStoreAlias + clientId
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias)
        }
        ecdhSessionKeyGenerators.remove(clientId)
        sharedPhraseMap.remove(clientId)
    }

    fun hasClientSessionKeyFor(clientId: UByte): Boolean {
        return keyStore.containsAlias(keyStoreAlias + clientId)
    }

    /**
     * Returns the shared phrase for the given client ID.
     * @param clientId The ID of the client.
     * @return The shared phrase for the client or null if not found.
     */
    fun getSharedPhraseForClient(clientId: UByte): String? {
        return sharedPhraseMap[clientId]
    }

    /**
     * Converts a key pair to a base64 encoded string.
     */
    private fun getEcdhKeyAsBase64(keyPair: KeyPair): String {
        // Get the public key in X.509 format
        return Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP)
    }

    /**
     * Creates a new ECDH key pair for the given remote ID.
     * The key pair is stored in the ecdhSessionKeyGenerators map and also returned
     * @param remoteId The ID of the remote client.
     * @return The base64 encoded public key of the generated key pair.
     */
    fun createEcdhKeyPair(remoteId: UByte): String{
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(ECGenParameterSpec(ecCurve), SecureRandom())
        ecdhSessionKeyGenerators[remoteId] = keyPairGenerator.generateKeyPair()
        return getEcdhKeyAsBase64(ecdhSessionKeyGenerators[remoteId]!!) // !! is safe because it is just added above
    }

    /**
     * Derives a shared secret from a base64 encoded ECDH public key.
     * @param remoteId The ID of the remote client.
     * @param base64otherPublicKey The base64 encoded public key of the other client.
     */
    private fun deriveSharedSecretFromBase64Key(remoteId: UByte, base64otherPublicKey: String): ByteArray {
        // get matching key pair from generator
        val ecdhKeyPair = ecdhSessionKeyGenerators[remoteId]
        requireNotNull(ecdhKeyPair){"ECDH key pair not found for client ID: $remoteId."}
        // get otherPublicKey keyBytes
        val keyBytes = Base64.decode(base64otherPublicKey, Base64.NO_WRAP)
        // Convert to ECDH public key
        val keySpec = X509EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance("EC").apply {
            ECGenParameterSpec(ecCurve)
        }
        val remotePublicKey: PublicKey = keyFactory.generatePublic(keySpec)
        // generate shared secret
        val keyAgreement = KeyAgreement.getInstance("ECDH")
        keyAgreement.init(ecdhKeyPair.private)
        keyAgreement.doPhase(remotePublicKey, true)

        return keyAgreement.generateSecret() // raw shared secret
    }

    /**
     * Derives an AES key and IV from the shared secret.
     * The key is derived using SHA-256, and the IV is derived from the key halves.
     * @param sharedSecret The raw shared secret byte array.
     * @return AesKeyMaterial containing the derived AES key and IV.
     */
    private fun deriveAesKeyFromSharedSecret(sharedSecret: ByteArray): SecretKey {
        val sha256 = MessageDigest.getInstance("SHA-256")
        val derivedKey = sha256.digest(sharedSecret) // 32-byte key

        val secretKey = SecretKeySpec(derivedKey, "AES")
        return secretKey
    }

    /**
     * Generates and stores an AES session key from the key exchange.
     * Also generates and stores a shared phrase for the client.
     * @param remoteId The ID of the remote client.
     * @param otherKeyBase64 The base64 encoded public key of the other client.
     */
    fun generateAndStoreAesSessionKeyFromKeyExchange(remoteId: UByte, otherKeyBase64: String) {
        val sharedSecret = deriveSharedSecretFromBase64Key(remoteId, otherKeyBase64)
        val aesSessionKey = deriveAesKeyFromSharedSecret(sharedSecret)
        storeSessionKey(remoteId, aesSessionKey)
        sharedPhraseMap[remoteId] = getSharedPhrase(remoteId, otherKeyBase64)
    }

    /**
     * Encrypts a message using AES-GCM.
     * @param remoteId The ID of the remote client. Used to find the session key.
     * @param baseMessage The message to encrypt.
     */
    fun encryptAesGcm(remoteId: UByte, baseMessage: SodtPackets.IBasePacket): ByteArray? {
        // prepare
        val toEncrypt = baseMessage.toByteArray()
        val aes = getSessionKey(remoteId)
        requireNotNull(aes){"AES session key not found for client ID: $remoteId."}
        val cipher = Cipher.getInstance(aesAlgorithm)
        cipher.init(Cipher.ENCRYPT_MODE, aes)
        // encrypt
        val nonce = cipher.iv
        val encrypted = cipher.doFinal(toEncrypt)
        val tag = encrypted.slice(encrypted.size - SodtConstants.TAG_SIZE until encrypted.size).toByteArray()
        // remove tag, because in sodt protocol its at the beginning of the message
        val encryptedWithoutTag = encrypted.slice(0 until encrypted.size - SodtConstants.TAG_SIZE)
        return nonce + tag + encryptedWithoutTag
    }

    /**
     * Decrypts a message using AES-GCM.
     * @param clientId The ID of the client that sent the message.
     * @param receivedData The encrypted message. Must be exactly SodtConstants.FULL_MESSAGE_SIZE bytes long.
     */
    fun decryptAesGcm(clientId: UByte, receivedData: ByteArray): ByteArray? {
        require(receivedData.size == SodtConstants.FULL_MESSAGE_SIZE) {
            "Data size must be exactly ${SodtConstants.FULL_MESSAGE_SIZE} bytes, but was ${receivedData.size}"
        }

        // prepare decryption and get relevant data
        val ciphertext = receivedData.slice(SodtConstants.HEADER_SIZE_WITHOUT_CONTENT_LENGTH until receivedData.size).toByteArray()
        val tag = receivedData.slice((SodtConstants.ID_SIZE + SodtConstants.NONCE_SIZE) until (SodtConstants.ID_SIZE + SodtConstants.NONCE_SIZE + SodtConstants.TAG_SIZE)).toByteArray()
        val nonce = receivedData.slice(SodtConstants.ID_SIZE until (SodtConstants.ID_SIZE + SodtConstants.NONCE_SIZE)).toByteArray()
        val cipher = Cipher.getInstance(aesAlgorithm)
        // decrypt
        try {
            val aes = getSessionKey(clientId)
            cipher.init(Cipher.DECRYPT_MODE, aes, GCMParameterSpec(128, nonce))
            // cipher expects tag at the end of the message, but sodt protocol puts tag before message, so reverse it
            return cipher.doFinal(ciphertext + tag)
        }
        catch (e: Exception) {
            Log.e(logTag, "Decryption failed for client ID: $clientId", e)
        }
        return null
    }

    /**
     * Derives a shared phrase from the shared secret.
     * @param remoteId The ID of the remote client.
     * @param otherKeyBase64 The base64 encoded public key of the other client.
     * @return The derived shared phrase in hex format "XX-XX-XX-XX-XX"
     */
    private fun getSharedPhrase(remoteId: UByte, otherKeyBase64: String): String {
        val sharedSecret = deriveSharedSecretFromBase64Key(remoteId, otherKeyBase64)
        val sha256 = MessageDigest.getInstance("SHA-256")
        val derivedKey = sha256.digest(sharedSecret) // 32-byte key
        val keyInHex = derivedKey.joinToString("") { "%02X".format(it) }
        val keyParts = keyInHex.chunked(2) // split into pairs of 2 characters
        // return 0th, 4th, 8th, 16th, 31th pair with hyphens
        return "${keyParts[0]}-${keyParts[4]}-${keyParts[8]}-${keyParts[16]}-${keyParts[31]}"
    }

    /**
     * Parses a PEM encoded public key into a PublicKey object.
     * @param pemString The PEM encoded public key.
     */
    fun parsePemPublicKey(pemString: String): PublicKey? {
         val publicKeyPem = pemString
             .replace("-----BEGIN PUBLIC KEY-----", "")
             .replace("-----END PUBLIC KEY-----", "")
             .replace("\\s".toRegex(), "") // Removes \n, \r, and spaces

         // 2. Base64 decode the resulting string
         val encoded = Base64.decode(publicKeyPem, Base64.DEFAULT)

         // 3. Create a KeySpec and generate the Public Key using KeyFactory
         val keySpec = X509EncodedKeySpec(encoded)
         // Note: Use "EC" because your C# code uses ECDsa.Create
         val keyFactory = KeyFactory.getInstance("EC")

         return keyFactory.generatePublic(keySpec)
    }

    /**
     * Verifies the signature of a discovery response.
     * @param certificate The certificate of the server.
     * @param dataPacket The discovery response packet to verify.
     */
    fun verifySignature(certificate: String, dataPacket: SodtPackets.DiscoveryPayload): Boolean {
        // prepare certificate
        val publicKey = parsePemPublicKey(certificate) ?: return false
        // prepare signature verification
        val localEcdhKey = ecdhSessionKeyGenerators[SodtConstants.SERVER_ID]?.public?.encoded ?: return false
        val remoteEcdhKey = try {
            Base64.decode(dataPacket.publicKey, Base64.NO_WRAP)
        } catch (_: Exception) {
            return false
        }
        val toVerify = localEcdhKey + remoteEcdhKey + dataPacket.id.toByte()

        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initVerify(publicKey)
        signature.update(toVerify)

        return try {
            val signatureBytes = Base64.decode(dataPacket.signature, Base64.DEFAULT)
            val isValid = signature.verify(ieeeP1363ToDer(signatureBytes))
            if (!isValid) {
                Log.e(logTag, "Signature verification failed")
            }
            isValid
        } catch (e: Exception) {
            Log.e(logTag, "Error during signature verification", e)
            false
        }
    }

    /**
     * Cleans up all session keys and shared phrases.
     */
    fun close(){
        val aliases = keyStore.aliases()
        val sessionAliases = mutableListOf<String>()
        while (aliases.hasMoreElements()) {
            val alias = aliases.nextElement()
            if (alias.startsWith(keyStoreAlias)) {
                sessionAliases.add(alias)
            }
        }
        for (alias in sessionAliases) {
            keyStore.deleteEntry(alias)
        }
        ecdhSessionKeyGenerators.clear()
        sharedPhraseMap.clear()
    }

    /**
     * Converts an IEEE P1363 signature to DER format.
     * SODT uses IEEE P1363 for its signature but Android uses DER.
     * This code is AI generated.
     */
    private fun ieeeP1363ToDer(ieeeSignature: ByteArray): ByteArray {
        require(ieeeSignature.size % 2 == 0) { "Invalid IEEE P1363 signature length" }
        val halfLength = ieeeSignature.size / 2

        val r = ieeeSignature.copyOfRange(0, halfLength)
        val s = ieeeSignature.copyOfRange(halfLength, ieeeSignature.size)

        fun encodeDerInteger(bytes: ByteArray): ByteArray {
            // Führende 0x00 Bytes entfernen
            var startIdx = 0
            while (startIdx < bytes.size - 1 && bytes[startIdx] == 0.toByte()) {
                startIdx++
            }
            val trimmed = bytes.copyOfRange(startIdx, bytes.size)

            // Sign-Bit Handling: Wenn MSB >= 0x80 ist, ein 0x00 Byte voranstellen
            val needsZeroPrefix = (trimmed[0].toInt() and 0x80) != 0
            val payload = if (needsZeroPrefix) byteArrayOf(0) + trimmed else trimmed

            // 0x02 = INTEGER Tag
            return byteArrayOf(0x02.toByte(), payload.size.toByte()) + payload
        }

        val rDer = encodeDerInteger(r)
        val sDer = encodeDerInteger(s)
        val sequenceBody = rDer + sDer

        // 0x30 = SEQUENCE Tag
        return byteArrayOf(0x30.toByte(), sequenceBody.size.toByte()) + sequenceBody
    }

}