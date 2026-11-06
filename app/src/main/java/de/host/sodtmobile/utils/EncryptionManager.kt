package de.host.sodtmobile.utils

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
 * It supports AES encryption for client-server and client-client communication, as well as RSA encryption
 * for secure key exchange with the server. Additionally, it provides methods for ECDH key exchange to
 * derive shared secrets for symmetric encryption.
 *
 * Key Features:
 * - AES encryption with CFB8 mode for secure data transfer.
 * - RSA encryption for secure key exchange with the server.
 * - ECDH key exchange for deriving shared secrets between clients.
 * - Management of session keys and initialization vectors (IVs) for secure communication.
 *
 * @param serverPublicKey The server's RSA public key in PEM format, used for secure key exchange.
 */
class EncryptionManager() {

    private val TAG = "EncryptionManager"
    private val aesKeySize = 256 // AES-256
    private val ecCurve = "secp256r1"
    private val aesAlgorithm = "AES/Gcm/NoPadding"
    private val aesSessionKeys = mutableMapOf<UByte, SecretKey>()
    private val ecdhSessionKeyGenerators = mutableMapOf<UByte, KeyPair>()

    // INFO:
    // android keystore not used because it does not support needed algorithm configurations
    // (eg. AES/CFB8/NoPadding)


    fun removeSessionKey(clientId: UByte) {
        aesSessionKeys.remove(clientId)
        ecdhSessionKeyGenerators.remove(clientId)
    }

    fun hasClientSessionKeyFor(clientId: UByte): Boolean {
        return aesSessionKeys.containsKey(clientId)
    }

    private fun getEcdhKeyAsBase64(keyPair: KeyPair): String {
        // Get the public key in X.509 format
        return Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP)
    }

    fun createEcdhKeyPair(remoteId: UByte): String{
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(ECGenParameterSpec(ecCurve), SecureRandom())
        ecdhSessionKeyGenerators[remoteId] = keyPairGenerator.generateKeyPair()
        return getEcdhKeyAsBase64(ecdhSessionKeyGenerators[remoteId]!!) // !! is safe because it is just added above
    }

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


    fun generateAndStoreAesSessionKeyFromKeyExchange(remoteId: UByte, otherKeyBase64: String) {
        val sharedSecret = deriveSharedSecretFromBase64Key(remoteId, otherKeyBase64)
        val aesSessionKey = deriveAesKeyFromSharedSecret(sharedSecret)
        aesSessionKeys[remoteId] = aesSessionKey
    }

    fun encryptAesGcm(remoteId: UByte, baseMessage: SodtPackets.IBasePacket): ByteArray? {
        // prepare
        val toEncrypt = baseMessage.toByteArray()
        val aes = aesSessionKeys[remoteId]
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
            val aes = aesSessionKeys[clientId]
            cipher.init(Cipher.DECRYPT_MODE, aes, GCMParameterSpec(128, nonce))
            // cipher expects tag at the end of the message, but sodt protocol puts tag before message, so reverse it
            return cipher.doFinal(ciphertext + tag)
        }
        catch (e: Exception) {
            Log.e(TAG, "Decryption failed for client ID: $clientId", e)
        }
        return null
    }

    fun getSharedPhrase(remoteId: UByte, keyExchangePacket: SodtPackets.KeyExchangePayload): String {
        val sharedSecret = deriveSharedSecretFromBase64Key(remoteId, keyExchangePacket.key)
        val sha256 = MessageDigest.getInstance("SHA-256")
        val derivedKey = sha256.digest(sharedSecret) // 32-byte key
        val keyInHex = derivedKey.joinToString("") { "%02X".format(it) }
        val keyParts = keyInHex.chunked(2) // split into pairs of 2 characters
        // return 0th, 4th, 8th, 16th, 31th pair with hyphens
        return "${keyParts[0]}-${keyParts[4]}-${keyParts[8]}-${keyParts[16]}-${keyParts[31]}"
    }

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

    fun verifySignature(certificate: String, dataPacket: SodtPackets.DiscoveryPayload): Boolean {
        // prepare certificate
        val publicKey = parsePemPublicKey(certificate)
        // prepare signature verification
        val localEcdhKey = ecdhSessionKeyGenerators[SodtConstants.SERVER_ID]!!.public.encoded
        val remoteEcdhKey = Base64.decode(dataPacket.publicKey, Base64.NO_WRAP)
        val toVerify = localEcdhKey + remoteEcdhKey + dataPacket.id.toByte()

        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initVerify(publicKey)
        signature.update(toVerify)

        return try {
            val signatureBytes = Base64.decode(dataPacket.signature, Base64.DEFAULT)
            val isValid = signature.verify(ieeeP1363ToDer(signatureBytes))
            if (!isValid) {
                Log.e(TAG, "Signature verification failed")
            }
            isValid
        } catch (e: Exception) {
            Log.e(TAG, "Error during signature verification", e)
            false
        }
    }

    // AI code to convert IEEE P1363 signature to DER format for ECDSA verification
    private fun ieeeP1363ToDer(ieeeSignature: ByteArray): ByteArray {
        require(ieeeSignature.size % 2 == 0) { "Ungültige Signatur-Länge" }
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