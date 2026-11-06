package de.host.sodtmobile.utils

import android.util.Base64
import android.util.Log
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.SecureRandom

import java.security.*
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
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

    fun getEcdhKeyAsBase64(clientId: UByte): String {

        // Get the public key in X.509 format
        val publicKeyBytes = ecdhSessionKeyGenerators[clientId]
        return Base64.encodeToString(publicKeyBytes!!.public.encoded, Base64.NO_WRAP) // TODO remove !! with null checks
    }

    /**
     * Adds a client session key for a specific client ID.
     * This allows for secure communication between clients using their own session keys.
     */
    fun addSessionKey(remoteId: UByte, sessionKey: SecretKey) {
        aesSessionKeys[remoteId] = sessionKey
    }
    fun createEcdhKeyPair(remoteId: UByte): String{
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(ECGenParameterSpec(ecCurve), SecureRandom())
        ecdhSessionKeyGenerators[remoteId] = keyPairGenerator.generateKeyPair()
        return getEcdhKeyAsBase64(remoteId)
    }

    private fun deriveSharedSecretFromBase64Key(remoteId: UByte, base64otherPublicKey: String): ByteArray {
        // get matching key pair from generator
        val ecdhKeyPair = ecdhSessionKeyGenerators[remoteId]
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
        keyAgreement.init(ecdhKeyPair!!.private) // TODO remove !! with null checks
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


    fun generateSessionAesKeyFromExchangeMessage(remoteId: UByte, otherKeyBase64: String): SecretKey {
        val sharedSecret = deriveSharedSecretFromBase64Key(remoteId, otherKeyBase64)
        return deriveAesKeyFromSharedSecret(sharedSecret)
    }

    fun encryptAesGcm(remoteId: UByte, baseMessage: SodtPackets.IBasePacket): ByteArray? {

        // prepare
        val toEncrypt = baseMessage.toByteArray()
        val aes = aesSessionKeys[remoteId]
        val cipher = Cipher.getInstance(aesAlgorithm)
        cipher.init(Cipher.ENCRYPT_MODE, aes)
        // encrypt
        val nonce = cipher.iv
        val encrypted = cipher.doFinal(toEncrypt)
        val tag = encrypted.slice(encrypted.size - SodtConstants.TAG_SIZE until encrypted.size).toByteArray()
        val encryptedWithoutTag = encrypted.slice(0 until encrypted.size - SodtConstants.TAG_SIZE) // remove tag, because in sodt protocol its at the beginning of the message
        return nonce + tag + encryptedWithoutTag
    }

    fun decryptAesGcm(clientId: UByte, receivedData: ByteArray): ByteArray? {
        // TODO check receivedData == 4096

        // prepare decryption and get relevant data
        val ciphertext = receivedData.slice(SodtConstants.HEADER_SIZE_WITHOUT_CONTENT_LENGTH until receivedData.size).toByteArray()
        val aes = aesSessionKeys[clientId]
        val tag = receivedData.slice((SodtConstants.ID_SIZE + SodtConstants.NONCE_SIZE) until (SodtConstants.ID_SIZE + SodtConstants.NONCE_SIZE + SodtConstants.TAG_SIZE)).toByteArray()
        val nonce = receivedData.slice(SodtConstants.ID_SIZE until (SodtConstants.ID_SIZE + SodtConstants.NONCE_SIZE)).toByteArray()
        // decrypt
        val cipher = Cipher.getInstance(aesAlgorithm)
        cipher.init(Cipher.DECRYPT_MODE, aes!!, GCMParameterSpec(128, nonce))
        return cipher.doFinal(ciphertext + tag) // cipher expects tag at the end of the message, but sodt protocol puts tag before message, so reverse it
        // TODO implement errorchecks
        return null
    }

     fun parsePemCertificate(pemString: String): X509Certificate? {
        return try {
            val factory = CertificateFactory.getInstance("X.509")
            // Convert the string to an InputStream
            val inputStream = pemString.byteInputStream()
            factory.generateCertificate(inputStream) as X509Certificate
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse PEM certificate", e)
            null
        }
    }

}