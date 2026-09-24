package de.host.sodtmobile.utils

import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import de.host.sodtmobile.activities.LogsActivity
import org.bouncycastle.asn1.ASN1Primitive
import java.io.ByteArrayOutputStream
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.SecureRandom
import org.bouncycastle.asn1.pkcs.RSAPublicKey

import java.security.spec.RSAPublicKeySpec
import javax.crypto.KeyGenerator
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement
import javax.crypto.SecretKey
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
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
class EncryptionManager(serverPublicKey: String) {

    /**
     * Data class representing AES key material, including the secret key and initialization vector (IV).
     */
    data class AesKeyMaterial(val key: SecretKey, val iv: IvParameterSpec)

    private val TAG = "EncryptionManager"
    private val aesKeySize = 256 // AES-256
    private val ecCurve = "secp256r1"
    private val aesAlgorithm = "AES/CFB8/NoPadding"
    private val rsaAlgorithm = "RSA/ECB/PKCS1Padding"
    private var rsaServerPublicKey: PublicKey? = null
    private var aesServerSessionKey: AesKeyMaterial
    private var ecdhKeyPair: KeyPair = KeyPairGenerator.getInstance("EC").apply {
        ECGenParameterSpec(ecCurve)
    }.generateKeyPair()
    // store session keys and ivs for client-client communication
    private val clientAesSessionKeys = mutableMapOf<UByte, AesKeyMaterial>()

    // INFO:
    // android keystore not used because it does not support needed algorithm configurations
    // (eg. AES/CFB8/NoPadding)

    init {
        // load the server public rsa key
        try {
            rsaServerPublicKey = parsePkcs1RsaPublicKey(serverPublicKey)
        } catch (error: InvalidKeyException) {
            Log.d(TAG, "Could not parse server rsa public key")
        }
        // generate new client-server aes session key and iv for this instance
        aesServerSessionKey = AesKeyMaterial(
            generateAesSecretKey(),
            IvParameterSpec(generateAesIv())
        )
    }
    companion object{
        /**
         * Checks if the provided RSA public key in PEM format is valid.
         */
        fun isRsaPemKeyValid(pem: String): Boolean {
            return parsePkcs1RsaPublicKey(pem) != null
        }
        /**
         * Parses an RSA public key string in PEM format and returns a PublicKey object.
         * The input string should include the BEGIN and END headers/footers.
         *
         * @param pem The RSA public key string in PEM format.
         * @return A PublicKey object, or null if parsing fails.
         */
        private fun parsePkcs1RsaPublicKey(pem: String): PublicKey? {
            return try {
                val cleaned = pem
                    .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                    .replace("-----END RSA PUBLIC KEY-----", "")
                    .replace("\\s".toRegex(), "")

                val decoded = Base64.decode(cleaned, Base64.NO_WRAP)

                val asn1 = ASN1Primitive.fromByteArray(decoded)
                val rsaKey = RSAPublicKey.getInstance(asn1)

                val keySpec = RSAPublicKeySpec(rsaKey.modulus, rsaKey.publicExponent)

                // Use default provider (not "BC")
                val keyFactory = KeyFactory.getInstance("RSA")
                keyFactory.generatePublic(keySpec)

            } catch (e: Exception) {
                e.printStackTrace()
                null
            }
        }
    }
    /**
     * Returns the AES client-server session key.
     * This is a copy of the key, not the original to prevent accidental modification.
     */
    fun getAesServerSessionKeyAsBase64(): String {
        return Base64.encodeToString(aesServerSessionKey.key.encoded, Base64.NO_WRAP)
    }

    fun removeClientSessionKey(clientId: UByte) {
        clientAesSessionKeys.remove(clientId)
    }

    fun getAllConnectedClientIds(): Set<UByte> {
        return clientAesSessionKeys.keys
    }

    fun hasClientSessionKeyFor(clientId: UByte): Boolean {
        return clientAesSessionKeys.containsKey(clientId)
    }

    fun getAesServerSessionIVAsBase64(): String {
        return Base64.encodeToString(aesServerSessionKey.iv.iv, Base64.NO_WRAP)
    }

    /**
     * Returns the public ECDH key as a Base64 encoded string.
     * This key can be shared with other clients a secure key exchange.
     */
    fun getPublicEcdhKeyAsBase64(): String {
        // Get the public key in X.509 format
        val publicKeyBytes = ecdhKeyPair.public.encoded
        return Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP)
    }

    /**
     * Adds a client session key for a specific client ID.
     * This allows for secure communication between clients using their own session keys.
     */
    fun addClientSessionKey(clientId: UByte, sessionKey: AesKeyMaterial) {
        clientAesSessionKeys[clientId] = sessionKey
    }

    /**
     * Generates a new random AES secret key. This key will be used as the session key.
     */
    private fun generateAesSecretKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES)
        keyGenerator.init(aesKeySize, SecureRandom())
        return keyGenerator.generateKey()
    }

    /**
     * Generates a new random Initialization Vector (IV) for AES CFB mode.
     * The IV must be unique for each encryption.
     */
    private fun generateAesIv(): ByteArray {
        val iv = ByteArray(16) // AES block size is 16 bytes (128 bits)
        SecureRandom().nextBytes(iv)
        return iv
    }

    /**
     * Encrypts data using AES in CFB mode.
     * @param plaintext The data to encrypt.
     * @param aesKey The AES secret key (session key).
     * @param iv The Initialization Vector.
     * @return Encrypted data bytes, or null on error.
     */
    private fun encryptWithAesCfb(plaintext: ByteArray, aes: AesKeyMaterial): ByteArray? {
        return try {
            val cipher = Cipher.getInstance(aesAlgorithm)
            cipher.init(Cipher.ENCRYPT_MODE, aes.key, aes.iv)
            cipher.doFinal(plaintext)
        } catch (e: Exception) {
            LogsActivity.addLog("Error encrypting with AES CFB: ${e.message}")
            Log.e(TAG, "Error encrypting with AES CFB: ${e.message}", e)
            null
        }
    }

    /**
     * Decrypts data using AES in CFB mode.
     * @param ciphertext The data to decrypt.
     * @param aesKey The AES secret key (session key).
     * @param iv The Initialization Vector.
     * @return Decrypted data bytes, or null on error.
     */
    private fun decryptWithAesCfb(ciphertext: ByteArray, aes: AesKeyMaterial): ByteArray? {
        return try {
            val cipher = Cipher.getInstance(aesAlgorithm)
            cipher.init(Cipher.DECRYPT_MODE, aes.key, aes.iv)
            cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            LogsActivity.addLog("Error decrypting with AES CFB: ${e.message}")
            Log.e(TAG, "Error decrypting with AES CFB: ${e.message}", e)
            null
        }
    }

    /**
     * Encrypts data using the server's AES session key and IV.
     * This is used for communication between the client and server.
     * @param plaintext The data to encrypt.
     * @return Encrypted data bytes, or null on error.
     */
    fun encryptWithAesServer(plaintext: ByteArray): ByteArray? {
        return encryptWithAesCfb(plaintext, aesServerSessionKey)
    }

    /**
     * Decrypts data using the server's AES session key and IV.
     * @param ciphertext The data to decrypt.
     * @return Decrypted data bytes, or null on error.
     */
    fun decryptWithAesServer(ciphertext: ByteArray): ByteArray? {
        return decryptWithAesCfb(ciphertext, aesServerSessionKey)
    }

    /**
     * Encrypts data for a specific client using their session key.
     * @param clientId The ID of the client to encrypt for.
     * @param plaintext The data to encrypt.
     * @return Encrypted data bytes, or null if no session key is found for the client.
     */
    fun encryptWithAesClient(clientId: UByte, plaintext: ByteArray): ByteArray? {
        val sessionKey = clientAesSessionKeys[clientId] ?: run {
            LogsActivity.addLog("encryptWithAesClient: No session key found for client ID $clientId")
            Log.w(TAG, "encryptWithAesClient: No session key found for client ID $clientId")
            return null
        }
        return encryptWithAesCfb(plaintext, sessionKey)
    }

    /**
     * Decrypts data for a specific client using their session key.
     * @param clientId The ID of the client to decrypt for.
     * @param ciphertext The data to decrypt.
     * @return Decrypted data bytes, or null if no session key is found for the client.
     */
    fun decryptWithAesClient(clientId: UByte, ciphertext: ByteArray): ByteArray? {
        val sessionKey = clientAesSessionKeys[clientId] ?: run {
            LogsActivity.addLog("encryptWithAesClient: No session key found for client ID $clientId")
            Log.w(TAG, "decryptWithAesClient: No session key found for client ID $clientId")
            return null
        }
        return decryptWithAesCfb(ciphertext, sessionKey)
    }

    /**
     * Encrypts data using RSA with the server's public key.
     * The data is split into chunks to fit within the RSA block size.
     * @param data The data to encrypt.
     * @return Encrypted data bytes, or null on error.
     */
    fun encryptRsa(data: ByteArray): ByteArray? {
        val publicKey = rsaServerPublicKey ?: run {
            LogsActivity.addLog("encryptRsa: Public key is null")
            Log.w(TAG, "encryptRsa: Public key is null")
            return null
        }

        return try {
            val cipher = Cipher.getInstance(rsaAlgorithm)
            cipher.init(Cipher.ENCRYPT_MODE, publicKey)

            val maxBlockSize = 501 // For 4096-bit key with PKCS1Padding
            val outputStream = ByteArrayOutputStream()

            var offset = 0
            while (offset < data.size) {
                val chunkSize = minOf(maxBlockSize, data.size - offset)
                val chunk = cipher.doFinal(data, offset, chunkSize)
                outputStream.write(chunk)
                offset += chunkSize
            }

            outputStream.toByteArray()
        } catch (e: Exception) {
            LogsActivity.addLog("RSA encryption failed: ${e.message}")
            Log.e(TAG, "RSA encryption failed: ${e.message}", e)
            null
        }
    }

    /**
     * Derives a shared secret with the other party's public key.
     * This is used in ECDH key exchange to create a shared secret for symmetric encryption.
     * @param base64otherPublicKey The other party's public key in Base64 format.
     * @return The derived shared secret as a byte array.
     */
    private fun deriveSharedSecretFromBase64Key(base64otherPublicKey: String): ByteArray {
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
    private fun deriveAesKeyAndIvFromSharedSecret(sharedSecret: ByteArray): AesKeyMaterial {
        val sha256 = MessageDigest.getInstance("SHA-256")
        val derivedKey = sha256.digest(sharedSecret) // 32-byte key

        // Derive IV by hashing derivedKey and using the first 16 bytes
        val ivBytes = sha256.digest(derivedKey).sliceArray(0..15)

        val secretKey = SecretKeySpec(derivedKey, "AES")
        return AesKeyMaterial(secretKey, IvParameterSpec(ivBytes))
    }

    /**
     * Generates an AES key from a KeyExchangePayload message.
     * This is used to derive the session key for secure communication between clients.
     * @param dataPacket The otherParty KeyExchangePayload containing the Base64 encoded key.
     * @return AesKeyMaterial containing the derived AES key and IV.
     */
    fun generateSessionAesKeyFromExchangeMessage(dataPacket: SodtPackets.KeyExchangePayload): AesKeyMaterial {
        val sharedSecret = deriveSharedSecretFromBase64Key(dataPacket.key)
        return deriveAesKeyAndIvFromSharedSecret(sharedSecret)
    }
}