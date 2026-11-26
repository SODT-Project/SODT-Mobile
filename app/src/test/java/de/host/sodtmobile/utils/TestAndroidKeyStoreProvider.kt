package de.host.sodtmobile.utils

import java.io.InputStream
import java.io.OutputStream
import java.security.*
import java.security.cert.Certificate
import java.util.Date
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.SecretKey

class TestAndroidKeyStoreProvider : Provider("AndroidKeyStore", 1.0, "Test AndroidKeyStore Provider") {

    init {
        put("KeyStore.AndroidKeyStore", TestKeyStoreSpi::class.java.name)
    }

    class TestKeyStoreSpi : KeyStoreSpi() {
        private val entries = ConcurrentHashMap<String, KeyStore.Entry>()
        private val keyProtections = ConcurrentHashMap<String, KeyStore.ProtectionParameter>()

        override fun engineGetKey(alias: String?, password: CharArray?): Key? {
            val entry = entries[alias]
            return when (entry) {
                is KeyStore.SecretKeyEntry -> entry.secretKey
                is KeyStore.PrivateKeyEntry -> entry.privateKey
                else -> null
            }
        }

        override fun engineGetCertificateChain(alias: String?): Array<Certificate>? {
            val entry = entries[alias]
            return when (entry) {
                is KeyStore.PrivateKeyEntry -> entry.certificateChain
                is KeyStore.TrustedCertificateEntry -> arrayOf(entry.trustedCertificate)
                else -> null
            }
        }

        override fun engineGetCertificate(alias: String?): Certificate? {
            val chain = engineGetCertificateChain(alias)
            return chain?.firstOrNull()
        }

        override fun engineGetCreationDate(alias: String?): Date? = Date()

        override fun engineSetKeyEntry(alias: String?, key: Key?, password: CharArray?, chain: Array<out Certificate>?) {
            if (alias != null && key != null) {
                if (key is SecretKey) {
                    entries[alias] = KeyStore.SecretKeyEntry(key)
                } else if (key is PrivateKey) {
                    entries[alias] = KeyStore.PrivateKeyEntry(key, chain)
                }
            }
        }

        override fun engineSetKeyEntry(alias: String?, key: ByteArray?, chain: Array<out Certificate>?) {
            // Not supported
        }

        override fun engineSetCertificateEntry(alias: String?, cert: Certificate?) {
            if (alias != null && cert != null) {
                entries[alias] = KeyStore.TrustedCertificateEntry(cert)
            }
        }

        override fun engineDeleteEntry(alias: String?) {
            if (alias != null) {
                entries.remove(alias)
                keyProtections.remove(alias)
            }
        }

        override fun engineContainsAlias(alias: String?): Boolean {
            return alias != null && entries.containsKey(alias)
        }

        override fun engineAliases(): java.util.Enumeration<String> {
            return java.util.Collections.enumeration(entries.keys)
        }

        override fun engineSize(): Int {
            return entries.size
        }

        override fun engineIsKeyEntry(alias: String?): Boolean {
            val entry = entries[alias]
            return entry is KeyStore.SecretKeyEntry || entry is KeyStore.PrivateKeyEntry
        }

        override fun engineIsCertificateEntry(alias: String?): Boolean {
            return entries[alias] is KeyStore.TrustedCertificateEntry
        }

        override fun engineGetCertificateAlias(cert: Certificate?): String? = null

        override fun engineStore(stream: OutputStream?, password: CharArray?) {
            // No-op
        }

        override fun engineLoad(stream: InputStream?, password: CharArray?) {
            // No-op
        }

        override fun engineSetEntry(alias: String?, entry: KeyStore.Entry?, protParam: KeyStore.ProtectionParameter?) {
            if (alias != null && entry != null) {
                entries[alias] = entry
                if (protParam != null) {
                    keyProtections[alias] = protParam
                }
            }
        }

        override fun engineGetEntry(alias: String?, protParam: KeyStore.ProtectionParameter?): KeyStore.Entry? {
            return entries[alias]
        }

        override fun engineEntryInstanceOf(alias: String?, entryClass: Class<out KeyStore.Entry>?): Boolean {
            val entry = entries[alias]
            return entryClass != null && entryClass.isInstance(entry)
        }
    }

    companion object {
        private var installed = false

        fun install() {
            if (!installed) {
                try {
                    Security.addProvider(TestAndroidKeyStoreProvider())
                    installed = true
                } catch (e: Exception) {
                    // Ignore if already added
                }
            }
        }
    }
}
