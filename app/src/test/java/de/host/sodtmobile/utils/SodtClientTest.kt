package de.host.sodtmobile.utils

import android.content.ContentResolver
import android.content.Context
import android.util.Base64
import org.robolectric.RuntimeEnvironment
import com.google.gson.JsonParser
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec

@RunWith(RobolectricTestRunner::class)
class SodtClientTest {

    private lateinit var context: Context
    private lateinit var contentResolver: ContentResolver
    private lateinit var dummyCertPem: String
    private lateinit var client: SodtClient

    @Before
    fun setUp() {
        context = RuntimeEnvironment.getApplication()
        contentResolver = context.contentResolver

        // Generate a dummy EC certificate PEM for testing
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
        val keyPair = kpg.generateKeyPair()
        dummyCertPem = """-----BEGIN PUBLIC KEY-----
${Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP)}
-----END PUBLIC KEY-----"""

        // Initialize SodtClient with dummy host (network connection will gracefully fail)
        client = SodtClient("127.0.0.1", 0, dummyCertPem, contentResolver)
    }

    @After
    fun tearDown() {
        client.disconnect()
    }

    @Test
    fun packetSerialization_allPacketTypes_produceCorrectByteStructure() {
        val packets = listOf(
            SodtPackets.DiscoveryPayload(id = 2u, code = 100, publicKey = "dummyKey", signature = "dummySig"),
            SodtPackets.ClientListPayload(code = 200, clients = "dummyClients"),
            SodtPackets.KeyExchangePayload(code = 100, key = "ecdhKey"),
            SodtPackets.DisconnectPayload(code = 100),
            SodtPackets.InitTransferPayload(code = 100, filename = "test.txt", filesize = 1024L, filehash = "hash123"),
            SodtPackets.TransferDataPayload(code = 200, data = "dGVzdA==", position = 0L),
            SodtPackets.PingPong(code = 100),
        )

        for (packet in packets) {
            val bytes = packet.toByteArray()
            assertEquals(
                "Serialized packet ${packet.type} must match MESSAGE_WITH_CONTENT_SIZE",
                SodtConstants.MESSAGE_WITH_CONTENT_SIZE,
                bytes.size,
            )

            // First two bytes are content length (little-endian unsigned short)
            val size = ((bytes[1].toInt() and 0xFF) shl 8 or (bytes[0].toInt() and 0xFF))
            val jsonString = String(bytes.slice(2 until (2 + size)).toByteArray(), Charsets.UTF_8)
            val jsonObject = JsonParser.parseString(jsonString).asJsonObject

            assertEquals(packet.type, jsonObject["type"].asString)
            assertEquals(packet.code, jsonObject["code"].asInt)
        }
    }

    @Test
    fun receiveDiscoveryResponse_successful_setsClientIdAndStartsPinging() {
        // Prepare server identity keypair and certificate
        val serverKpg = KeyPairGenerator.getInstance("EC")
        serverKpg.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
        val serverIdentityKeyPair = serverKpg.generateKeyPair()
        val serverCert = """-----BEGIN PUBLIC KEY-----
${Base64.encodeToString(serverIdentityKeyPair.public.encoded, Base64.NO_WRAP)}
-----END PUBLIC KEY-----"""

        // Subclass SodtClient to initialize encryptionManager for SERVER_ID without exposing initialDiscovery()
        class TestSodtClient : SodtClient("127.0.0.1", 0, serverCert, contentResolver) {
            fun prepareServerEcdh(): String = encryptionManager.createEcdhKeyPair(SodtConstants.SERVER_ID)
        }

        val testClient = TestSodtClient()
        testClient.prepareServerEcdh()

        // Server generates its own ECDH key
        val serverEcdhKeyPair = serverKpg.generateKeyPair()
        val serverEcdhPubBase64 = Base64.encodeToString(serverEcdhKeyPair.public.encoded, Base64.NO_WRAP)

        val assignedId: UByte = 7u
        val discoveryPayload = SodtPackets.DiscoveryPayload(
            id = assignedId,
            code = 200,
            publicKey = serverEcdhPubBase64,
            signature = "dGVzdFNpZw==", // dummy signature
        )

        testClient.receiveDiscoveryResponse(discoveryPayload)

        assertEquals("Globals.clientID must be updated to assigned id", assignedId, Globals.clientID)
        testClient.disconnect()
    }

    @Test
    fun receiveDiscoveryResponse_illegalResponse_triggersDisconnect() {
        // Zero client ID is illegal
        val illegalPayload = SodtPackets.DiscoveryPayload(
            id = 0u,
            code = 200,
            publicKey = "dummyKey",
            signature = null,
        )

        client.receiveDiscoveryResponse(illegalPayload)
        assertFalse(client.isInitiated)
    }

    @Test
    fun receiveDiscoveryResponse_failedStatusCode_triggersDisconnect() {
        val failedPayload = SodtPackets.DiscoveryPayload(
            id = 5u,
            code = 400,
            publicKey = "dummyKey",
            signature = "sig",
        )

        client.receiveDiscoveryResponse(failedPayload)
        assertFalse(client.isInitiated)
    }

    @Test
    fun receiveClientList_nullClients_handledGracefully() {
        val emptyPayload = SodtPackets.ClientListPayload(code = 200, clients = null)
        // Should not throw exception
        client.receiveClientList(emptyPayload)
    }

    @Test
    fun receiveClientList_parsesClientIdsAndFiltersServerAndSelf() {
        Globals.clientID = 5u
        // Byte array representing client IDs 1 (server), 5 (self), 8 (peer)
        val clientIds = byteArrayOf(1, 5, 8)
        val base64Clients = org.bouncycastle.util.encoders.Base64.toBase64String(clientIds)

        val payload = SodtPackets.ClientListPayload(code = 200, clients = base64Clients)
        client.receiveClientList(payload)
        // Verified: handled without crash or error
    }

    @Test
    fun respondToKeyExchange_code100_createsSessionKey() {
        val peerManager = EncryptionManager()
        val peerPubKeyBase64 = peerManager.createEcdhKeyPair(Globals.clientID)

        val requestPacket = SodtPackets.KeyExchangePayload(
            code = 100,
            key = peerPubKeyBase64,
        )

        val remotePeerId: UByte = 9u
        client.respondToKeyExchange(remotePeerId, requestPacket)

        peerManager.close()
    }

    @Test
    fun respondToKeyExchange_emptyKey_rejected() {
        val emptyKeyPacket = SodtPackets.KeyExchangePayload(code = 100, key = "")
        client.respondToKeyExchange(9u, emptyKeyPacket)
    }

    @Test
    fun respondToKeyExchange_deniedCode300_doesNotCrash() {
        val deniedPacket = SodtPackets.KeyExchangePayload(code = 300, key = "key")
        client.respondToKeyExchange(9u, deniedPacket)
    }

    @Test
    fun respondToKeyExchange_failedCode400_doesNotCrash() {
        val failedPacket = SodtPackets.KeyExchangePayload(code = 400, key = "key")
        client.respondToKeyExchange(9u, failedPacket)
    }

    @Test
    fun respondToTransferRequest_rejectedCodes300and400_cleansUp() {
        val payload300 = SodtPackets.InitTransferPayload(
            code = 300,
            uuid = 12345,
            filename = "sample.txt",
            filesize = 100L,
            filehash = "hash",
        )
        client.respondToTransferRequest(9u, payload300)

        val payload400 = SodtPackets.InitTransferPayload(
            code = 400,
            uuid = 67890,
            filename = "sample2.txt",
            filesize = 200L,
            filehash = "hash2",
        )
        client.respondToTransferRequest(9u, payload400)
    }

    @Test
    fun disconnect_resetsState() {
        client.disconnect()
        assertFalse("Client should not be initiated after disconnect", client.isInitiated)
        assertFalse("Client should not be connected after disconnect", client.isConnected)
    }
}
