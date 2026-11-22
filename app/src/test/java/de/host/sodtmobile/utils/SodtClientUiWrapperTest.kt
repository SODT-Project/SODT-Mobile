package de.host.sodtmobile.utils

import android.content.Context
import android.util.Base64
import androidx.preference.PreferenceManager
import de.host.sodtmobile.elements.ClientListElement
import de.host.sodtmobile.elements.ListElementAdapter
import de.host.sodtmobile.elements.TransferElement
import io.mockk.mockk
import io.mockk.verify
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowLooper
import org.robolectric.shadows.ShadowToast
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class SodtClientUiWrapperTest {

    private lateinit var context: Context
    private lateinit var clientList: MutableList<ClientListElement>
    private lateinit var transferList: MutableList<TransferElement>
    private lateinit var clientAdapter: ListElementAdapter
    private lateinit var transferAdapter: ListElementAdapter
    private var lastSetClient: ClientListElement? = null
    private lateinit var wrapper: SodtClientUiWrapper

    @Before
    fun setUp() {
        context = RuntimeEnvironment.getApplication()

        // Enable auto accept by default in tests for simplicity
        PreferenceManager.getDefaultSharedPreferences(context)
            .edit()
            .putBoolean("preference_auto_accept_key_exchange", true)
            .putBoolean("preference_auto_accept_transfer", true)
            .apply()

        clientList = mutableListOf()
        transferList = mutableListOf()

        clientAdapter = mockk(relaxed = true)
        transferAdapter = mockk(relaxed = true)
        lastSetClient = null

        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
        val keyPair = kpg.generateKeyPair()
        val dummyCertPem = """-----BEGIN PUBLIC KEY-----
${Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP)}
-----END PUBLIC KEY-----"""

        wrapper = SodtClientUiWrapper(
            serverAddress = "127.0.0.1",
            serverPort = 0,
            encryptionKey = dummyCertPem,
            context = context,
            clientList = clientList,
            clientListElementAdapter = clientAdapter,
            onClientSetAction = { lastSetClient = it },
            transferList = transferList,
            transferListElementAdapter = transferAdapter,
        )
    }

    @After
    fun tearDown() {
        wrapper.disconnect()
    }

    @Test
    fun receiveDiscoveryResponse_unverifiedSignature_showsWarningToast() {
        val discoveryPayload = SodtPackets.DiscoveryPayload(
            id = 5u,
            code = 200,
            publicKey = "dummyKey",
            signature = "invalidSignature"
        )

        wrapper.receiveDiscoveryResponse(discoveryPayload)
        ShadowLooper.idleMainLooper()

        val toastText = ShadowToast.getTextOfLatestToast()
        assertNotNull(toastText)
        assertTrue(toastText!!.contains("discovery signature could not be verified"))
    }

    @Test
    fun receiveClientList_populatesListExcludingServerAndMarksSelf() {
        Globals.clientID = 2u
        val clientIds = byteArrayOf(1, 2, 3) // 1=server, 2=self, 3=peer
        val base64Clients = org.bouncycastle.util.encoders.Base64.toBase64String(clientIds)

        val packet = SodtPackets.ClientListPayload(code = 200, clients = base64Clients)
        wrapper.receiveClientList(packet)

        ShadowLooper.idleMainLooper()

        assertEquals("Server ID (1) must be excluded; 2 clients should remain", 2, clientList.size)
        assertTrue(clientList.any { (id, name) -> (id == 2.toUByte()) && name.contains("(you)") })
        assertTrue(clientList.any { (id, name) -> (id == 3.toUByte()) && !name.contains("(you)") })

        verify { clientAdapter.notifyDataSetChanged() }
    }

    @Test
    fun receiveClientList_invokesOnClientSetActionWithSelectedClient() {
        val selected = ClientListElement(3u, "3", null)
        wrapper.selectedClient = selected

        val clientIds = byteArrayOf(3)
        val base64Clients = org.bouncycastle.util.encoders.Base64.toBase64String(clientIds)
        wrapper.receiveClientList(SodtPackets.ClientListPayload(code = 200, clients = base64Clients))

        ShadowLooper.idleMainLooper()

        assertEquals("onClientSetAction should be invoked with selectedClient", selected, lastSetClient)
    }

    @Test
    fun respondToTransferRequest_autoAcceptEnabled_addsTransferElementAndNotifiesAdapter() {
        val packet = SodtPackets.InitTransferPayload(
            code = 100,
            uuid = 999,
            filename = "document.pdf",
            filesize = 5000L,
            filehash = "hash123",
        )

        wrapper.respondToTransferRequest(4u, packet)
        ShadowLooper.idleMainLooper()

        assertEquals(1, transferList.size)
        val (transferId, senderName, fileName, totalSize, _, remainingSize) = transferList[0]
        assertEquals(999, transferId)
        assertEquals("document.pdf", fileName)
        assertEquals("4", senderName)
        assertEquals(5000L, totalSize)
        assertEquals(5000L, remainingSize)

        verify { transferAdapter.notifyItemInserted(0) }
    }

    @Test
    fun respondToTransferRequest_code250_showsSuccessToast() {
        val packet = SodtPackets.InitTransferPayload(
            code = 250,
            uuid = 999,
            filename = "document.pdf",
            filesize = 5000L,
            filehash = "hash123",
        )

        wrapper.respondToTransferRequest(4u, packet)
        ShadowLooper.idleMainLooper()

        val toastText = ShadowToast.getTextOfLatestToast()
        assertNotNull(toastText)
        assertTrue(toastText!!.contains("reported successful transfer of document.pdf"))
    }

    @Test
    fun respondToTransferRequest_code300_showsRejectionToast() {
        val packet = SodtPackets.InitTransferPayload(
            code = 300,
            uuid = 999,
            filename = "document.pdf",
            filesize = 5000L,
            filehash = "hash123",
        )

        wrapper.respondToTransferRequest(4u, packet)
        ShadowLooper.idleMainLooper()

        val toastText = ShadowToast.getTextOfLatestToast()
        assertNotNull(toastText)
        assertTrue(toastText!!.contains("rejected by 4"))
    }

    @Test
    fun respondToTransferRequest_code400_showsFailureToast() {
        val packet = SodtPackets.InitTransferPayload(
            code = 400,
            uuid = 999,
            filename = "document.pdf",
            filesize = 5000L,
            filehash = "hash123",
        )

        wrapper.respondToTransferRequest(4u, packet)
        ShadowLooper.idleMainLooper()

        val toastText = ShadowToast.getTextOfLatestToast()
        assertNotNull(toastText)
        assertTrue(toastText!!.contains("failed with code 400"))
    }

    @Test
    fun receiveFileData_updatesRemainingSizeAndNotifiesAdapter() {
        val transfer = TransferElement(
            transferId = 1234,
            senderName = "4",
            fileName = "photo.jpg",
            totalSize = 1000L,
            fileHash = "hash",
            remainingSize = 1000L,
        )
        transferList.add(transfer)

        wrapper.incomingTransfersProgress[1234] = 600L

        val dataPacket = SodtPackets.TransferDataPayload(
            code = 200,
            uuid = 1234,
            data = Base64.encodeToString(byteArrayOf(1, 2, 3), Base64.NO_WRAP),
            position = 400L,
        )

        wrapper.receiveFileData(4u, dataPacket)
        ShadowLooper.idleMainLooper()

        assertEquals(600L, transferList[0].remainingSize)
        verify { transferAdapter.notifyItemChanged(0) }
    }

    @Test
    fun receiveFileData_whenCompleted_showsToastAndMarksRemainingNegative() {
        val transfer = TransferElement(
            transferId = 1234,
            senderName = "4",
            fileName = "photo.jpg",
            totalSize = 1000L,
            fileHash = "hash",
            remainingSize = 100L,
        )
        transferList.add(transfer)

        wrapper.incomingTransfersProgress[1234] = 0L

        val dataPacket = SodtPackets.TransferDataPayload(
            code = 200,
            uuid = 1234,
            data = Base64.encodeToString(byteArrayOf(1, 2, 3), Base64.NO_WRAP),
            position = 1000L,
        )

        wrapper.receiveFileData(4u, dataPacket)
        ShadowLooper.idleMainLooper()

        val toastText = ShadowToast.getTextOfLatestToast()
        assertNotNull(toastText)
        assertTrue(toastText!!.contains("File transfer completed"))
        assertEquals(-1L, transferList[0].remainingSize)
    }

    @Test
    fun sendFile_showsSendingToast() {
        wrapper.sendFile(3u, 888)
        ShadowLooper.idleMainLooper()

        val toastText = ShadowToast.getTextOfLatestToast()
        assertNotNull(toastText)
        assertTrue(toastText!!.contains("Sending file (uuid: 888) to 3"))
    }

    @Test
    fun respondToKeyExchange_autoAcceptEnabled_updatesSharedPhraseInClientList() {
        clientList.add(ClientListElement(6u, "6", null))

        val peerManager = EncryptionManager()
        val peerKeyBase64 = peerManager.createEcdhKeyPair(Globals.clientID)

        val packet = SodtPackets.KeyExchangePayload(code = 100, key = peerKeyBase64)
        wrapper.respondToKeyExchange(6u, packet)
        ShadowLooper.idleMainLooper()

        assertEquals(1, clientList.size)
        assertNotNull("Shared phrase must be set after key exchange", clientList[0].sharedPhrase)
        verify { clientAdapter.notifyItemChanged(0) }

        peerManager.close()
    }

    @Test
    fun respondToKeyExchange_code300_showsRejectionToastAndUnselectsClient() {
        val clientElem = ClientListElement(6u, "6", null)
        clientList.add(clientElem)
        wrapper.selectedClient = clientElem

        val packet = SodtPackets.KeyExchangePayload(code = 300, key = "")
        wrapper.respondToKeyExchange(6u, packet)
        ShadowLooper.idleMainLooper()

        val toastText = ShadowToast.getTextOfLatestToast()
        assertNotNull(toastText)
        assertTrue(toastText!!.contains("rejected by 6"))
        assertEquals(null, wrapper.selectedClient)
    }
}
