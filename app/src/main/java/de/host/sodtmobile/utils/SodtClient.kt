package de.host.sodtmobile.utils

import android.content.ContentResolver
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.util.Base64
import android.util.Log
import de.host.sodtmobile.activities.LogsActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.FileOutputStream
import java.nio.ByteBuffer
import kotlin.time.Duration.Companion.milliseconds

/** * SodtClient is the main class for the Sodt client.
 * It handles the connection to the server, sending and receiving packets, and file transfers.
 * It uses the NetworkingClient to handle the network communication and the EncryptionManager to handle encryption.
 * @param serverAddress The address of the server to connect to.
 * @param serverPort The port of the server to connect to.
 * @param serverCertificate The certificate of the server to verify the server's identity.
 * @param contentResolver The ContentResolver used to access files.
 */
open class SodtClient(
    serverAddress: String,
    serverPort: Int,
    protected val serverCertificate: String,
    private val contentResolver: ContentResolver
) {
    private val logTag = "SodtClient"
    protected val encryptionManager = EncryptionManager() //TODO val ok?

    private val fileManager = FileManager(contentResolver)

    private var pingJob: Job? = null
    private val pingDelay = 3000.milliseconds
    // not ideal logic but it works
    private var sodtReceiver: SodtReceiver = SodtReceiver(encryptionManager, this)
    private var networkingClient: NetworkingClient =
        NetworkingClient(sodtReceiver, serverAddress, serverPort)
    private val connectedClients = mutableListOf<UByte>()

    /**
     * Flag to indicate if the client has been initiated and sent the initial discovery message.
     */
    var isInitiated = false
        private set

    /**
     * Map to store pending transfer requests.
     * Key is the uuid of the transfer request.
     * Value is the URI of the file to be transferred.
     */
    private val pendingTransferRequests = mutableMapOf<Int, Uri>()
    /**
     * Map to store incoming transfers.
     * Contains the file descriptor to write the received bytes into.
     */
    private val incomingTransfers = mutableMapOf<Int, ParcelFileDescriptor>()
    /**
     * Map to store metadata for incoming transfers.
     * Main use is to store the correct hash for the file, received in the transfer request.
     */
    private val incomingTransferMetaData = mutableMapOf<Int, SodtPackets.InitTransferPayload>()

    /**
     * Map to store incoming transfers progress.
     * Key is the uuid of the transfer request.
     * Value is the remaining size of the file to be transferred. Therefore, 0 means the transfer is complete.
     */
    internal val incomingTransfersProgress = mutableMapOf<Int, Long>()

    /**
     * Mutex to synchronize access to the incomingTransfersProgress map.
     */
    private val incomingTransfersProgressMutex = Mutex()
    val isConnected: Boolean
        get() = networkingClient.isConnected

    /**
     * On init connect to the server and send initial Discovery
     */
    init {
        CoroutineScope(Dispatchers.Default).launch {
            val connected = networkingClient.connect()
            if (connected) {
                initialDiscovery()
                isInitiated = true
            }
        }
    }


    /**
     * Sends an encrypted packet to a specific client.
     * This method encrypts the packet using AES and sends it to the specified client.
     * @param receiverID The ID of the client to send the packet to.
     * @param dataPaket The data packet to be sent.
     */
    protected fun sendEncryptedAesPacket(receiverID: UByte, dataPaket: SodtPackets.IBasePacket) {
        CoroutineScope(Dispatchers.Default).launch {
            val encryptedPacket = encryptionManager.encryptAesGcm(receiverID, dataPaket)

            if (encryptedPacket == null) {
                LogsActivity.addErrorLog(logTag,"Failed to encrypt packet for client $receiverID")
                return@launch
            }
            networkingClient.sendData(receiverID, encryptedPacket)
        }
    }

    /**
     * Sends an unencrypted packet to a specific client.
     * Used for discovery and key exchange packets.
     * @param receiverID The ID of the client to send the packet to.
     * @param dataPaket The data packet to be sent.
     */
    protected fun sendUnencryptedPacket(receiverID: UByte, dataPaket: SodtPackets.IBasePacket) {
        CoroutineScope(Dispatchers.Default).launch {
            val cryptoHeader = ByteArray(SodtConstants.TAG_SIZE + SodtConstants.NONCE_SIZE)
            networkingClient.sendData(receiverID, cryptoHeader + dataPaket.toByteArray())
        }
    }

    /**
     * Sends an initial discovery packet (unencrypted) to the server.
     */
    private fun initialDiscovery() {

        val payload = SodtPackets.DiscoveryPayload(
            id = 0u,
            code = 100,
            publicKey = encryptionManager.createEcdhKeyPair(SodtConstants.SERVER_ID),
            signature = null
        )
        sendUnencryptedPacket(SodtConstants.SERVER_ID, payload)
    }

    /** Disconnects from the server.
     * This method sends a disconnect packet to the server and closes the networking client.
     * It should be called when the user wants to disconnect from the server.
     */
    fun disconnect() {
        pingJob?.cancel()
        // disconnect from server
        // send disconnect packet
        val payload = SodtPackets.DisconnectPayload(
            code = 100,
        )
        if (encryptionManager.hasClientSessionKeyFor(SodtConstants.SERVER_ID)) {
            sendEncryptedAesPacket(SodtConstants.SERVER_ID, payload)
        }

        CoroutineScope(Dispatchers.Default).launch {
            delay(100.milliseconds) // wait for the packet to be sent
            networkingClient.close()
            encryptionManager.close()
            connectedClients.clear()
            isInitiated = false
            Globals.clientID = 0u
            LogsActivity.addLog(logTag,"Disconnected from server")
        }
    }

    /**
     * Requests a key exchange with the specified receiver.
     * @param receiverID The ID of the client to exchange keys with.
     */
    open fun requestKeyExchange(receiverID: UByte) {
        require(receiverID != Globals.clientID) { "Cannot request key exchange with oneself." }
        require(connectedClients.contains(receiverID)) { "Client $receiverID is not connected." }

        LogsActivity.addLog(logTag,"Requesting key exchange with $receiverID")

        val payload = SodtPackets.KeyExchangePayload(
            code = 100,
            key = encryptionManager.createEcdhKeyPair(receiverID)
        )
        sendUnencryptedPacket(receiverID, payload)
    }

    /**
     * Handles the response to a key exchange request.
     * If the response code is 200 an AES session key is generated and stored in the encryption manager.
     */
    open fun respondToKeyExchange(remoteID: UByte, requestPacket: SodtPackets.KeyExchangePayload) {
        // handle possible errors
        if (requestPacket.key.isEmpty()) {
            LogsActivity.addErrorLog(logTag,"Key exchange failed with ${remoteID}: Key is empty")
            return
        }
        when (requestPacket.code) {
            100 -> {
                LogsActivity.addLog(logTag,"Key exchange requested by: $remoteID")
                acceptKeyExchange(remoteID, requestPacket)
                return
            }
            200 -> {
                LogsActivity.addLog(logTag,"Key exchange successful with $remoteID")
                // shared phrase is also generated and stored in the encryption manager
                encryptionManager.generateAndStoreAesSessionKeyFromKeyExchange(remoteID, requestPacket.key)
                return
            }
            300 -> {
                // remote client denied the key exchange request
                LogsActivity.addLog(logTag,"Key exchange denied by $remoteID")
                return
            }
            400 -> {
                // remote client failed the key exchange request
                LogsActivity.addLog(logTag,"Key exchange failed with $remoteID")
                return
            }
            else -> {
                LogsActivity.addLog(logTag,"Unknown key exchange code: ${requestPacket.code}")
                return
            }
        }
    }

    /**
     * Handles a received key exchange request by sending a code 200 key exchange back.
     * Also generates and stores an AES session key in the encryption manager.
     */
    open fun acceptKeyExchange(remoteID: UByte, requestPacket: SodtPackets.KeyExchangePayload) {
        val responsePacket = SodtPackets.KeyExchangePayload(
            code = 200,
            key = encryptionManager.createEcdhKeyPair(remoteID)
        )
        sendUnencryptedPacket(remoteID, responsePacket)
        encryptionManager.generateAndStoreAesSessionKeyFromKeyExchange(remoteID, requestPacket.key)
    }

    /**
     * Denies a key exchange request by sending a code 300 key exchange back.
     */
    open fun denyKeyExchange(remoteID: UByte) {
        LogsActivity.addLog(logTag,"Denying key exchange request from $remoteID")
        val responsePacket = SodtPackets.KeyExchangePayload(
            code = 300,
            key = ""
        )
        sendUnencryptedPacket(remoteID, responsePacket)
    }

    /**
     * Handles the client list received from the server.
     * This method updates the client list internal state and the UI state.
     */
    open fun receiveClientList(dataPacket: SodtPackets.ClientListPayload) {
        if (dataPacket.clients == null) {
            Log.w(logTag, "Empty client list")
            return
        }
        val clients =
            org.bouncycastle.util.encoders.Base64.decode(dataPacket.clients).joinToString(",")
                .split(",")
        // remove all old clients (clients that are in the sessionKeys map but not in the new client list)
        // this is necessary to dispose keys of clients that are no longer connected
        for (client in connectedClients) {
            if (!clients.contains(client.toString())) {
                // remove client from sessionKeys map
                LogsActivity.addLog(logTag,"Removing client $client from client list")
                encryptionManager.removeSessionKey(client)
            }
        }
        connectedClients.clear()
        for (client in clients) {
            val clientId = client.toUByteOrNull()
            // check if clientId is null or if it is the server ID
            if (clientId == null || clientId == SodtConstants.SERVER_ID || encryptionManager.hasClientSessionKeyFor(clientId) || clientId == Globals.clientID) {
                continue
            }
            connectedClients.add(clientId)
        }
    }

    /**
     * Handles the discovery response from the server.
     * This method sets the client ID and logs it.
     * @param dataPacket The discovery payload received from the server.
     */
    open fun receiveDiscoveryResponse(dataPacket: SodtPackets.DiscoveryPayload) {
        if (dataPacket.id.toInt() == 0 || dataPacket.signature == null) {
            LogsActivity.addErrorLog(logTag,"Illegal Discovery response received.")
            disconnect()
            return
        }
        if (dataPacket.code >= 300) {
            LogsActivity.addErrorLog(logTag,"Discovery response failed with code ${dataPacket.code}")
            disconnect()
            return
        }

        if (encryptionManager.verifySignature(serverCertificate, dataPacket)) {
            LogsActivity.addLog(logTag,"Discovery verified")
        } else {
            LogsActivity.addErrorLog(logTag,"Discovery not verified")
        }
        encryptionManager.generateAndStoreAesSessionKeyFromKeyExchange(SodtConstants.SERVER_ID, dataPacket.publicKey)


        Globals.clientID = dataPacket.id
        LogsActivity.addLog(logTag,"Your client ID is ${dataPacket.id}")
        startPinging() // start the pinging coroutine to the server to ensure connection is still alive
    }

    /**
     * Starts the pinging coroutine to the server.
     * The server needs at least one ping every 10 seconds to keep the connection alive.
     */
    fun startPinging() {
        // Stop any existing ping job before starting a new one
        pingJob?.cancel()
        // "Fire and forget" - launches a new coroutine
        pingJob = CoroutineScope(Dispatchers.Default).launch {
            // Equivalent to while(client.Connected)
            // isActive ensures the loop stops if the coroutine is canceled
            while (isActive) {
                delay(pingDelay) // Non-blocking delay (Equivalent to Task.Delay)
                if (!isInitiated) {
                    continue
                }

                try {
                    sendEncryptedAesPacket(SodtConstants.SERVER_ID, SodtPackets.PingPong(code = 100))
                } catch (e: Exception) {
                    Log.e("NetworkingClient", "Failed to send ping", e)
                }
            }
        }
    }

    /**
     * Creates and sends a file transfer request to the client that should receive the file.
     * @param receiverID The ID of the client that should receive the file.
     * @param fileUri The URI of the file to be sent.
     */
    fun requestFileTransfer(receiverID: UByte, fileUri: Uri) {
        val payload = SodtPackets.InitTransferPayload(
            code = 100,
            filename = fileManager.getFileName(fileUri),
            filesize = contentResolver.openAssetFileDescriptor(fileUri, "r")?.use { it.length } ?: -1L,
            filehash = fileManager.getFileHash(fileUri)
        )

        if (payload.filesize <= 0) {
            LogsActivity.addErrorLog(logTag, "Invalid file size for ${payload.filename}")
            return
        }

        pendingTransferRequests[payload.uuid] = fileUri
        sendEncryptedAesPacket(receiverID, payload)
    }

    /**
     * Responds to a file transfer request.
     * This method handles the initial transfer request and sends the appropriate response.
     * It also starts the file transfer if the request is accepted.
     * @param remoteID The ID of the client requesting the file transfer.
     * @param dataPacket The init transfer payload received from the client.
     */
    open fun respondToTransferRequest(remoteID: UByte, dataPacket: SodtPackets.InitTransferPayload) {
        when (dataPacket.code) {
            100 -> {
                LogsActivity.addLog(logTag, "Transfer request from $remoteID for file ${dataPacket.filename} of size ${dataPacket.filesize}")
                acceptTransferRequest(remoteID, dataPacket)
            }

            200 -> {
                LogsActivity.addLog(logTag, "Transfer request accepted for file ${dataPacket.filename} of size ${dataPacket.filesize}")
                sendFile(remoteID, dataPacket.uuid)
                // rest is handled in sendFile method
            }
            250 -> {} // acknowledgement message is handled in UIWrapper, nothing to do here
            300 -> {cleanIncomingTransfers(dataPacket.uuid)} // message handed in UIWrapper
            400 -> {cleanIncomingTransfers(dataPacket.uuid)} // message handed in UIWrapper

            else -> {
                LogsActivity.addErrorLog(logTag, "Transfer request failed. Code: ${dataPacket.code}")
                return
            }
        }
    }

    /**
     * Accepts a file transfer request by sending the appropriate response.
     * Also creates a new save stream for the file.
     * Furthermore, creates the entries in the incomingTransfers, incomingTransfersProcess and incomingTransferMetaData maps.
     * @param remoteID The ID of the client requesting the file transfer.
     * @param dataPacket The init transfer payload received from the client.
     */
    open fun acceptTransferRequest(remoteID: UByte, dataPacket: SodtPackets.InitTransferPayload) {
        // check if the file already exists in incoming transfers
        if (incomingTransfers.containsKey(dataPacket.uuid)) {
            LogsActivity.addErrorLog(logTag, "Transfer request for file ${dataPacket.filename} already exists")
            return
        }
        // add the transfer request to incoming transfers
        val file = fileManager.createNewSaveStream(dataPacket)
        if (file == null) {
            LogsActivity.addErrorLog(logTag, "Failed to create new file for transfer request")
            return
        }
        // save the transfer request
        incomingTransfers[dataPacket.uuid] = file
        incomingTransfersProgress[dataPacket.uuid] = dataPacket.filesize
        incomingTransferMetaData[dataPacket.uuid] = dataPacket
        // send response
        val responsePacket = SodtPackets.InitTransferPayload(
            code = 200,
            uuid = dataPacket.uuid,
            filename = dataPacket.filename,
            filesize = dataPacket.filesize,
            filehash = dataPacket.filehash
        )
        sendEncryptedAesPacket(remoteID, responsePacket)
    }

    /**
     * Denies a file transfer request by sending the appropriate response.
     * @param remoteID The ID of the client requesting the file transfer.
     * @param dataPacket The init transfer payload received from the client.
     */
    open fun denyTransferRequest(remoteID: UByte, dataPacket: SodtPackets.InitTransferPayload) {
        LogsActivity.addLog(logTag, "Denying transfer request for file ${dataPacket.filename} from $remoteID")
        cleanIncomingTransfers(dataPacket.uuid)
        val responsePacket = SodtPackets.InitTransferPayload(
            code = 300,
            uuid = dataPacket.uuid,
            filename = dataPacket.filename,
            filesize = dataPacket.filesize,
            filehash = dataPacket.filehash
        )
        sendEncryptedAesPacket(remoteID, responsePacket)
    }

    /**
     * Sends the file to the target client.
     * This method reads the file in chunks and sends it to the target client.
     * It uses a coroutine to perform the file transfer in the background.
     * After the file is sent, it removes the transfer request from the pending requests map.
     * @param targetId The ID of the target client to send the file to.
     * @param uuid The UUID of the transfer request.
     */
    protected open fun sendFile(targetId: UByte, uuid: Int) {
        val fileUri = pendingTransferRequests[uuid]
        if (fileUri == null) {
            LogsActivity.addErrorLog(logTag, "No file URI found for UUID $uuid")
            return
        }
        CoroutineScope(Dispatchers.IO).launch {
            val buffer = ByteArray(SodtConstants.FILE_BUFFER_SIZE)
            var bytesRead: Int
            try {
                // Open the file input stream
                contentResolver.openInputStream(fileUri)?.use { inputStream ->
                    var position: Long = 0
                    while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                        // Send the buffer data to the target
                        val dataPacket = SodtPackets.TransferDataPayload(
                            code = 200,
                            uuid = uuid,
                            // data as Base64 encoded string
                            data = Base64.encodeToString(buffer, 0, bytesRead, Base64.NO_WRAP),
                            position = position
                        )
                        position += bytesRead
                        sendEncryptedAesPacket(targetId, dataPacket)
                    }
                    LogsActivity.addLog(logTag, "Send File completed for UUID $uuid")
                }
            } catch (e: Exception) {
                LogsActivity.addErrorLog(logTag, "Error while reading or sending file: ${e.message}")
            } finally {
                pendingTransferRequests.remove(uuid)
            }
        }
        LogsActivity.addLog(logTag, "Sending file with UUID $uuid from URI $fileUri")
    }

    /**
     * Receives file data from the server.
     * This method is called when a data packet is received for a file transfer.
     * It writes the received data to the file output stream.
     * @param dataPacket The transfer data payload received from the server.
     */
    open fun receiveFileData(remoteId: UByte, dataPacket: SodtPackets.TransferDataPayload) {
        // check if the transfer request exists
        if (!incomingTransfers.containsKey(dataPacket.uuid)) {
            LogsActivity.addErrorLog(logTag, "No accepted transfer found for UUID ${dataPacket.uuid}")
            return
        }
        // get the output stream for the file
        val file = incomingTransfers[dataPacket.uuid] ?: run {
            LogsActivity.addErrorLog(logTag, "No output stream found for UUID ${dataPacket.uuid}")
            return
        }
        // write data
        val dataBytes = Base64.decode(dataPacket.data, Base64.NO_WRAP)
        FileOutputStream(file.fileDescriptor).channel.use { channel ->
            channel.position(dataPacket.position)
            channel.write(ByteBuffer.wrap(dataBytes))
        }
        // lock the incomingTransfersProgress map to avoid concurrent modification
        CoroutineScope(Dispatchers.Main).launch {
            incomingTransfersProgressMutex.withLock {
                // update the remaining size of the transfer
                incomingTransfersProgress[dataPacket.uuid] =
                    incomingTransfersProgress[dataPacket.uuid]!! - dataBytes.size
            }
            // if transfer is complete
            if (incomingTransfersProgress[dataPacket.uuid] == 0L) {
                LogsActivity.addLog(logTag, "File transfer completed for UUID ${dataPacket.uuid}")
                // send acknowledgement
                val initialTransfer = incomingTransferMetaData[dataPacket.uuid] ?: return@launch
                val ack = SodtPackets.InitTransferPayload(
                    code = 250,
                    filename = initialTransfer.filename,
                    filesize = initialTransfer.filesize,
                    filehash = initialTransfer.filehash)
                sendEncryptedAesPacket(remoteId, ack)
                cleanIncomingTransfers(dataPacket.uuid)
            }
        }
    }

    /**
     * Removes the transfer request from incomingTransfers, incomingTransfersProgress and incomingTransferMetaData.
     * If a parcelFileDescriptor is present, it is closed.
     */
    private fun cleanIncomingTransfers(transferUuid: Int) {
        incomingTransfers[transferUuid]?.close()
        incomingTransfers.remove(transferUuid)
        incomingTransfersProgress.remove(transferUuid)
        incomingTransferMetaData.remove(transferUuid)
    }
}