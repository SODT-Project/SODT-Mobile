package de.host.sodtmobile.utils

import android.R.attr.mimeType
import android.content.ContentResolver
import android.content.ContentValues
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.MediaStore
import android.provider.OpenableColumns
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
import java.security.MessageDigest

/** * SodtClient is the main class for the Sodt client.
 * It handles the connection to the server, sending and receiving packets, and file transfers.
 * It uses the NetworkingClient to handle the network communication and the EncryptionManager to handle encryption.
 * @param serverAddress The address of the server to connect to.
 * @param serverPort The port of the server to connect to.
 * @param encryptionKey The key used for encryption.
 * @param contentResolver The ContentResolver used to access files.
 */
open class SodtClient(
    serverAddress: String,
    serverPort: Int,
    private val serverCertificate: String,
    private val contentResolver: ContentResolver
) {


    protected var encryptionManager: EncryptionManager = EncryptionManager()
    private var pingJob: Job? = null
    private var sodtReceiver: SodtReceiver =
        SodtReceiver(encryptionManager, this) // not ideal logic but it works
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
    private val incomingTransfers = mutableMapOf<Int, ParcelFileDescriptor>()

    private val incomingTransferMetaData = mutableMapOf<Int, SodtPackets.InitTransferPayload>()

    /**
     * Map to store incoming transfers progress.
     * Key is the uuid of the transfer request.
     * Value is the remaining size of the file to be transferred. Therefore 0 means the transfer is complete.
     */
    internal val incomingTransfersProgress = mutableMapOf<Int, Long>()
    private val incomingTransfersProgressMutex = Mutex()
    private val TAG = "SodtClient"
    val isConnected: Boolean
        get() = networkingClient.isConnected

    init {
        CoroutineScope(Dispatchers.Default).launch {
            val connected = networkingClient.connect()
            if (connected == true) {
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
                LogsActivity.addLog("Failed to encrypt packet for client $receiverID")
                Log.e(TAG, "Failed to encrypt packet for client $receiverID")
                return@launch
            }
            networkingClient.sendData(receiverID, encryptedPacket)
        }
    }

    protected fun sendUnencryptedPacket(receiverID: UByte, dataPaket: SodtPackets.IBasePacket) {
        CoroutineScope(Dispatchers.Default).launch {
            val cryptoHeader = ByteArray(SodtConstants.TAG_SIZE + SodtConstants.NONCE_SIZE)
            networkingClient.sendData(receiverID, cryptoHeader + dataPaket.toByteArray())
        }
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
        if (encryptionManager.hasClientSessionKeyFor(Globals.SERVER_ID)) {
            sendEncryptedAesPacket(Globals.SERVER_ID, payload)
        }

        CoroutineScope(Dispatchers.Default).launch {
            delay(100) // wait for the packet to be sent
            networkingClient.close()
            encryptionManager.close()
            connectedClients.clear()
            isInitiated = false
            LogsActivity.addLog("Disconnected from server")
            Log.d(TAG, "Disconnected from server")
        }
    }

    /**
     * Requests a key exchange with the specified receiver.
     */
    private fun requestKeyExchange(receiverID: UByte) {
        require(receiverID != Globals.clientID) { "Cannot request key exchange with oneself." }
        require(connectedClients.contains(receiverID)) { "Client $receiverID is not connected." }

        LogsActivity.addLog("Requesting key exchange with $receiverID")
        Log.d(TAG, "Requesting key exchange with $receiverID")

        val payload = SodtPackets.KeyExchangePayload(
            code = 100,
            key = encryptionManager.createEcdhKeyPair(receiverID)
        )
        sendUnencryptedPacket(receiverID, payload)
    }

    open fun respondToKeyExchange(remoteID: UByte, requestPacket: SodtPackets.KeyExchangePayload) {
        // handle possible errors
        if (requestPacket.key.isEmpty()) {
            LogsActivity.addLog("Key exchange failed with ${remoteID}: Key is empty")
            Log.e(TAG, "Key exchange failed: Key is empty")
            return
        }
        when (requestPacket.code) {
            100 -> {
                LogsActivity.addLog("Key exchange requested by: $remoteID")
                Log.d(TAG, "Key exchange requested by : $remoteID")
                acceptKeyExchange(remoteID, requestPacket)
                return
            }

            200 -> {
                LogsActivity.addLog("Key exchange successful with $remoteID")
                Log.d(TAG, "Key exchange successful with $remoteID")
            }

            300 -> {
                // remote client denied the key exchange request
                LogsActivity.addLog("Key exchange denied by $remoteID")
                Log.d(TAG, "Key exchange denied by $remoteID")
                return
            }
            400 -> {
                // remote client failed the key exchange request
                LogsActivity.addLog("Key exchange failed with $remoteID")
                Log.d(TAG, "Key exchange failed with $remoteID")
                return
            }

            else -> {
                LogsActivity.addLog("Unknown key exchange code: ${requestPacket.code}")
                Log.e(TAG, "Unknown key exchange code: ${requestPacket.code}")
                return
            }
        }
        // generate key exchange pair from dataPacket (if code was 100 or 200)
        // shared phrase is also generated and stored in the encryption manager
        encryptionManager.generateAndStoreAesSessionKeyFromKeyExchange(remoteID, requestPacket.key)
    }

    open fun acceptKeyExchange(remoteID: UByte, requestPacket: SodtPackets.KeyExchangePayload) {
        val responsePacket = SodtPackets.KeyExchangePayload(
            code = 200,
            key = encryptionManager.createEcdhKeyPair(remoteID)
        )
        sendUnencryptedPacket(remoteID, responsePacket)
        encryptionManager.generateAndStoreAesSessionKeyFromKeyExchange(remoteID, requestPacket.key)
    }

    open fun denyKeyExchange(remoteID: UByte) {
        LogsActivity.addLog("Denying key exchange request from $remoteID")
        Log.d(TAG, "Denying key exchange request from $remoteID")
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
            Log.w(TAG, "Empty client list")
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
                LogsActivity.addLog("Removing client $client from client list")
                Log.d(TAG, "Removing client $client from client list")
                encryptionManager.removeSessionKey(client)
            }
        }
        // request key exchange for all clients that are not the server and do not have a session key yet
        for (client in clients) {
            val clientId = client.toUByteOrNull()
            // check if clientId is null or if it is the server ID
            if (clientId == null || clientId == Globals.SERVER_ID || encryptionManager.hasClientSessionKeyFor(clientId) || clientId == Globals.clientID) {
                continue
            }
            connectedClients.add(clientId)
            //requestKeyExchange(clientId) // TODO
        }
    }

    /**
     * Handles the discovery response from the server.
     * This method sets the client ID and logs it.
     * @param dataPacket The discovery payload received from the server.
     */
    fun receiveDiscoveryResponse(dataPacket: SodtPackets.DiscoveryPayload) {
        if (dataPacket.id.toInt() == 0 || dataPacket.signature == null) {
            LogsActivity.addLog("Illegal Discovery response received.")
            disconnect()
            return
        }
        if (dataPacket.code >= 300) {
            LogsActivity.addLog("Discovery response failed with code ${dataPacket.code}")
            disconnect()
            return
        }

        if (encryptionManager.verifySignature(serverCertificate, dataPacket)) {
            LogsActivity.addLog("Discovery verified")
            Log.d(TAG, "Discovery verified")
        } else {
            LogsActivity.addLog("Discovery not verified") // TODO add to UI
            Log.w(TAG, "Discovery not verified")
        }
        encryptionManager.generateAndStoreAesSessionKeyFromKeyExchange(Globals.SERVER_ID, dataPacket.publicKey)


        Globals.clientID = dataPacket.id
        LogsActivity.addLog("Your client ID is ${dataPacket.id}")
        Log.d(TAG, "Your ID: ${dataPacket.id}")
        startPinging()
    }


    private fun initialDiscovery() {

        val payload = SodtPackets.DiscoveryPayload(
            id = 0u,
            code = 100,
            publicKey = encryptionManager.createEcdhKeyPair(SodtConstants.SERVER_ID),
            signature = null
        )
        sendUnencryptedPacket(SodtConstants.SERVER_ID, payload)
    }
    fun startPinging() {
        // Stop any existing ping job before starting a new one
        pingJob?.cancel()
        // "Fire and forget" - launches a new coroutine
        pingJob = CoroutineScope(Dispatchers.Default).launch {
            // Equivalent to while(client.Connected)
            // isActive ensures the loop stops if the coroutine is cancelled

            while (isActive) {
                delay(3000) // Non-blocking delay (Equivalent to Task.Delay)
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
     * Calculates the SHA-256 hash of a file provided via Uri.
     * Returns the base64 encoded hash as a String.
     */
    private fun getFileHash(fileUri: Uri): String {
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            contentResolver.openInputStream(fileUri)?.use { inputStream ->
                val buffer = ByteArray(8192)
                var bytesRead: Int
                while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                    digest.update(buffer, 0, bytesRead)
                }
            }
            // Convert byte array to Hex String
            Base64.encodeToString(digest.digest(), Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to calculate hash for $fileUri", e)
            throw e;
        }
    }

    private fun getFileName(fileUri: Uri): String{
        return (contentResolver.query(fileUri, null, null, null, null)?.use { cursor ->
            val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (index != -1 && cursor.moveToFirst()) {
                cursor.getString(index)
            } else {
                null
            }
        }) ?: "unknown_file"
    }

    fun requestFileTransfer(receiverID: UByte, fileUri: Uri) {
        val payload = SodtPackets.InitTransferPayload(
            code = 100,
            filename = getFileName(fileUri),
            filesize = contentResolver.openAssetFileDescriptor(fileUri, "r")?.use { it.length } ?: -1L,
            filehash = getFileHash(fileUri)
        )

        if (payload.filesize <= 0) {
            LogsActivity.addLog("Invalid file size for ${payload.filename}")
            Log.e(TAG, "Invalid file size for ${payload.filename}")
            return
        }

        pendingTransferRequests.put(payload.uuid, fileUri)
        // send
        sendEncryptedAesPacket(receiverID, payload)
    }

    /**
     * Responds to a file transfer request.
     * This method handles the initial transfer request and sends the appropriate response.
     * It also starts the file transfer if the request is accepted.
     * @param dataPacket The init transfer payload received from the client.
     */
    open fun respondToTransferRequest(remoteID: UByte, dataPacket: SodtPackets.InitTransferPayload) {
        when (dataPacket.code) {
            100 -> {
                LogsActivity.addLog(
                    "Transfer request from $remoteID for file ${dataPacket.filename} of size ${dataPacket.filesize}"
                )
                Log.d(
                    TAG,
                    "Transfer request from $remoteID for file ${dataPacket.filename} of size ${dataPacket.filesize}"
                )
                acceptTransferRequest(remoteID, dataPacket)
            }

            200 -> {
                LogsActivity.addLog("Transfer request accepted for file ${dataPacket.filename} of size ${dataPacket.filesize}")
                Log.d(
                    TAG,
                    "Transfer request accepted for file ${dataPacket.filename} of size ${dataPacket.filesize}"
                )
                sendFile(remoteID, dataPacket.uuid)
                // rest is handled in sendFile method
            }
            250 -> {} // acknowledgement message is handled in UIWrapper, nothing to do here
            300 -> {cleanIncomingTransfers(dataPacket.uuid)} // message handed in UIWrapper
            400 -> {cleanIncomingTransfers(dataPacket.uuid)} // message handed in UIWrapper

            else -> {
                LogsActivity.addLog("Transfer request failed. Code: ${dataPacket.code}")
                Log.e(TAG, "Transfer request failed. Code: ${dataPacket.code}")
                return
            }
        }
    }

    open fun acceptTransferRequest(remoteID: UByte, dataPacket: SodtPackets.InitTransferPayload) {
        // check if the file already exists in incoming transfers
        if (incomingTransfers.containsKey(dataPacket.uuid)) {
            LogsActivity.addLog("Transfer request for file ${dataPacket.filename} already exists")
            Log.w(TAG, "Transfer request for file ${dataPacket.filename} already exists")
            return
        }
        // add the transfer request to incoming transfers
        val file = createNewSaveStream(dataPacket)
        if (file == null) {
            LogsActivity.addLog("Failed to create new file for transfer request")
            Log.e(TAG, "Failed to create new file for transfer request")
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

    open fun denyTransferRequest(remoteID: UByte, dataPacket: SodtPackets.InitTransferPayload) {
        LogsActivity.addLog("Denying transfer request for file ${dataPacket.filename} from $remoteID")
        Log.d(TAG, "Denying transfer request for file ${dataPacket.filename} from $remoteID")
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
     * Checks if a file with the given name is present in the device's Downloads directory.
     *
     * This function queries the MediaStore.Downloads content provider to get a list of
     * filenames in the external Downloads directory. It then checks if the provided
     * `fileName` exists in that list.
     *
     * Note: This function is suitable for API level 29 and above, as it uses
     * `MediaStore.Downloads.EXTERNAL_CONTENT_URI`.
     *
     * @param fileName The name of the file to search for (e.g., "my_document.pdf").
     * @return `true` if a file with the specified name exists in the Downloads directory,
     *         `false` otherwise.
     */
    private fun isPresentInDownloads(fileName: String): Boolean {
        // URI for external Download collection (API 29+)
        val downloadsUri = MediaStore.Downloads.EXTERNAL_CONTENT_URI

        // We only need the DISPLAY_NAME column to get the filename
        val projection = arrayOf(MediaStore.Downloads.DISPLAY_NAME)
        val fileNames = mutableListOf<String>()

        contentResolver.query(
            downloadsUri,
            projection,
            /* no selection = all rows */ null,
            /* no selection args */ null,
            /* optional sort: most recent first */ "${MediaStore.Downloads.DATE_ADDED} DESC"
        )?.use { cursor ->
            val nameIdx = cursor.getColumnIndexOrThrow(MediaStore.Downloads.DISPLAY_NAME)
            while (cursor.moveToNext()) {
                fileNames += cursor.getString(nameIdx)
            }
        }

        return fileNames.contains(fileName)
    }

    /**
     * Creates a new save stream for the file transfer.
     * This method creates a new file in the Downloads directory and returns an OutputStream to write the file data.
     * Uses MediaStore to create a new file in the Downloads directory. (permission is not needed for Android 10+)
     */
    private fun createNewSaveStream(dataPacket: SodtPackets.InitTransferPayload): ParcelFileDescriptor? {
        // create filename
        val fileNameWithoutExtension = dataPacket.filename.substringBeforeLast('.')
        val extension = dataPacket.filename.substringAfterLast('.', "").substringBefore(" ").lowercase()
        var renamedFile = dataPacket.filename
        var counter = 1
        while (isPresentInDownloads(renamedFile)){
            renamedFile = "$fileNameWithoutExtension ${counter}.$extension"
            counter++
        }

        // create file
        val contentValues = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, renamedFile)
            put(MediaStore.Downloads.MIME_TYPE, getMimeTypeForExtension(extension))
            put(MediaStore.Downloads.IS_PENDING, 1)
            put(MediaStore.Downloads.SIZE, dataPacket.filesize)
        }

        val uri = contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)
            ?: run {
                LogsActivity.addLog("Failed to create new file in Downloads directory")
                Log.e(TAG, "Failed to create new file in Downloads directory")
                return null
            }

        val pfd = try {
            contentResolver.openFileDescriptor(uri, "rw")
        } catch (e: Exception) {
            LogsActivity.addLog("Failed to open file descriptor: ${e.message}")
            Log.e(TAG, "Failed to open file descriptor", e)
            return null
        }

        // fill with dummy data to reserve space
        pfd?.fileDescriptor?.let { fd ->
            FileOutputStream(fd).use { fos ->
                // ByteArray takes only int as size, so we need to write the size multiple times if it's larger than Int.MAX_VALUE
                var size = dataPacket.filesize
                while (size > Int.MAX_VALUE) {
                    fos.write(ByteArray(Int.MAX_VALUE)) // write max size chunk
                    size -= Int.MAX_VALUE.toLong()
                }
                fos.write(ByteArray(size.toInt()))
                fos.flush()
            }
        }

        // make the file available for writing
        contentValues.clear()
        contentValues.put(MediaStore.Downloads.IS_PENDING, 0)
        contentResolver.update(uri, contentValues, null, null)

        return try {
            contentResolver.openFileDescriptor(uri, "rw")
        } catch (e: Exception) {
            LogsActivity.addLog("Failed to reopen file descriptor: ${e.message}")
            Log.e(TAG, "Failed to reopen file descriptor", e)
            null
        }
    }

    /** * Detects the MIME type of a file based on its extension.
     * This method checks the file extension and returns the corresponding MIME type.
     * If the extension is not recognized, it tries to use the default MIME type.
     * This method is needed because is auto-detection of MIME type is not always reliable,
     * @param fileName The name of the file to detect the MIME type for.
     * @return The MIME type of the file as an Int.
     */
    private fun getMimeTypeForExtension(extension: String): Int {
        return when (extension.replace(".","").lowercase()) {
            "jpg", "jpeg" -> MediaStore.Files.FileColumns.MEDIA_TYPE_IMAGE
            "png" -> MediaStore.Files.FileColumns.MEDIA_TYPE_IMAGE
            "gif" -> MediaStore.Files.FileColumns.MEDIA_TYPE_IMAGE
            "mp4" -> MediaStore.Files.FileColumns.MEDIA_TYPE_VIDEO
            "mp3" -> MediaStore.Files.FileColumns.MEDIA_TYPE_AUDIO
            "pdf", "txt", "html", "htm", "json", "xml" -> MediaStore.Files.FileColumns.MEDIA_TYPE_DOCUMENT
            else -> mimeType // try to auto-detect the MIME type
        }
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
            LogsActivity.addLog("No file URI found for UUID $uuid")
            Log.e(TAG, "No file URI found for UUID $uuid")
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
                    LogsActivity.addLog("Send File completed for UUID $uuid")
                    Log.d(TAG, "Send File completed for UUID $uuid")
                }
            } catch (e: Exception) {
                LogsActivity.addLog("Error while reading or sending file: ${e.message}")
                Log.e(TAG, "Error while reading or sending file: ${e.message}")
            } finally {
                pendingTransferRequests.remove(uuid)
            }
        }
        LogsActivity.addLog("Sending file with UUID $uuid from URI $fileUri")
        Log.d(TAG, "Sending file with UUID $uuid from URI $fileUri")
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
            LogsActivity.addLog("No accepted transfer found for UUID ${dataPacket.uuid}")
            Log.e(TAG, "No accepted transfer found for UUID ${dataPacket.uuid}")
            return
        }
        // get the output stream for the file
        val file = incomingTransfers[dataPacket.uuid] ?: run {
            LogsActivity.addLog("No output stream found for UUID ${dataPacket.uuid}")
            Log.e(TAG, "No output stream found for UUID ${dataPacket.uuid}")
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
                LogsActivity.addLog("File transfer completed for UUID ${dataPacket.uuid}")
                Log.d(TAG, "File transfer completed for UUID ${dataPacket.uuid}")
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
    private fun cleanIncomingTransfers(transferUuid: Int) {
        incomingTransfers[transferUuid]?.close()
        incomingTransfers.remove(transferUuid)
        incomingTransfersProgress.remove(transferUuid)
        incomingTransferMetaData.remove(transferUuid)
    }
}