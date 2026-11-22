package de.host.sodtmobile.utils

import com.google.gson.Gson
import com.google.gson.JsonParser
import de.host.sodtmobile.activities.LogsActivity

/** * SodtReceiver is responsible for handling incoming data packets from the server.
 * It decrypts the received data and converts it into a SodtPacket for further processing.
 * It implements IDataReceivedEventListener to listen for incoming data events.
 *
 * @property encryptionManager The EncryptionManager used for decrypting packets.
 * @property sodtClient The SodtClient instance to handle the received packets.
 */
class SodtReceiver (
    private val encryptionManager: EncryptionManager,
    private val sodtClient: SodtClient) : IDataReceivedEventListener {

    private val logTag = "Receiver"

    private fun bytesToUShort(byte1: Byte, byte2: Byte): UShort {
        return ((byte2.toInt() and 0xFF) shl 8 or (byte1.toInt() and 0xFF)).toUShort()
    }

    /**
     * Converts a received packet from the server into a SodtPacket.
     * This method parses the JSON string into a SodtPacket object
     * and calls the appropriate method to handle the packet.
     */
    private fun convertPacket(sourceId: UByte, buffer: ByteArray) {
        val json = String(buffer, Charsets.UTF_8)
        val gson = Gson()
        val jsonObject = JsonParser.parseString(json).asJsonObject
        val type = jsonObject["type"].asString

        when (type) {
            "discovery" -> sodtClient.receiveDiscoveryResponse(gson.fromJson(json, SodtPackets.DiscoveryPayload::class.java))
            "pingpong" -> return // pinpong are only used for keep alive, no action is needed
            "clients" -> sodtClient.receiveClientList(gson.fromJson(json, SodtPackets.ClientListPayload::class.java))
            "exchange" -> sodtClient.respondToKeyExchange(sourceId, gson.fromJson(json, SodtPackets.KeyExchangePayload::class.java))
            "transfer" -> sodtClient.respondToTransferRequest(sourceId, gson.fromJson(json, SodtPackets.InitTransferPayload::class.java))
            "file" -> sodtClient.receiveFileData(sourceId, gson.fromJson(json, SodtPackets.TransferDataPayload::class.java))
            "disconnect" -> sodtClient.disconnect()
            else -> throw IllegalArgumentException("Unknown packet")
        }
    }

    /**
     * Handles incoming data packets.
     * This method is called when data is received from the server.
     * It decrypts the payload and processes the message.
     *
     * @param dataPacket The received data packet as a ByteArray.
     */
    override fun onDataReceived(dataPacket: ByteArray) {
        val sourceId: UByte = dataPacket[1].toUByte()
        val nonceAndTag = dataPacket.slice(SodtConstants.ID_SIZE until SodtConstants.HEADER_SIZE_WITHOUT_CONTENT_LENGTH)

        // check if nonce and tag are all zeros => message is unencrypted
        val decryptedMessage: ByteArray? =
        if (nonceAndTag.all { it == 0.toByte() }) {
             dataPacket.slice(SodtConstants.HEADER_SIZE_WITHOUT_CONTENT_LENGTH until dataPacket.size).toByteArray()
        }
        else{
             encryptionManager.decryptAesGcm(sourceId, dataPacket)
        }

        if (decryptedMessage == null) {
            LogsActivity.addErrorLog(logTag, "Decryption failed for source ID: $sourceId")
            return
        }
        // the first two bytes are the size of the message
        val size = bytesToUShort(decryptedMessage[0], decryptedMessage[1])
        // get message from decrypted packet
        val finalDecryptedMessage = decryptedMessage.slice(SodtConstants.CONTENT_LENGTH_SIZE until  (SodtConstants.CONTENT_LENGTH_SIZE + size.toInt())).toByteArray()
        convertPacket(sourceId, finalDecryptedMessage)
    }
}