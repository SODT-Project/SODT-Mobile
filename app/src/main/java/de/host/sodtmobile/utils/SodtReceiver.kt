package de.host.sodtmobile.utils

import android.util.Log
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

    private val TAG = "Receiver"

    private fun bytesToUShort(byte1: Byte, byte2: Byte): UShort {
        return ((byte2.toInt() and 0xFF) shl 8 or (byte1.toInt() and 0xFF)).toUShort()
    }

    /**
     * Converts a received packet from the server into a SodtPacket.
     * This method parses the JSON string into a SodtPacket object
     * and calls the appropriate method to handle the packet.
     */
    private fun convertPacket(buffer: ByteArray) {
        val json = String(buffer, Charsets.UTF_8)
        val gson = Gson()
        val jsonObject = JsonParser.parseString(json).asJsonObject
        val type = jsonObject["type"].asString
        val statusCode = jsonObject["code"].asInt

        if (statusCode == 400) {
            LogsActivity.addLog("Error request received (Code 400): $json")
            Log.e(TAG, "Invalid Request")
            return
        }

        when (type) {
            "discovery" -> sodtClient.receiveDiscoveryResponse(gson.fromJson(json, SodtPackets.DiscoveryPayload::class.java))
            "clients" -> sodtClient.receiveClientList(gson.fromJson(json, SodtPackets.ClientListPayload::class.java))
            "exchange" -> sodtClient.respondToKeyExchange(gson.fromJson(json, SodtPackets.KeyExchangePayload::class.java))
            "transfer" -> sodtClient.respondToTransferRequest(gson.fromJson(json, SodtPackets.InitTransferPayload::class.java))
            "file" -> sodtClient.receiveFileData(gson.fromJson(json, SodtPackets.TransferDataPayload::class.java))
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
        // removes the sender and receiver bytes
        val payload = dataPacket.slice(2 until dataPacket.size).toByteArray()
        // decrypt the payload with AES
        val decryptedPacket = if (sourceId == Globals.SERVER_ID) {
            encryptionManager.decryptWithAesServer(payload)
        } else {
            encryptionManager.decryptWithAesClient(sourceId, payload)
        }
        if (decryptedPacket == null) {
            LogsActivity.addLog("Decryption failed for source ID: $sourceId")
            Log.e(TAG, "Decryption failed for source ID: $sourceId")
            return
        }
        // the first two bytes are the size of the message
        val size = bytesToUShort(decryptedPacket[0], decryptedPacket[1])
        // get message from decrypted packet
        val decryptedMessage = decryptedPacket.slice(2 until  (2 + size.toInt())).toByteArray()
        convertPacket(decryptedMessage)
    }
}