package de.host.sodtmobile.utils

import com.google.gson.Gson
import org.bouncycastle.asn1.ocsp.Signature
import java.util.UUID

/** * This object contains all packets used in the SODT protocol.
 * Each packet is represented by a data class that implements the IBasePacket interface.
 * The packets are used for communication between the client and server.
 * Each packet has a type, code, uuid, and other specific fields depending on the packet type.
 */
class SodtPackets {

    /**
     * Base interface for all packets used in the SODT protocol.
     * Each packet must implement this interface to ensure it has the necessary properties and methods.
     */
    interface IBasePacket{
        val type: String
        val code: Int
        val uuid: Int

        /**
         * Converts the packet to a JSON string.
         * This method is used to serialize the packet for transmission over the network.
         * It must be implemented in each packet individually to ensure that all fields are included.
         * @return JSON string representation of the packet.
         */
        fun toJson(): String

        fun toByteArray(): ByteArray{
            // get json and size
            val json = this.toJson()
            require(json.length <= 0xFFFF) { "Data too large to fit in UShort" }
            val size = json.length.toUShort()
            // convert to byte array
            val sizeBytes = byteArrayOf(
                (size.toInt() and 0xFF).toByte(),
                (size.toInt() shr 8 and 0xFF).toByte()
            )
            val padding = ByteArray(SodtConstants.MESSAGE_WITH_CONTENT_SIZE - sizeBytes.size - json.toByteArray(Charsets.UTF_8).size) { (0..255).random().toByte() }
            // return
            return sizeBytes + json.toByteArray(Charsets.UTF_8) + padding
        }
    }

    data class DiscoveryPayload(
        val id : UByte,
        override val type: String = "discovery",
        override val code: Int,
        override val uuid: Int = UUID.randomUUID().hashCode(),
        val publicKey: String,
        val signature: String?
    ) : IBasePacket {
        override fun toJson(): String {
            return Gson().toJson(this)
        }
    }

    data class ClientListPayload(
        override val type: String = "clients",
        override val code: Int,
        override val uuid: Int = UUID.randomUUID().hashCode(),
        val clients: String?
    ) : IBasePacket {
        override fun toJson(): String {
            return Gson().toJson(this)
        }
    }

    data class KeyExchangePayload(
        override val type: String = "exchange",
        override val code: Int,
        override val uuid: Int = UUID.randomUUID().hashCode(),
        val key: String,
    ) : IBasePacket {
        override fun toJson(): String {
            return Gson().toJson(this)
        }
    }

    data class DisconnectPayload(
        override val type: String = "disconnect",
        override val code: Int,
        override val uuid: Int = UUID.randomUUID().hashCode(),
    ) : IBasePacket {
        override fun toJson(): String {
            return Gson().toJson(this)
        }
    }

    data class InitTransferPayload(
        override val type: String = "transfer",
        override val code: Int,
        override val uuid: Int = UUID.randomUUID().hashCode(),
        val filename: String,
        val filesize: Long, // DO NOT RENAME filesize, it must have the same the name like in the json file
        val filehash: String // DO NOT RENAME filehash, ...
    ) : IBasePacket {
        override fun toJson(): String {
            return Gson().toJson(this)
        }
    }

    data class TransferDataPayload(
        override val type: String = "file",
        override val code: Int,
        override val uuid: Int = UUID.randomUUID().hashCode(),
        val data: String,
        val position: Long
    ) : IBasePacket {
        override fun toJson(): String {
            return Gson().toJson(this)
        }
    }

    data class PingPong(
        override val type: String = "pingpong",
        override val code: Int,
        override val uuid: Int = UUID.randomUUID().hashCode(),
    ) : IBasePacket {
        override fun toJson(): String {
            return Gson().toJson(this)
        }
    }
}