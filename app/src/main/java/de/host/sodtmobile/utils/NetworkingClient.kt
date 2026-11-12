package de.host.sodtmobile.utils
import android.util.Log
import de.host.sodtmobile.activities.LogsActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import java.security.SecureRandom

class NetworkingClient(private val receivedEventListener: IDataReceivedEventListener,
                       private val serverAddress: String,
                       private val serverPort: Int) {

    private var socket: Socket? = null
    private var inputStream: InputStream? = null
    private var outputStream: OutputStream? = null

    // Job to control the lifecycle of the continuous receive coroutine
    private var receiveJob: Job? = null
    private val clientScope = CoroutineScope(Dispatchers.IO) // Scope for network operations

    private val TAG = "NetworkingClient"
    private val secureRandom = SecureRandom()

    val isConnected: Boolean
        get() = socket?.isConnected == true && receiveJob?.isActive == true

    /**
     * Establishes a connection to the server.
     * This method should be called on a background thread.
     */
    suspend fun connect(): Boolean = withContext(Dispatchers.IO) {
        try {
            socket = Socket(serverAddress, serverPort)
            inputStream = socket?.getInputStream()
            outputStream = socket?.getOutputStream()
            LogsActivity.addLog("Connected to server: $serverAddress:$serverPort")
            Log.d(TAG, "Connected to server: $serverAddress:$serverPort")
            startReceiving() // Start listening for messages immediately after connecting
            true
        } catch (e: IOException) {
            LogsActivity.addLog("Error connecting to server: ${e.message}")
            Log.e(TAG, "Error connecting to server: ${e.message}")
            close() // Ensure resources are closed on failure
            false
        }
    }

    private fun prependSourceIdAndTargetId(byte1: UByte, byte2: UByte, data: ByteArray): ByteArray {
        val prefix = byteArrayOf(byte1.toByte(), byte2.toByte())
        return prefix + data
    }
    /**
     * Sends data to the server.
     * This method should be called on a background thread.
     */
    suspend fun sendData(targetId: UByte, data: ByteArray): Boolean = withContext(Dispatchers.IO) {
        if (socket?.isConnected != true || outputStream == null) {
            Log.e(TAG, "Not connected to server or output stream is null. Cannot send data.")
            return@withContext false
        }
        return@withContext try {
            val dataWithIds = prependSourceIdAndTargetId(targetId, Globals.clientID, data)
            require(dataWithIds.size == SodtConstants.FULL_MESSAGE_SIZE) { "Data size must be exactly ${SodtConstants.FULL_MESSAGE_SIZE} bytes, but was ${dataWithIds.size}" }
            outputStream?.write(dataWithIds)
            outputStream?.flush() // Important to flush the stream to ensure data is sent
            true
        } catch (e: IOException) {
            Log.e(TAG, "Error sending data: ${e.message}")
            close() // Connection likely lost
            false
        }
    }

    /**
     * Starts a continuous loop to receive data from the server.
     * This runs on a separate coroutine.
     */
    private fun startReceiving() {
        receiveJob?.cancel()
        receiveJob = clientScope.launch(Dispatchers.IO) {
            val buffer = ByteArray(SodtConstants.FULL_MESSAGE_SIZE)
            val accumulated = mutableListOf<Byte>()

            while (isActive && socket?.isConnected == true && inputStream != null) {
                try {
                    val bytesRead = inputStream?.read(buffer)
                    if (bytesRead != null && bytesRead > 0) {
                        // Add new bytes to accumulated buffer
                        accumulated.addAll(buffer.take(bytesRead))

                        // Try to extract complete messages if full messages are available
                        while (accumulated.size >= SodtConstants.FULL_MESSAGE_SIZE) {

                            // Check if full message is available
                            val encryptedDataPacket = accumulated.subList(0, SodtConstants.FULL_MESSAGE_SIZE).toByteArray()
                            CoroutineScope(Dispatchers.Default).launch {
                                receivedEventListener.onDataReceived(encryptedDataPacket)
                            }
                            // Remove processed message
                            accumulated.subList(0, 4096).clear()
                        }
                    } else if (bytesRead == -1) {
                        LogsActivity.addLog("End of stream reached. Server closed connection.")
                        Log.d(TAG, "End of stream reached. Server closed connection.")
                        close()
                        break
                    }
                } catch (e: IOException) {
                    if (isActive) {
                        LogsActivity.addLog("Error receiving data: ${e.message}")
                        Log.e(TAG, "Error receiving data: ${e.message}")
                    }
                    close()
                    break
                } catch (e: Exception) {
                    LogsActivity.addLog("Unexpected error in receive loop: ${e.message}")
                    Log.e(TAG, "Unexpected error in receive loop: ${e.message}")
                    close()
                    break
                }
            }
            Log.d(TAG, "Receive loop stopped.")
        }
    }


    /**
     * Stops the continuous receiving coroutine.
     */
    private fun stopReceiving() {
        receiveJob?.cancel()
        receiveJob = null
    }

    /**
     * Closes the connection and releases resources.
     * This method should be called on a background thread.
     */
    fun close() {
        stopReceiving() // Stop the receiving coroutine first
        try {
            outputStream?.close()
            inputStream?.close()
            socket?.close()
            LogsActivity.addLog("Connection closed to $serverAddress:$serverPort")
            Log.d(TAG, "Connection closed.")
        } catch (e: IOException) {
            LogsActivity.addLog("Error closing connection: ${e.message}")
            Log.e(TAG, "Error closing connection: ${e.message}")
        } finally {
            socket = null
            inputStream = null
            outputStream = null
        }
    }
}