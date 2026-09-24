package de.host.sodtmobile.utils

/**
 * This interface is used to listen for data received events.
 * It is implemented by classes that need to handle data received events.
 */
interface IDataReceivedEventListener {
    /**
     * This method is called when data is received.
     * @param data The data that was received.
     */
    fun onDataReceived(data: ByteArray)
}