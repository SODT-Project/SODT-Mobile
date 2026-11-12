package de.host.sodtmobile.utils

import android.content.Context
import android.util.Log
import android.widget.Toast
import de.host.sodtmobile.activities.LogsActivity
import de.host.sodtmobile.elements.ClientListElement
import de.host.sodtmobile.elements.ListElementAdapter
import de.host.sodtmobile.elements.TransferElement
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** * SodtClientUiWrapper is a wrapper around the SodtClient that provides additional functionality for the UI.
 * It handles the client list and transfer list, and updates the UI accordingly.
 *
 * @param serverAddress The address of the server to connect to.
 * @param serverPort The port of the server to connect to.
 * @param encryptionKey The encryption key to use for communication.
 * @param context The context of the application.
 * @param clientList The list of clients to display in the UI.
 * @param clientListElementAdapter The adapter for the client list.
 * @param onClientSetAction Action to perform when a client is set.
 * @param transferList The list of transfers to display in the UI.
 * @param transferListElementAdapter The adapter for the transfer list.
 */
class SodtClientUiWrapper(
    serverAddress: String,
    serverPort: Int,
    encryptionKey: String,
    private val context: Context,
    private val clientList: MutableList<ClientListElement>,
    private val clientListElementAdapter: ListElementAdapter,
    private val onClientSetAction: (ClientListElement?) -> Unit,
    private val transferList: MutableList<TransferElement>,
    private val transferListElementAdapter: ListElementAdapter
) : SodtClient(serverAddress, serverPort, encryptionKey, context.contentResolver) {
    var selectedClient: ClientListElement? = null

    private val TAG = "SodtClientUiWrapper"

    override fun receiveClientList(dataPacket: SodtPackets.ClientListPayload) {
        if (dataPacket.clients == null) {
            Log.w(TAG, "Empty client list")
            return
        }
        val clients = org.bouncycastle.util.encoders.Base64.decode(dataPacket.clients).joinToString(",").split(",")
        super.receiveClientList(dataPacket)
        // add new clients to the client list by rebuilding the whole list
        clientList.clear()
        for (client in clients) {
            val clientId = client.toUByteOrNull()
            // check if clientId is null or if it is the server ID
            if (clientId == null || clientId == Globals.SERVER_ID) {
                continue
            }
            // add client to the client list
            val clientName = client + if (clientId == Globals.clientID) " (you)" else ""
            clientList.add(ClientListElement(clientId, clientName, encryptionManager.getSharedPhraseForClient(clientId)))
        }
        // notify the adapter that the data has changed on main thread
        CoroutineScope(Dispatchers.Main).launch {
            clientListElementAdapter.notifyDataSetChanged()
            onClientSetAction(selectedClient)
        }

    }

    override fun respondToTransferRequest(remoteID: UByte, dataPacket: SodtPackets.InitTransferPayload) {
        super.respondToTransferRequest(remoteID, dataPacket)
        when (dataPacket.code) {
            100 -> {
                // save the transfer request
                transferList.add(0, TransferElement(
                    transferId = dataPacket.uuid,
                    senderName = remoteID.toString(),
                    fileName = dataPacket.filename,
                    totalSize = dataPacket.filesize,
                    fileHash = dataPacket.filehash,
                    remainingSize = dataPacket.filesize
                ))
                CoroutineScope(Dispatchers.Main).launch { transferListElementAdapter.notifyItemInserted(0) }
            }
            200 -> {/*Do nothing on ui level*/}
            250 -> {
                // make successful transfer acknowledgement visible in UI via Toast
                CoroutineScope(Dispatchers.Main).launch {
                    Toast.makeText(
                        context,
                        "$remoteID received ${dataPacket.filename} successfully!",
                        Toast.LENGTH_LONG
                    ).show()
                }
            }
            300 -> {
                // make failed transfer request visible in UI via Toast
                CoroutineScope(Dispatchers.Main).launch {
                    Toast.makeText(
                        context,
                        "Transfer request for file ${dataPacket.filename} rejected by $remoteID",
                        Toast.LENGTH_SHORT
                    ).show()
                }
            }
            400 -> {
                // make failed transfer request visible in UI via Toast
                CoroutineScope(Dispatchers.Main).launch {
                    Toast.makeText(
                        context,
                        "Transfer request for file ${dataPacket.filename} failed with code 400",
                        Toast.LENGTH_SHORT
                    ).show()
                }
            }
            else -> {
                LogsActivity.addLog("File transfer request for ${dataPacket.filename} failed with code: ${dataPacket.code}")
            }
        }
    }

    override fun receiveFileData(dataPacket: SodtPackets.TransferDataPayload) {
        super.receiveFileData(dataPacket)
        // find the transfer in the list (not ideal but enough to fulfill the requirements. Use a map later)
        val transferListIndex = transferList.indexOfFirst { it.transferId == dataPacket.uuid }
        if (transferListIndex == -1) {
            LogsActivity.addLog("Transfer with UUID ${dataPacket.uuid} not found in transfer list")
            Log.w(TAG, "Transfer with UUID ${dataPacket.uuid} not found in transfer list")
            return
        }
        // update the transfer list and notify the adapter
        CoroutineScope(Dispatchers.Main).launch {
            transferList[transferListIndex].remainingSize = incomingTransfersProgress[dataPacket.uuid] ?: 0L
            transferListElementAdapter.notifyItemChanged(transferListIndex)
            if (transferList[transferListIndex].remainingSize == 0L) {
                Toast.makeText(context, "File transfer completed", Toast.LENGTH_SHORT).show()
                transferList[transferListIndex].remainingSize = -1L
            }
        }
    }

    public override fun sendFile(targetId: UByte, uuid: Int){
        CoroutineScope(Dispatchers.Main).launch {
            Toast.makeText(context, "Sending file (uuid: $uuid) to $targetId", Toast.LENGTH_SHORT).show()
        }
        super.sendFile(targetId, uuid)
    }

    override fun respondToKeyExchange(remoteID: UByte, requestPacket: SodtPackets.KeyExchangePayload) {
        super.respondToKeyExchange(remoteID, requestPacket)
        // update the client list with the new shared phrase
        val clientIndex = clientList.indexOfFirst { it.clientId == remoteID }
        if (clientIndex != -1) {
            clientList[clientIndex] = ClientListElement(remoteID, remoteID.toString(), encryptionManager.getSharedPhraseForClient(remoteID))
            CoroutineScope(Dispatchers.Main).launch { clientListElementAdapter.notifyItemChanged(clientIndex) }
        }
    }
}