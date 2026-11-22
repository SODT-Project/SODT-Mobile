package de.host.sodtmobile.utils

import android.content.Context
import android.text.format.Formatter
import android.util.Log
import android.widget.Toast
import androidx.preference.PreferenceManager
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import de.host.sodtmobile.R
import de.host.sodtmobile.activities.LogsActivity
import de.host.sodtmobile.elements.ClientListElement
import de.host.sodtmobile.elements.ListElementAdapter
import de.host.sodtmobile.elements.TransferElement
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

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

    private val logTag = "SodtClientUiWrapper"

    override fun receiveDiscoveryResponse(dataPacket: SodtPackets.DiscoveryPayload) {
        if (dataPacket.id.toInt() != 0 && dataPacket.signature != null && dataPacket.code < 300) {
            if (!encryptionManager.verifySignature(serverCertificate, dataPacket)) {
                CoroutineScope(Dispatchers.Main).launch {
                    Toast.makeText(context, R.string.toast_discovery_not_verified, Toast.LENGTH_LONG).show()
                }
            }
        }
        super.receiveDiscoveryResponse(dataPacket)
    }

    override fun receiveClientList(dataPacket: SodtPackets.ClientListPayload) {
        if (dataPacket.clients == null) {
            Log.w(logTag, "Empty client list")
            return
        }
        val clients = org.bouncycastle.util.encoders.Base64.decode(dataPacket.clients).joinToString(",").split(",")
        super.receiveClientList(dataPacket)
        // add new clients to the client list by rebuilding the whole list
        clientList.clear()
        for (client in clients) {
            val clientId = client.toUByteOrNull()
            // check if clientId is null or if it is the server ID
            if (clientId == null || clientId == SodtConstants.SERVER_ID) {
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
        if (dataPacket.code == 100) {
            val prefs = PreferenceManager.getDefaultSharedPreferences(context)
            val autoAccept = prefs.getBoolean("preference_auto_accept_transfer", false)
            if (autoAccept) {
                acceptTransferRequest(remoteID, dataPacket)
                CoroutineScope(Dispatchers.Main).launch {
                    transferList.add(0, TransferElement(
                        transferId = dataPacket.uuid,
                        senderName = remoteID.toString(),
                        fileName = dataPacket.filename,
                        totalSize = dataPacket.filesize,
                        fileHash = dataPacket.filehash,
                        remainingSize = dataPacket.filesize
                    ))
                    transferListElementAdapter.notifyItemInserted(0)
                }
                return
            }

            CoroutineScope(Dispatchers.Main).launch {
                val formattedSize = Formatter.formatFileSize(context, dataPacket.filesize)
                MaterialAlertDialogBuilder(context)
                    .setTitle(R.string.dialog_file_transfer_title)
                    .setMessage(context.getString(R.string.dialog_file_transfer_message, remoteID.toString(), dataPacket.filename, formattedSize))
                    .setCancelable(false)
                    .setPositiveButton(R.string.dialog_accept) { _, _ ->
                        acceptTransferRequest(remoteID, dataPacket)
                        transferList.add(0, TransferElement(
                            transferId = dataPacket.uuid,
                            senderName = remoteID.toString(),
                            fileName = dataPacket.filename,
                            totalSize = dataPacket.filesize,
                            fileHash = dataPacket.filehash,
                            remainingSize = dataPacket.filesize
                        ))
                        transferListElementAdapter.notifyItemInserted(0)
                    }
                    .setNegativeButton(R.string.dialog_deny) { _, _ ->
                        denyTransferRequest(remoteID, dataPacket)
                    }
                    .show()
            }
            return
        }

        super.respondToTransferRequest(remoteID, dataPacket)
        when (dataPacket.code) {
            200 -> {/*Do nothing on ui level*/}
            250 -> {
                // make successful transfer acknowledgement visible in UI via Toast
                CoroutineScope(Dispatchers.Main).launch {
                    Toast.makeText(
                        context,
                        "$remoteID reported successful transfer of ${dataPacket.filename}",
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
                LogsActivity.addErrorLog(logTag, "File transfer request for ${dataPacket.filename} failed with code: ${dataPacket.code}")
            }
        }
    }

    override fun receiveFileData(remoteId: UByte, dataPacket: SodtPackets.TransferDataPayload) {
        super.receiveFileData(remoteId, dataPacket)
        // find the transfer in the list (not ideal but enough to fulfill the requirements. Use a map later)
        val transferListIndex = transferList.indexOfFirst { it.transferId == dataPacket.uuid }
        if (transferListIndex == -1) {
            LogsActivity.addErrorLog(logTag, "Transfer with UUID ${dataPacket.uuid} not found in transfer list")
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
        if (requestPacket.code == 100) {
            val prefs = PreferenceManager.getDefaultSharedPreferences(context)
            val autoAccept = prefs.getBoolean("preference_auto_accept_key_exchange", false)
            if (autoAccept) {
                acceptKeyExchange(remoteID, requestPacket)
                updateClientSharedPhrase(remoteID)
                return
            }

            CoroutineScope(Dispatchers.Main).launch {
                MaterialAlertDialogBuilder(context)
                    .setTitle(R.string.dialog_key_exchange_title)
                    .setMessage(context.getString(R.string.dialog_key_exchange_message, remoteID.toString()))
                    .setCancelable(false)
                    .setPositiveButton(R.string.dialog_accept) { _, _ ->
                        acceptKeyExchange(remoteID, requestPacket)
                        updateClientSharedPhrase(remoteID)
                    }
                    .setNegativeButton(R.string.dialog_deny) { _, _ ->
                        denyKeyExchange(remoteID)
                    }
                    .show()
            }
            return
        }

        super.respondToKeyExchange(remoteID, requestPacket)
        when (requestPacket.code) {
            200 -> {
                // update the client list with the new shared phrase (e.g. after code 200 response received)
                updateClientSharedPhrase(remoteID)
            }
            300 -> {
                CoroutineScope(Dispatchers.Main).launch {
                    Toast.makeText(context, "Key exchange rejected by $remoteID", Toast.LENGTH_SHORT).show()
                    if (selectedClient?.clientId == remoteID) {
                        selectedClient = null
                        onClientSetAction(null)
                    }
                }
            }
            400 -> {
                CoroutineScope(Dispatchers.Main).launch {
                    Toast.makeText(context, "Key exchange failed with $remoteID", Toast.LENGTH_SHORT).show()
                    if (selectedClient?.clientId == remoteID) {
                        selectedClient = null
                        onClientSetAction(null)
                    }
                }
            }
        }
    }

    /**
     * Updates the shared phrase for a client in the client list visually.
     */
    private fun updateClientSharedPhrase(remoteID: UByte) {
        val clientIndex = clientList.indexOfFirst { it.clientId == remoteID }
        if (clientIndex != -1) {
            clientList[clientIndex] = ClientListElement(remoteID, remoteID.toString(), encryptionManager.getSharedPhraseForClient(remoteID))
            CoroutineScope(Dispatchers.Main).launch { clientListElementAdapter.notifyItemChanged(clientIndex) }
        }
    }
}