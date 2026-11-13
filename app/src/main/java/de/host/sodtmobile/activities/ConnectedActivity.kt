package de.host.sodtmobile.activities

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.Toast
import androidx.activity.result.ActivityResult
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import de.host.sodtmobile.R
import de.host.sodtmobile.elements.ClickableListElementAdapter
import de.host.sodtmobile.elements.ClientListElement
import de.host.sodtmobile.elements.IListElement
import de.host.sodtmobile.elements.TransferElement
import de.host.sodtmobile.elements.ProgressBarListElementAdapter
import de.host.sodtmobile.utils.Globals
import de.host.sodtmobile.utils.SodtClientUiWrapper

class ConnectedActivity : AppCompatActivity() {
    // UI elements
    private lateinit var selectFileButton: Button
    private lateinit var recyclerViewClientList: RecyclerView
    private lateinit var recyclerViewIncomingTransfers: RecyclerView
    // global variables
    private val clientList = ArrayList<ClientListElement>()
    private val transfers = ArrayList<TransferElement>()
    private lateinit var clientListElementAdapter: ClickableListElementAdapter
    private lateinit var transferElementAdapter: ProgressBarListElementAdapter
    private lateinit var sodtClient: SodtClientUiWrapper
    // activity for result handler
    val getFileAndSend = registerForActivityResult(StartActivityForResult()) { uri: ActivityResult ->
        if (uri.resultCode == RESULT_OK) {
            // handle the file selection
            val fileUri = uri.data?.data
            if (fileUri == null) {
                Log.e("ConnectedActivity", "No file selected or file URI is null")
                return@registerForActivityResult
            }
            if (sodtClient.selectedClient == null) {
                Log.e("ConnectedActivity", "No client selected to send the file to")
                return@registerForActivityResult
            }
            sodtClient.requestFileTransfer(sodtClient.selectedClient!!.clientId, fileUri)
            // rest of the file transfer logic is handled in SodtClient (and SodtReceiver)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_connected)
        // ui elements
        selectFileButton = findViewById(R.id.button_selectFile)
        recyclerViewClientList = findViewById(R.id.recyclerView_clientList)
        recyclerViewClientList.layoutManager = LinearLayoutManager(this)
        recyclerViewIncomingTransfers = findViewById(R.id.recyclerView_incomingTransfers)
        recyclerViewIncomingTransfers.layoutManager = LinearLayoutManager(this)
        selectFileButton.text = getString(R.string.select_file, "(no client selected)")
        // set up the client list adapter
        clientListElementAdapter = ClickableListElementAdapter(clientList, this::selectClient)
        recyclerViewClientList.adapter = clientListElementAdapter
        // set up the incoming transfers adapter
        transferElementAdapter = ProgressBarListElementAdapter(transfers)
        recyclerViewIncomingTransfers.adapter = transferElementAdapter
        sodtClient = SodtClientUiWrapper(
            intent.getStringExtra("serverAddress")!!,
            intent.getIntExtra("serverPort", 0),
            intent.getStringExtra("publicKey")!!,
            this,
            clientList,
            clientListElementAdapter,
            this::selectClient,
            transfers,
            transferElementAdapter)
        // sleep for a short time to allow the client to connect
        Thread.sleep(150)
        if (!sodtClient.isInitiated) {
            LogsActivity.addLog("Connection Failed. Is the server online?")
            Toast.makeText(this, "Connection Failed. Is the server online?", Toast.LENGTH_LONG).show()
            disconnect() // Close the activity if the client is not initiated
            finish()
        }
    }

    private fun selectClient(client: IListElement?) {
        if (client is ClientListElement && client.clientId == Globals.clientID) {
            Toast.makeText(this, "You cant send to yourself!", Toast.LENGTH_LONG).show()
        }
        else if (client is ClientListElement && clientList.contains(client)) {
            sodtClient.selectedClient = client
            selectFileButton.text = getString(R.string.select_file, client.clientName)
            if (client.sharedPhrase == null) {
                sodtClient.requestKeyExchange(client.clientId)
            }
        }
        else {
            sodtClient.selectedClient = null
            selectFileButton.text = getString(R.string.select_file, "(no client selected)")
        }
    }
    fun onDisconnectButtonClick(view: View) {
        disconnect()
    }
    private fun disconnect(){
        sodtClient.disconnect()
        finish() // Close the activity, returning to the previous one (MainActivity)
    }
    fun onSendFileToButtonClick(view: View) {
        val client = sodtClient.selectedClient
        if (client == null || !clientList.contains(client)) {
            // send toast message to select a client first
            Toast.makeText(this, "Select a connected client first!", Toast.LENGTH_SHORT).show()
            return
        }
        if (client.sharedPhrase == null) {
            Toast.makeText(this, "Key exchange not completed with ${client.clientName}!", Toast.LENGTH_SHORT).show()
            return
        }
        val intent = Intent()
            .setType("*/*")
            .setAction(Intent.ACTION_GET_CONTENT)
        getFileAndSend.launch(intent)
    }
    override fun onBackPressed() {
        disconnect()
        super.onBackPressed()
    }

    override fun onResume() {
        super.onResume()
        if (!sodtClient.isInitiated){
            return // on init the client will connect to the server, do not abort the activity
        }
        if (!sodtClient.isConnected) {
            Log.e("ConnectedActivity", "SodtClient is not connected, disconnecting activity")
            Toast.makeText(this, "Disconnected from server.", Toast.LENGTH_SHORT).show()
            disconnect() // Close the activity if the client is not connected
        }
    }
}