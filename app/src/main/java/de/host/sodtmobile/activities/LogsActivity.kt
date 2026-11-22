package de.host.sodtmobile.activities

import android.os.Bundle
import android.util.Log
import android.widget.Button
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import de.host.sodtmobile.R
import de.host.sodtmobile.elements.ListElementAdapter
import de.host.sodtmobile.elements.LogListElement
import java.time.Instant

class LogsActivity : AppCompatActivity() {
    companion object {
        private val logs = ArrayList<LogListElement>()
        fun addLog(tag: String, message: String) {
            logs.add(LogListElement(Instant.now(), message))
            Log.d(tag, message)
        }

        fun addErrorLog(tag: String, message: String){
            logs.add(LogListElement(Instant.now(), message))
            Log.e(tag, message)
        }
    }
    // UI elements
    private lateinit var recyclerViewLogs: RecyclerView
    // global variables
    private lateinit var logListElementAdapter: ListElementAdapter
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_logs)
        // ui elements
        recyclerViewLogs = findViewById(R.id.recyclerView_logs)
        recyclerViewLogs.layoutManager = LinearLayoutManager(this)
        // set up the logs list adapter
        logListElementAdapter = ListElementAdapter(logs)
        recyclerViewLogs.adapter = logListElementAdapter

        logListElementAdapter.notifyDataSetChanged()
    }

    fun onCloseButtonClick(view: android.view.View) {
        finish()
    }

    fun onClearButtonClick(view: android.view.View) {
        val size = logs.size
        logs.clear()
        logListElementAdapter.notifyItemRangeRemoved(0, size)
    }


}