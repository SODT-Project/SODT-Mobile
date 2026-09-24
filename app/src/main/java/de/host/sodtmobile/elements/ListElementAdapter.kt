package de.host.sodtmobile.elements

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ProgressBar
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import de.host.sodtmobile.R

open class ListElementAdapter (internal open val elements: List<IListElement>) : RecyclerView.Adapter<ListElementAdapter.ViewHolder>() {
    /**
     * Provide a reference to the type of views that you are using
     * (custom ViewHolder)
     * use inner to access the outer class properties like dataSet
     */
    inner class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        // Define click listener for the ViewHolder's View
        val textViewDisplay: TextView = view.findViewById(R.id.textView_displayElement)
        val progressBarDisplay: ProgressBar = view.findViewById(R.id.progressBar_display)
    }

    // Create new views (invoked by the layout manager)
    override fun onCreateViewHolder(viewGroup: ViewGroup, viewType: Int): ViewHolder {
        // Create a new view, which defines the UI of the list item
        val view = LayoutInflater.from(viewGroup.context)
            .inflate(R.layout.layout_list, viewGroup, false)
        return ViewHolder(view)
    }

    // Replace the contents of a view (invoked by the layout manager)
    override fun onBindViewHolder(viewHolder: ViewHolder, position: Int) {
        // Get element from dataset at this position and replace the contents of the view
        // get categories and display them as [cat1, cat2, ...]
        val content = elements[position]
        viewHolder.textViewDisplay.text = content.displayString
    }
    override fun getItemCount() = elements.size
}
