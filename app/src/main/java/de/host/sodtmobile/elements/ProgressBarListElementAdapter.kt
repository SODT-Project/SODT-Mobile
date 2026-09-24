package de.host.sodtmobile.elements

import android.view.View
import android.view.ViewGroup

class ProgressBarListElementAdapter(override val elements: List<TransferElement>) : ListElementAdapter(elements) {

    override fun onCreateViewHolder(viewGroup: ViewGroup, viewType: Int): ViewHolder {
        // Create a new view, which defines the UI of the list item
        val viewHolder = super.onCreateViewHolder(viewGroup, viewType)
        // make sure the progress bar is visible
        viewHolder.progressBarDisplay.visibility = View.VISIBLE
        // return the view holder
        return viewHolder
    }
    // Replace the contents of a view (invoked by the layout manager)
    override fun onBindViewHolder(viewHolder: ViewHolder, position: Int) {
        // Get element from dataset at this position and replace the contents of the view
        // get categories and display them as [cat1, cat2, ...]
        super.onBindViewHolder(viewHolder, position)
        val content = elements[position]
        viewHolder.progressBarDisplay.max = content.totalSize.toInt()
        viewHolder.progressBarDisplay.progress = (content.totalSize - content.remainingSize).toInt()
    }
}