package de.host.sodtmobile.elements

class ClickableListElementAdapter(
    elements: List<IListElement>,
    private val onClickAction: (IListElement) -> Unit
) : ListElementAdapter(elements) {


    override fun onBindViewHolder(viewHolder: ViewHolder, position: Int) {
        super.onBindViewHolder(viewHolder, position)
        // Set click listener for the item view
        viewHolder.itemView.setOnClickListener {
            onClickAction(elements[position])
        }
    }
}