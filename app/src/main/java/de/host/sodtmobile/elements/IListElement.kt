package de.host.sodtmobile.elements

/**
 * Interface representing an element in a list for the recycler view in the UI.
 * This interface is used to define a common structure for elements that can be displayed in the UI.
 * @author Moritz Ehrke, 20961
 */
interface IListElement {
    /**
     * A string that represents the element in a user-friendly way for the UI.
     */
    val displayString : String
}