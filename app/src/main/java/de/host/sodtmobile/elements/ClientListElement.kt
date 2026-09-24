package de.host.sodtmobile.elements

data class ClientListElement(
    val clientId: UByte,
    val clientName: String,
) : IListElement {
    override val displayString: String
        get() = clientName
}
