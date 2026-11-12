package de.host.sodtmobile.elements

data class ClientListElement(
    val clientId: UByte,
    val clientName: String,
    val sharedPhrase: String?
) : IListElement {
    override val displayString: String
        get() = clientName + (if (sharedPhrase != null) " (Shared Phrase: $sharedPhrase)" else "")
}
