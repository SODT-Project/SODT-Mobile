package de.host.sodtmobile.elements

data class TransferElement(
    val transferId: Int,
    val senderName: String,
    val fileName : String,
    val totalSize: Long,
    var remainingSize: Long,
) : IListElement {
    override val displayString: String
        get() = "Receiving $fileName from $senderName"

}
