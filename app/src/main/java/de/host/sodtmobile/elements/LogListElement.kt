package de.host.sodtmobile.elements

import java.time.Instant
import java.time.format.DateTimeFormatter

data class LogListElement(
    val logTimestamp: Instant,
    val logDetails: String
) : IListElement {
    override val displayString: String
        get() = "${logTimestamp.atZone(java.time.ZoneId.systemDefault()).toLocalTime()}: $logDetails"
}
