package de.host.sodtmobile.utils

object SodtConstants {
    const val SERVER_ID: UByte = 1u
    const val FULL_MESSAGE_SIZE = 4096
    const val NONCE_SIZE = 12
    const val TAG_SIZE = 16
    const val CONTENT_LENGTH_SIZE = 2
    const val ID_SIZE = 2
    const val HEADER_SIZE = NONCE_SIZE + TAG_SIZE + CONTENT_LENGTH_SIZE + ID_SIZE
    const val HEADER_SIZE_WITHOUT_CONTENT_LENGTH = HEADER_SIZE - CONTENT_LENGTH_SIZE
    const val FILE_BUFFER_SIZE = FULL_MESSAGE_SIZE - HEADER_SIZE - 1088 // 1088 bytes are reserved for the json overhead of the file data message. This a worst case scenario. The actual overhead is usually smaller
    const val MESSAGE_CONTENT_SIZE = FULL_MESSAGE_SIZE - HEADER_SIZE
    const val MESSAGE_WITH_CONTENT_SIZE = MESSAGE_CONTENT_SIZE + CONTENT_LENGTH_SIZE



}