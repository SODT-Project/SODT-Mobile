package de.host.sodtmobile.utils

/**
 * SodtConstants is a singleton object that contains constants used in the SODT-Protocol.
 */
object SodtConstants {
    /**
     * The ID of the server.
     */
    const val SERVER_ID: UByte = 1u

    /**
     * The size of the full message (4096 Bytes)
     */
    const val FULL_MESSAGE_SIZE = 4096

    /**
     * The size of the nonce for aes encryption. (12 Bytes)
     */
    const val NONCE_SIZE = 12

    /**
     * The size of the tag for aes encryption. (16 Bytes)
     */
    const val TAG_SIZE = 16

    /**
     * The size of the content length field. (2 Bytes)
     */
    const val CONTENT_LENGTH_SIZE = 2

    /**
     * The size of the ID field. (2 Bytes)
     */
    const val ID_SIZE = 2

    /**
     * The size of the full header with ids, nonce, tags and content length. (32 Bytes)
     */
    const val HEADER_SIZE = NONCE_SIZE + TAG_SIZE + CONTENT_LENGTH_SIZE + ID_SIZE

    /**
     * The size of the header without the content length. (30 Bytes)
     */
    const val HEADER_SIZE_WITHOUT_CONTENT_LENGTH = HEADER_SIZE - CONTENT_LENGTH_SIZE

    /**
     * The size of the buffer used for file transfers. (2976 Bytes)
     */
    // 1088 bytes are reserved for the JSON overhead of the file data message (type, code, ... and extra size for base64 conversion).
    // This a worst case scenario. The actual overhead is usually smaller
    const val FILE_BUFFER_SIZE = FULL_MESSAGE_SIZE - HEADER_SIZE - 1088

    /**
     * The size for the encoded content. (4064 Bytes)
     */
    const val MESSAGE_CONTENT_SIZE = FULL_MESSAGE_SIZE - HEADER_SIZE

    /**
     * The size for the encoded content plus its encoded content length. (4066 Bytes)
     */
    const val MESSAGE_WITH_CONTENT_SIZE = MESSAGE_CONTENT_SIZE + CONTENT_LENGTH_SIZE



}