package de.host.sodtmobile.utils

import android.R.attr.mimeType
import android.content.ContentResolver
import android.content.ContentValues
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.MediaStore
import android.provider.OpenableColumns
import android.util.Base64
import de.host.sodtmobile.activities.LogsActivity
import java.io.FileOutputStream
import java.security.MessageDigest

class FileManager(private val contentResolver: ContentResolver) {
    private val logTag = "FileManager"


    /**
     * Calculates the SHA-256 hash of a file provided via Uri.
     * Returns the base64 encoded hash as a String.
     */
    fun getFileHash(fileUri: Uri): String {
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            contentResolver.openInputStream(fileUri)?.use { inputStream ->
                val buffer = ByteArray(8192)
                var bytesRead: Int
                while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                    digest.update(buffer, 0, bytesRead)
                }
            }
            // Convert byte array to Hex String
            Base64.encodeToString(digest.digest(), Base64.NO_WRAP)
        } catch (e: Exception) {
            LogsActivity.addErrorLog(logTag, "Failed to calculate hash for $fileUri")
            throw e;
        }
    }

    /**
     * Returns the display name of a file provided via Uri.
     */
    fun getFileName(fileUri: Uri): String{
        return (contentResolver.query(fileUri, null, null, null, null)?.use { cursor ->
            val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (index != -1 && cursor.moveToFirst()) {
                cursor.getString(index)
            } else {
                null
            }
        }) ?: "unknown_file"
    }

    /**
     * Checks if a file with the given name is present in the device's Downloads directory.
     * This is needed to rename the file to avoid overwriting existing files.
     *
     * This function queries the MediaStore.Downloads content provider to get a list of
     * filenames in the external Downloads directory. It then checks if the provided
     * `fileName` exists in that list.
     *
     * Note: This function is suitable for API level 29 and above, as it uses
     * `MediaStore.Downloads.EXTERNAL_CONTENT_URI`.
     *
     * @param fileName The name of the file to search for (e.g., "my_document.pdf").
     * @return `true` if a file with the specified name exists in the Downloads directory,
     *         `false` otherwise.
     */
    private fun isPresentInDownloads(fileName: String): Boolean {
        // URI for external Download collection (API 29+)
        val downloadsUri = MediaStore.Downloads.EXTERNAL_CONTENT_URI

        // We only need the DISPLAY_NAME column to get the filename
        val projection = arrayOf(MediaStore.Downloads.DISPLAY_NAME)
        val fileNames = mutableListOf<String>()

        contentResolver.query(
            downloadsUri,
            projection,
            /* no selection = all rows */ null,
            /* no selection args */ null,
            /* optional sort: most recent first */ "${MediaStore.Downloads.DATE_ADDED} DESC"
        )?.use { cursor ->
            val nameIdx = cursor.getColumnIndexOrThrow(MediaStore.Downloads.DISPLAY_NAME)
            while (cursor.moveToNext()) {
                fileNames += cursor.getString(nameIdx)
            }
        }

        return fileNames.contains(fileName)
    }

    /** * Detects the MIME type of a file based on its extension.
     * This method checks the file extension and returns the corresponding MIME type.
     * If the extension is not recognized, it tries to use the default MIME type.
     * This method is needed because is auto-detection of MIME type is not always reliable,
     * @param extension The extension of the file to detect the MIME type for.
     * @return The MIME type of the file as an Int.
     */
    private fun getMimeTypeForExtension(extension: String): Int {
        return when (extension.replace(".","").lowercase()) {
            "jpg", "jpeg" -> MediaStore.Files.FileColumns.MEDIA_TYPE_IMAGE
            "png" -> MediaStore.Files.FileColumns.MEDIA_TYPE_IMAGE
            "gif" -> MediaStore.Files.FileColumns.MEDIA_TYPE_IMAGE
            "mp4" -> MediaStore.Files.FileColumns.MEDIA_TYPE_VIDEO
            "mp3" -> MediaStore.Files.FileColumns.MEDIA_TYPE_AUDIO
            "pdf", "txt", "html", "htm", "json", "xml" -> MediaStore.Files.FileColumns.MEDIA_TYPE_DOCUMENT
            else -> mimeType // try to auto-detect the MIME type
        }
    }

    /**
     * Creates a new save stream for the file transfer.
     * This method creates a new file in the Downloads directory and returns an OutputStream to write the file data.
     * Uses MediaStore to create a new file in the Downloads directory. (permission is not needed for Android 10+)
     * @param dataPacket The init transfer payload received from the client.
     * @return The ParcelFileDescriptor of the new file.
     */
    fun createNewSaveStream(dataPacket: SodtPackets.InitTransferPayload): ParcelFileDescriptor? {
        // create filename
        val fileNameWithoutExtension = dataPacket.filename.substringBeforeLast('.')
        val extension = dataPacket.filename.substringAfterLast('.', "").substringBefore(" ").lowercase()
        var renamedFile = dataPacket.filename
        var counter = 1
        while (isPresentInDownloads(renamedFile)){
            renamedFile = "$fileNameWithoutExtension ${counter}.$extension"
            counter++
        }

        // create file
        val contentValues = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, renamedFile)
            put(MediaStore.Downloads.MIME_TYPE, getMimeTypeForExtension(extension))
            put(MediaStore.Downloads.IS_PENDING, 1)
            put(MediaStore.Downloads.SIZE, dataPacket.filesize)
        }

        val uri = contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)
            ?: run {
                LogsActivity.addErrorLog(logTag, "Failed to create new file in Downloads directory")
                return null
            }

        val pfd = try {
            contentResolver.openFileDescriptor(uri, "rw")
        } catch (e: Exception) {
            LogsActivity.addErrorLog(logTag, "Failed to open file descriptor: ${e.message}")
            return null
        }

        try {
            // fill with dummy data to reserve space
            pfd?.fileDescriptor?.let { fd ->
                FileOutputStream(fd).use { fos ->
                    // ByteArray takes only int as size, so we need to write the size multiple times if it's larger than Int.MAX_VALUE
                    var size = dataPacket.filesize
                    while (size > Int.MAX_VALUE) {
                        fos.write(ByteArray(Int.MAX_VALUE)) // write max size chunk
                        size -= Int.MAX_VALUE.toLong()
                    }
                    fos.write(ByteArray(size.toInt()))
                    fos.flush()
                }
            }
        } catch (e: Exception){
            LogsActivity.addErrorLog(logTag,"Failed to create the file: ${e.message}")
            return null
        }

        // make the file available for writing
        contentValues.clear()
        contentValues.put(MediaStore.Downloads.IS_PENDING, 0)
        contentResolver.update(uri, contentValues, null, null)

        return try {
            contentResolver.openFileDescriptor(uri, "rw")
        } catch (e: Exception) {
            LogsActivity.addErrorLog(logTag, "Failed to reopen file descriptor: ${e.message}")
            null
        }
    }
}