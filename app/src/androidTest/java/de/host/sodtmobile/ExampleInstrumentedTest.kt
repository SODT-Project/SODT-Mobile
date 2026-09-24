package de.host.sodtmobile

import android.content.ContentResolver
import android.content.ContentUris
import android.content.ContentValues
import android.net.Uri
import android.provider.MediaStore
import androidx.appcompat.app.AppCompatActivity
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import de.host.sodtmobile.activities.MainActivity
import de.host.sodtmobile.utils.Globals
import de.host.sodtmobile.utils.SodtClient

import org.junit.Test
import org.junit.runner.RunWith

import org.junit.Assert.*
import java.io.File

/**
 * Instrumented test, which will execute on an Android device.
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */
@RunWith(AndroidJUnit4::class)
class ExampleInstrumentedTest {
    val server = "ehrke.me"
    val port = 45645
    val key = """-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEAzUNG10DDBNGCYzhdSd1rYsjFijkW1dx+kNH0XB1IGOUieqfQn8TM
32kEe+9dl2fqtqKJkOyaXJlme7yq9tdNv7B+aHfm64XiYgolCJT65Xj2D4UfuAjx
GW8Z5zUwwyY4rueEM7E4MBzY+9+xW5l9mRDdjC+2bq2Q74ybO7jV1syCAmQy28Ij
pjjK072hVolnYnOC14b8Tgot+mYPNI8MbjhpFggga37IJI7YVW5LIp711BR7j3HE
rXF8eFHsalgff9wKjQWqHTPJRB+6KfINVNP907Yiq3P6yG0r9m+teWdewdGar/En
34tNKXv9n6xUB4ysMFPW2MBzc8oJsxYGs7RqSWIU/vxODYYdO679Q58Ihaml80FF
CYnJ1DYRCT+CMmZhHNNpVacpZt5Nxb1mVRe7UroGLdZRvZC5vxz+fOnFXlIkNrBi
QvjJ0AuOyg4wIOk8ZcgQM+9Q54LmutaY5rK4i7/4Tu5BEHIYD/iWPpQDWMkNLhH+
/qM/Fl+QH29ETVnZQM33sWMSqCnu8K1LzhAnmgspH8fYwofF9fx+IB5VDDqNeGc3
STxTlVzvqLaEeQrWB/ITcbU5yRfzNbyCbZs4Oz4h/nAcFj5+aw/6Lp+Xt0YPZDIJ
jz/YEnktcZnZq616geTkA2P3ebIyZ/pRiUI0bDFXITNx8lKW2FSIWssCAwEAAQ==
-----END RSA PUBLIC KEY-----"""
    @Test
    fun useAppContext() {
        // Context of the app under test.
        val appContext = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("de.host.sodtmobile", appContext.packageName)
    }

    @Test
    fun canConnect(){
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        scenario.onActivity { activity ->
            val client = SodtClient(server, port, key, activity.contentResolver)
            // wait to ensure the client is initiated and connected
            Thread.sleep(3000) // wait for 3 seconds to allow connection
            assertTrue("Client should be initiated", client.isInitiated)
            assertTrue("Client should be connected", client.isConnected)
            client.disconnect()
            Thread.sleep(100)
            assertFalse("Client should be disconnected", client.isConnected)
        }
    }

    @Test // make encryptionManager available first before running this test
    fun canKeyExchange(){
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        scenario.onActivity { activity ->
            // client 1
            val client = SodtClient(server, port, key, activity.contentResolver)
            Thread.sleep(3000) // wait for 3 seconds to allow connection
            val client2 = SodtClient(server, port, key, activity.contentResolver)
            Thread.sleep(3000) // wait for 3 seconds to allow connection
            val ids = client.encryptionManager.getAllConnectedClientIds()
            assertTrue("key exchange failed", client.encryptionManager.hasClientSessionKeyFor(ids.first()))
            client.disconnect()
            client2.disconnect()
        }
    }

    @Test // make pending transfers available first before running this test
    fun canSendFile(){
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        scenario.onActivity { activity ->
            // client 1
            val client = SodtClient(server, port, key, activity.contentResolver)
            Thread.sleep(1000) // wait for 3 seconds to allow connection
            val id = Globals.clientID
            val uri = activity.contentResolver.insert(
                MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, "testfile.txt")
                    put(MediaStore.Downloads.MIME_TYPE, "text/plain")
                    put(MediaStore.Downloads.IS_PENDING, 1)
                }
            )
            requireNotNull(uri) { "Failed to create MediaStore entry for file" }

            // Write dummy content to the file
            activity.contentResolver.openOutputStream(uri)?.use { outputStream ->
                for (i in 0 until 1000) {
                    outputStream.write("Test content".toByteArray())
                }
            }

            // Mark the item as not pending so it's visible to the user
            val updatedValues = ContentValues().apply {
                put(MediaStore.MediaColumns.IS_PENDING, 0)
            }
            activity.contentResolver.update(uri, updatedValues, null, null)
            client.requestFileTransfer(id, uri!!)
            assertTrue("pending transfers is empty", client.pendingTransferRequests.isNotEmpty())
            Thread.sleep(100)
            client.disconnect()
        }
    }
}