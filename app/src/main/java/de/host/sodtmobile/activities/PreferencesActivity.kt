package de.host.sodtmobile.activities

import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.preference.PreferenceManager
import de.host.sodtmobile.R
import de.host.sodtmobile.utils.EncryptionManager

class PreferencesActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_preferences)

        // Set up the preferences fragment
        supportFragmentManager
            .beginTransaction()
            .replace(R.id.frame_layout_preferences, PreferenceFragment())
            .commit()
    }

    fun onSubmitButtonClick(view: android.view.View) {

        // validate the input before saving
        if (!validateInput()) {
            return
        }
        setResult(RESULT_OK)
        finish() // Close the activity, returning to the previous one
    }

    override fun onBackPressed() {
        if(!validateInput()) {
            return // Prevent going back if validation fails
        }
        super.onBackPressed()
    }

    private fun validateInput() : Boolean {
        val manager = PreferenceManager.getDefaultSharedPreferences(this).all
        // check if any of the preferences are empty or null (ignoring boolean switches)
        for ((key, value) in manager) {
            if (value !is Boolean && (value == null || value.toString().isEmpty())) {
                Toast.makeText(this, "Preference $key cannot be empty", Toast.LENGTH_SHORT).show()
                return false
            }
        }
        // check if port is a valid number (ushort)
        val port = manager["preference_server_port"]!!.toString().toUShortOrNull()
        if (port == null || port < 1u || port > 65535u) {
            Toast.makeText(this, "Port must be a valid number between 1 and 65535", Toast.LENGTH_SHORT).show()
            return false
        }
        // check if server address is a valid IP address or hostname
        val serverAddress = manager["preference_server_address"]!!.toString()
        if (serverAddress.isEmpty() || !android.util.Patterns.WEB_URL.matcher(serverAddress).matches()) {
            Toast.makeText(this, "Server address must be a valid IP address or hostname", Toast.LENGTH_SHORT).show()
            return false
        }
        // check if public key is in valid PEM format
        val publicKey = manager["preference_server_public_key"]!!.toString()
        /*if (!EncryptionManager.isValidPublicKey(publicKey)) {
            Toast.makeText(this, "Public key must be a valid PEM formatted RSA public key", Toast.LENGTH_SHORT).show()
            return false
        }*/ // TODO implement public key validation
        return true
    }
}