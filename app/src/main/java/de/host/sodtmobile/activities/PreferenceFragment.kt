package de.host.sodtmobile.activities

import android.os.Bundle
import androidx.preference.PreferenceFragmentCompat
import de.host.sodtmobile.R

/**
 * PreferenceFragment is a Fragment that displays the preferences for the app.
 * source: https://developer.android.com/develop/ui/views/components/settings?hl=de#kts
 * @author Moritz Ehrke, 20961
 */
class PreferenceFragment : PreferenceFragmentCompat() {
    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.preferences, rootKey)
    }
}