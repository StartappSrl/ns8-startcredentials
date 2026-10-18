package it.startapp.credentials.autofill

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.service.autofill.Dataset
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import androidx.annotation.RequiresApi

/** Lettura della richiesta e consegna dei valori scelti ad Android. */
@RequiresApi(Build.VERSION_CODES.O)
object AutofillResult {
  private fun ids(intent: Intent): ArrayList<AutofillId>? =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) intent.getParcelableArrayListExtra(ScAutofillService.EXTRA_IDS, AutofillId::class.java)
    else @Suppress("DEPRECATION") intent.getParcelableArrayListExtra(ScAutofillService.EXTRA_IDS)

  /** Dati della richiesta per l'interfaccia (nessun valore dei campi della pagina). */
  fun request(activity: Activity?): Map<String, Any?> {
    val intent = activity?.intent ?: return mapOf("active" to false)
    val mode = intent.getStringExtra(ScAutofillService.EXTRA_MODE) ?: return mapOf("active" to false)
    val kinds = intent.getStringArrayListExtra(ScAutofillService.EXTRA_KINDS) ?: arrayListOf()
    val pkg = intent.getStringExtra(ScAutofillService.EXTRA_PACKAGE)
    val label = try {
      if (pkg == null) null else activity.packageManager.getApplicationLabel(activity.packageManager.getApplicationInfo(pkg, 0)).toString()
    } catch (e: PackageManager.NameNotFoundException) {
      null
    }
    return mapOf(
      "active" to true,
      "mode" to mode,
      "kinds" to kinds.toList(),
      "webDomain" to intent.getStringExtra(ScAutofillService.EXTRA_DOMAIN),
      "packageName" to pkg,
      "appLabel" to label,
    )
  }

  /** Utente e password da salvare (solo nella modalità "save"). */
  fun saveRequest(activity: Activity?): Map<String, String>? {
    val intent = activity?.intent ?: return null
    if (intent.getStringExtra(ScAutofillService.EXTRA_MODE) != "save") return null
    return mapOf(
      "username" to (intent.getStringExtra(ScAutofillService.EXTRA_SAVE_USERNAME) ?: ""),
      "password" to (intent.getStringExtra(ScAutofillService.EXTRA_SAVE_PASSWORD) ?: ""),
    )
  }

  /** Compila i campi con i valori scelti e chiude la schermata. */
  fun complete(activity: Activity, values: Map<String, String>, label: String): Boolean {
    val intent = activity.intent
    val ids = ids(intent) ?: return false
    val kinds = intent.getStringArrayListExtra(ScAutofillService.EXTRA_KINDS) ?: return false
    val presentation = RemoteViews(activity.packageName, android.R.layout.simple_list_item_1).apply {
      setTextViewText(android.R.id.text1, "StartCredentials")
    }
    @Suppress("DEPRECATION")
    val builder = Dataset.Builder(presentation)
    var any = false
    for (i in ids.indices) {
      val value = values[kinds.getOrNull(i)]
      if (!value.isNullOrEmpty()) {
        @Suppress("DEPRECATION")
        builder.setValue(ids[i], AutofillValue.forText(value))
        any = true
      }
    }
    if (!any) return false
    RecentFill.remember(intent.getStringExtra(ScAutofillService.EXTRA_DOMAIN), intent.getStringExtra(ScAutofillService.EXTRA_PACKAGE), label, values)
    val result = Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, builder.build())
    activity.runOnUiThread {
      activity.setResult(Activity.RESULT_OK, result)
      activity.finish()
    }
    return true
  }

  fun cancel(activity: Activity) {
    activity.runOnUiThread {
      activity.setResult(Activity.RESULT_CANCELED)
      activity.finish()
    }
  }
}
