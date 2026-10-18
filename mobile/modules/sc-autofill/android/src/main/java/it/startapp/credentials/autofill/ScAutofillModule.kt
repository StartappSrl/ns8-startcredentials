package it.startapp.credentials.autofill

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.view.autofill.AutofillManager
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

/** Ponte JavaScript ↔ autofill di sistema. */
class ScAutofillModule : Module() {
  override fun definition() = ModuleDefinition {
    Name("ScAutofill")

    Function("isSupported") { Build.VERSION.SDK_INT >= Build.VERSION_CODES.O }

    /** true se StartCredentials è il servizio di autofill attivo. */
    Function("isEnabled") {
      if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return@Function false
      val ctx = appContext.reactContext ?: return@Function false
      ctx.getSystemService(AutofillManager::class.java)?.hasEnabledAutofillServices() == true
    }

    /** Apre la scelta del servizio di autofill nelle impostazioni di Android. */
    Function("openSettings") {
      if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return@Function false
      val activity = appContext.currentActivity ?: return@Function false
      val intent = Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE).setData(Uri.parse("package:${activity.packageName}"))
      activity.startActivity(intent)
      true
    }

    /** Richiesta in corso (solo nella schermata aperta dall'autofill). */
    Function("getRequest") {
      if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return@Function mapOf("active" to false)
      AutofillResult.request(appContext.currentActivity)
    }

    Function("complete") { values: Map<String, String>, label: String ->
      if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return@Function false
      val activity = appContext.currentActivity ?: return@Function false
      AutofillResult.complete(activity, values, label)
    }

    /** Utente e password da salvare, quando la schermata è aperta dalla proposta di salvataggio. */
    Function("getSave") {
      if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return@Function null
      AutofillResult.saveRequest(appContext.currentActivity)
    }

    /** Chiude la schermata dopo il salvataggio. */
    Function("finish") {
      appContext.currentActivity?.let { a -> a.runOnUiThread { a.finish() } }
      true
    }

    Function("cancel") {
      if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return@Function false
      appContext.currentActivity?.let { AutofillResult.cancel(it) }
      true
    }
  }
}
