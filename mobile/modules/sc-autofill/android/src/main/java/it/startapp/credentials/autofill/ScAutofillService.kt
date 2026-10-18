package it.startapp.credentials.autofill

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import androidx.annotation.RequiresApi

/**
 * Servizio di autofill di StartCredentials. Non conosce né riceve password:
 * individua i campi e propone "Compila con StartCredentials". Al tocco Android
 * apre AutofillActivity, che sblocca la cassaforte, fa scegliere la credenziale
 * e restituisce i valori (vedi AutofillResult).
 */
@RequiresApi(Build.VERSION_CODES.O)
class ScAutofillService : AutofillService() {
  override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
    val ctx = request.fillContexts.lastOrNull()
    if (ctx == null) {
      callback.onSuccess(null)
      return
    }
    val screen = AutofillParser.parse(ctx.structure)
    // Niente proposte per le schermate di StartCredentials stessa.
    if (screen.isEmpty || screen.packageName == packageName) {
      callback.onSuccess(null)
      return
    }
    val ids = ArrayList<AutofillId>()
    val kinds = ArrayList<String>()
    screen.usernameId?.let { ids.add(it); kinds.add("username") }
    screen.passwordId?.let { ids.add(it); kinds.add("password") }
    screen.otpId?.let { ids.add(it); kinds.add("otp") }

    val intent = Intent()
      .setClassName(this, "$packageName.AutofillActivity")
      .putExtra(EXTRA_MODE, "fill")
      .putParcelableArrayListExtra(EXTRA_IDS, ids)
      .putStringArrayListExtra(EXTRA_KINDS, kinds)
      .putExtra(EXTRA_DOMAIN, screen.webDomain)
      .putExtra(EXTRA_PACKAGE, screen.packageName)
    // Mutabile: Android aggiunge all'intent i dati della schermata.
    val pending = PendingIntent.getActivity(this, nextRequestCode(), intent, pendingFlags())

    val response = FillResponse.Builder()
    // Accesso in due passaggi: valori della compilazione appena fatta, senza nuovo sblocco.
    RecentFill.match(screen.webDomain, screen.packageName)?.let { (label, values) ->
      @Suppress("DEPRECATION")
      val ds = Dataset.Builder(row("StartCredentials · $label"))
      var any = false
      for (i in ids.indices) {
        val v = values[kinds[i]] ?: continue
        @Suppress("DEPRECATION")
        ds.setValue(ids[i], AutofillValue.forText(v))
        any = true
      }
      if (any) response.addDataset(ds.build())
    }
    // Voce che apre la schermata di sblocco e scelta (autenticazione del dataset).
    @Suppress("DEPRECATION")
    val auth = Dataset.Builder(row("Compila con StartCredentials"))
    for (id in ids) {
      @Suppress("DEPRECATION")
      auth.setValue(id, null)
    }
    auth.setAuthentication(pending.intentSender)
    response.addDataset(auth.build())

    // Proposta di salvataggio a fine accesso (password obbligatoria, utente facoltativo).
    screen.passwordId?.let { pwd ->
      val save = SaveInfo.Builder(SaveInfo.SAVE_DATA_TYPE_PASSWORD or SaveInfo.SAVE_DATA_TYPE_USERNAME, arrayOf(pwd))
      screen.usernameId?.let { save.setOptionalIds(arrayOf(it)) }
      save.setFlags(SaveInfo.FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE)
      response.setSaveInfo(save.build())
    }
    callback.onSuccess(response.build())
  }

  private fun row(text: String) = RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
    setTextViewText(android.R.id.text1, text)
  }

  private fun pendingFlags() = PendingIntent.FLAG_CANCEL_CURRENT or
    (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) PendingIntent.FLAG_MUTABLE else 0)

  /**
   * Fine di un accesso: Android ha chiesto "Salvare in StartCredentials?" e
   * l'utente ha confermato. Si apre la schermata dell'app, che sblocca e salva.
   * I valori passano solo nell'intent interno all'app, il servizio non li conserva.
   */
  override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
    val ctx = request.fillContexts.lastOrNull()
    if (ctx == null) {
      callback.onSuccess()
      return
    }
    val screen = AutofillParser.parse(ctx.structure)
    val values = AutofillParser.values(ctx.structure)
    val password = screen.passwordId?.let { values[it] }
    if (password.isNullOrEmpty()) {
      callback.onSuccess()
      return
    }
    val intent = Intent()
      .setClassName(this, "$packageName.AutofillActivity")
      .putExtra(EXTRA_MODE, "save")
      .putExtra(EXTRA_DOMAIN, screen.webDomain)
      .putExtra(EXTRA_PACKAGE, screen.packageName)
      .putExtra(EXTRA_SAVE_USERNAME, screen.usernameId?.let { values[it] } ?: "")
      .putExtra(EXTRA_SAVE_PASSWORD, password)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      val pending = PendingIntent.getActivity(this, nextRequestCode(), intent, PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_IMMUTABLE)
      callback.onSuccess(pending.intentSender)
    } else {
      startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
      callback.onSuccess()
    }
  }

  companion object {
    const val EXTRA_IDS = "sc_autofill_ids"
    const val EXTRA_KINDS = "sc_autofill_kinds"
    const val EXTRA_DOMAIN = "sc_autofill_domain"
    const val EXTRA_PACKAGE = "sc_autofill_package"
    const val EXTRA_MODE = "sc_autofill_mode"
    const val EXTRA_SAVE_USERNAME = "sc_autofill_save_username"
    const val EXTRA_SAVE_PASSWORD = "sc_autofill_save_password"
    private var requestCode = 1000
    @Synchronized private fun nextRequestCode(): Int = ++requestCode
  }
}
