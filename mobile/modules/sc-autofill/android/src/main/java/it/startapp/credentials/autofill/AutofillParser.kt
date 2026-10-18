package it.startapp.credentials.autofill

import android.app.assist.AssistStructure
import android.os.Build
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId
import androidx.annotation.RequiresApi

/** Campi di accesso trovati in una schermata (app o pagina web). */
data class ParsedScreen(
  val usernameId: AutofillId?,
  val passwordId: AutofillId?,
  val otpId: AutofillId?,
  /** Dominio della pagina, se la richiesta viene da un browser. */
  val webDomain: String?,
  /** Pacchetto dell'app che chiede la compilazione. */
  val packageName: String,
) {
  val isEmpty: Boolean get() = usernameId == null && passwordId == null && otpId == null
}

@RequiresApi(Build.VERSION_CODES.O)
object AutofillParser {
  private val USER = Regex("user|login|email|e-mail|account|utente|accesso", RegexOption.IGNORE_CASE)
  private val OTP = Regex("otp|totp|2fa|mfa|one.?time|verification|verifica|codice|auth.?code", RegexOption.IGNORE_CASE)
  private val TEXT_TYPES = setOf("text", "email", "tel", "number", "")

  fun parse(structure: AssistStructure): ParsedScreen {
    val nodes = ArrayList<AssistStructure.ViewNode>()
    for (i in 0 until structure.windowNodeCount) collect(structure.getWindowNodeAt(i).rootViewNode, nodes)
    val domain = nodes.firstNotNullOfOrNull { n -> n.webDomain?.takeIf { it.isNotBlank() } }
    var username: AutofillId? = null
    var password: AutofillId? = null
    var otp: AutofillId? = null
    var lastText: AutofillId? = null
    for (n in nodes) {
      val id = n.autofillId ?: continue
      if (n.autofillType != View.AUTOFILL_TYPE_TEXT) continue
      when (kind(n)) {
        "password" -> if (password == null) {
          password = id
          // Il campo di testo che precede la password è di solito l'utente.
          if (username == null) username = lastText
        }
        "username" -> if (username == null) username = id
        "otp" -> if (otp == null) otp = id
        "text" -> if (password == null) lastText = id
      }
    }
    return ParsedScreen(username, password, otp, domain, structure.activityComponent.packageName)
  }

  /** Testo inserito nei campi (solo per la proposta di salvataggio). */
  fun values(structure: AssistStructure): Map<AutofillId, String> {
    val nodes = ArrayList<AssistStructure.ViewNode>()
    for (i in 0 until structure.windowNodeCount) collect(structure.getWindowNodeAt(i).rootViewNode, nodes)
    val out = HashMap<AutofillId, String>()
    for (n in nodes) {
      val id = n.autofillId ?: continue
      val v = n.autofillValue ?: continue
      if (v.isText) out[id] = v.textValue.toString()
    }
    return out
  }

  private fun collect(n: AssistStructure.ViewNode, out: MutableList<AssistStructure.ViewNode>) {
    out.add(n)
    for (i in 0 until n.childCount) collect(n.getChildAt(i), out)
  }

  /** "username", "password", "otp", "text" (campo generico) oppure null. */
  fun kind(n: AssistStructure.ViewNode): String? {
    val hints = n.autofillHints?.map { it.lowercase() } ?: emptyList()
    if (hints.any { it.contains("password") }) return "password"
    if (hints.any { it.contains("otp") || it.contains("onetimecode") || it.contains("one-time-code") }) return "otp"
    if (hints.any { it.contains("username") || it.contains("email") }) return "username"

    // Pagine web: attributi del campo HTML.
    val html = n.htmlInfo
    if (html != null) {
      if (!html.tag.equals("input", ignoreCase = true)) return null
      val attrs = HashMap<String, String>()
      html.attributes?.forEach { p -> attrs[p.first.lowercase()] = p.second ?: "" }
      val type = attrs["type"]?.lowercase() ?: "text"
      if (type == "password") return "password"
      if (type !in TEXT_TYPES) return null
      val text = listOf("name", "id", "autocomplete", "placeholder", "aria-label").joinToString(" ") { attrs[it] ?: "" }
      if (attrs["autocomplete"] == "one-time-code" || OTP.containsMatchIn(text)) return "otp"
      if (type == "email" || USER.containsMatchIn(text)) return "username"
      return "text"
    }

    // App native: tipo di input, identificativo e testo d'aiuto.
    val cls = n.inputType and InputType.TYPE_MASK_CLASS
    val variation = n.inputType and InputType.TYPE_MASK_VARIATION
    if (cls == InputType.TYPE_CLASS_TEXT && (variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
        variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD || variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD)) return "password"
    if (cls == InputType.TYPE_CLASS_NUMBER && variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD) return "password"
    val text = listOf(n.idEntry ?: "", n.hint ?: "", n.contentDescription?.toString() ?: "").joinToString(" ")
    if (OTP.containsMatchIn(text)) return "otp"
    if (cls == InputType.TYPE_CLASS_TEXT && (variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS ||
        variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS)) return "username"
    if (USER.containsMatchIn(text)) return "username"
    return if (cls == InputType.TYPE_CLASS_TEXT) "text" else null
  }
}
