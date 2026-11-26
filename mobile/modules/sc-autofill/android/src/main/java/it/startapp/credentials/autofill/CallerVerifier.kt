package it.startapp.credentials.autofill

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import android.util.Log
import java.security.MessageDigest

/**
 * Verifica DI SICUREZZA dell'app che chiede la compilazione, tramite il suo
 * certificato di firma (SHA-256), come fanno Bitwarden e 1Password.
 *
 * Perché serve: la struttura della schermata (AssistStructure) è fornita
 * dall'app chiamante, quindi un'app malevola può dichiarare QUALSIASI webDomain
 * (es. "mia-banca.it") per farsi proporre le credenziali di un altro sito
 * (phishing). Il nome del pacchetto da solo non basta nemmeno per le app native:
 * un APK ricompilato/sideloaded può riusare lo stesso packageName con una firma
 * diversa. L'unico ancoraggio affidabile è il certificato di firma del chiamante,
 * che solo lo sviluppatore originale possiede.
 *
 * Principio FAIL-CLOSED: se non riusciamo a verificare la firma, trattiamo il
 * chiamante come NON fidato (non browser / associazione non confermata).
 */
object CallerVerifier {
  private const val TAG = "ScAutofill"

  /**
   * Hash SHA-256 (hex minuscolo, senza ":") dei certificati di firma di release
   * dei browser noti. SOLO da questi accettiamo il webDomain dichiarato.
   *
   * ================================ IMPORTANTE =============================
   * TODO(utente): confermare/popolare gli hash su dispositivi reali PRIMA del
   * rilascio. Qui gli insiemi sono VUOTI di proposito => fail-closed: finché
   * non sono popolati, nessun webDomain viene accettato (l'autofill dei browser
   * ricadrà sul match per solo pacchetto, che per i browser non trova nulla).
   *
   * Come ottenere l'hash corretto per ogni browser:
   *   1) Installa il browser dallo store sul dispositivo/emulatore.
   *   2) Avvia l'autofill su una pagina di login di quel browser: nei log
   *      (Logcat, tag "ScAutofill") compare la riga
   *      "browser non verificato <pkg> firma=<sha256>" con l'hash reale.
   *      In alternativa: `apksigner verify --print-certs <apk>` oppure
   *      `keytool -printcert -jarfile <apk>` (riga SHA256), togliendo i ":".
   *   3) Incolla l'hash (hex minuscolo, senza ":") nell'insieme del pacchetto.
   * Un pacchetto può avere più firme valide (es. varianti regionali): l'insieme
   * ne accetta diverse.
   * ========================================================================
   */
  private val BROWSERS: Map<String, Set<String>> = mapOf(
    // Google Chrome (e canali beta/dev) — firma Google Play release.
    "com.android.chrome" to emptySet(),
    "com.chrome.beta" to emptySet(),
    "com.chrome.dev" to emptySet(),
    "com.chrome.canary" to emptySet(),
    // Mozilla Firefox (+ beta/nightly/focus).
    "org.mozilla.firefox" to emptySet(),
    "org.mozilla.firefox_beta" to emptySet(),
    "org.mozilla.fenix" to emptySet(),
    "org.mozilla.focus" to emptySet(),
    // Microsoft Edge.
    "com.microsoft.emmx" to emptySet(),
    // Brave.
    "com.brave.browser" to emptySet(),
    "com.brave.browser_beta" to emptySet(),
    // Opera (+ mini/beta).
    "com.opera.browser" to emptySet(),
    "com.opera.browser.beta" to emptySet(),
    "com.opera.mini.native" to emptySet(),
    // DuckDuckGo.
    "com.duckduckgo.mobile.android" to emptySet(),
    // Samsung Internet.
    "com.sec.android.app.sbrowser" to emptySet(),
    // Browser AOSP / stock.
    "com.android.browser" to emptySet(),
    // Vivaldi, Kiwi, Ecosia (diffusi).
    "com.vivaldi.browser" to emptySet(),
    "com.kiwibrowser.browser" to emptySet(),
    "com.ecosia.android" to emptySet(),
  )

  /** true SOLO se il pacchetto è un browser noto E la sua firma coincide. */
  fun isVerifiedBrowser(context: Context, packageName: String): Boolean {
    val known = BROWSERS[packageName] ?: return false // non è nell'elenco browser
    val caller = certHashes(context, packageName)
    if (caller.isEmpty()) return false // firma illeggibile => fail-closed
    if (known.isEmpty()) {
      // Pacchetto browser noto ma hash non ancora confermato: fail-closed e
      // log dell'hash reale, così l'utente può confermarlo (vedi BROWSERS).
      Log.w(TAG, "browser non verificato $packageName firma=${caller.joinToString(",")} (hash da confermare in CallerVerifier.BROWSERS)")
      return false
    }
    return caller.any { it in known }
  }

  /**
   * SHA-256 (hex) del certificato di firma primario del chiamante, per legare
   * l'associazione di un'app alla sua firma (androidapp://pkg@sha256).
   * null se non leggibile.
   */
  fun certSha256(context: Context, packageName: String): String? =
    certHashes(context, packageName).firstOrNull()

  /** Hash SHA-256 (hex minuscolo) di tutte le firme correnti del pacchetto. */
  private fun certHashes(context: Context, packageName: String): List<String> {
    val sigs = signatures(context, packageName) ?: return emptyList()
    val md = MessageDigest.getInstance("SHA-256")
    return sigs.map { sig ->
      md.reset()
      md.digest(sig.toByteArray()).joinToString("") { b -> "%02x".format(b) }
    }
  }

  @Suppress("DEPRECATION")
  private fun signatures(context: Context, packageName: String): Array<Signature>? {
    return try {
      val pm = context.packageManager
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        // API 28+: firme correnti dell'APK (apkContentsSigners), più robusto
        // di GET_SIGNATURES contro la contraffazione della firma.
        val info = pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        val si = info.signingInfo ?: return null
        if (si.hasMultipleSigners()) si.apkContentsSigners else si.signingCertificateHistory
      } else {
        val info = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
        info.signatures
      }
    } catch (e: Exception) {
      // Pacchetto assente o non leggibile: nessuna firma => fail-closed.
      null
    }
  }
}
