package it.startapp.credentials.autofill

import android.os.SystemClock

/**
 * Ultima compilazione riuscita, solo in memoria e per 60 secondi: serve agli
 * accessi in due passaggi (utente in una pagina, password nella successiva)
 * per non chiedere un nuovo sblocco. Vale solo per lo stesso sito o la stessa app.
 */
object RecentFill {
  private const val TTL_MS = 60_000L
  private var domain: String? = null
  private var pkg: String? = null
  // Firma del chiamante: fa parte della chiave di identità (vedi match).
  private var cert: String? = null
  private var label: String = ""
  private var values: Map<String, String> = emptyMap()
  private var expiresAt = 0L

  @Synchronized
  fun remember(domain: String?, pkg: String?, cert: String?, label: String, values: Map<String, String>) {
    this.domain = domain
    this.pkg = pkg
    this.cert = cert
    this.label = label
    // Il codice OTP scade in pochi secondi: non viene riproposto.
    this.values = values.filterKeys { it == "username" || it == "password" }
    expiresAt = SystemClock.elapsedRealtime() + TTL_MS
  }

  /**
   * Valori ricordati per questa schermata, se ancora validi.
   * SICUREZZA: la chiave è l'identità VERIFICATA. Per i browser è il dominio
   * (già verificato prima di arrivare qui) più il pacchetto del browser; per le
   * app è pacchetto + firma. Così la cache in chiaro non può essere intercettata
   * da un'app che spaccia un dominio o un pacchetto con firma diversa.
   */
  @Synchronized
  fun match(domain: String?, pkg: String, cert: String?): Pair<String, Map<String, String>>? {
    if (SystemClock.elapsedRealtime() > expiresAt) {
      clear()
      return null
    }
    val same = if (domain != null) domain == this.domain && pkg == this.pkg
               else this.domain == null && pkg == this.pkg && cert == this.cert
    return if (same && values.isNotEmpty()) Pair(label, values) else null
  }

  @Synchronized
  fun clear() {
    domain = null
    pkg = null
    cert = null
    label = ""
    values = emptyMap()
    expiresAt = 0L
  }
}
