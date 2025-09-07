# SanitizeLinkBot

Rende i link più semplici da condividere: rimuove i parametri di tracking, segue i redirect e restituisce l’URL finale pulito. Funziona in chat privata, nei gruppi e in modalità inline.

## Funzionalità

* Rimozione dei parametri di tracciamento (utm, fbclid, gclid, ecc.)
* Follow dei redirect fino all’URL finale (HTTP, meta refresh, redirect JS comuni)
* Pulizia di frammenti superflui basata su prefissi configurabili (FRAG\_KEYS)
* Titolo della pagina di destinazione opzionale (Output.show\_title)
* Validazione del link pulito prima dell’invio (HTTP.validate\_cleaned)
* Normalizzazioni: aggiunta https se manca, rimozione punteggiatura finale
* Whitelist di domini non modificabili
* Deduplicazione e sanificazione in batch con concorrenza limitata
* Modalità inline: sanifica il primo link della query e lo propone come risultato

## Come si usa

* **Chat privata**: incolla uno o più link; il bot risponde con le versioni pulite.
* **Nei gruppi**: rispondi a un messaggio che contiene link e menziona il bot (es. `@NomeDelBot`); il bot invia i link sanificati di quel messaggio.
* **Ricerca inline**: digita `@NomeDelBot <link>` direttamente nella barra di testo.

## Requisiti

* Python 3.10+
* Dipendenze principali: `python-telegram-bot >= 20`, `aiohttp`

Installazione rapida:

```bash
pip install -r requirements.txt
```

## Configurazione

Metti il token in `token.txt` oppure nella variabile d’ambiente `TELEGRAM_BOT_TOKEN`.

File `config.json` (chiavi principali):

```json
{
  "Output": { "show_title": true },
  "Batch": { "max_concurrency": 10 },
  "HTTP": {
    "connections_per_host": 10,
    "ttl_dns_cache": 60,
    "max_redirects": 5,
    "timeout_sec": 15,
    "valida_link_post_pulizia": true
  },
  "Formatting": { "trailing_punct": ".,;:!?)”»’'\"" },
  "Logging": { "level": "INFO" }
}
```

* `Output.show_title`: se true, prova a estrarre e mostrare il titolo della pagina.
* `Batch.max_concurrency`: numero max di sanificazioni in parallelo.
* `HTTP.connections_per_host`: limite per host nelle richieste.
* `HTTP.ttl_dns_cache`: TTL cache DNS del connettore `aiohttp` (opzionale ma supportato dal codice).
* `HTTP.max_redirects`: numero massimo di redirect seguiti.
* `HTTP.timeout_sec`: timeout totale per richiesta.
* `HTTP.valida_link_post_pulizia`: se true, verifica che l’URL pulito sia raggiungibile; in caso contrario invia l’URL finale originale.
* `Formatting.trailing_punct`: insieme di caratteri finali da rimuovere dai link.
* `Logging.level`: livello di log (DEBUG, INFO, WARNING, ERROR, CRITICAL).

File `keys.json` (estratto indicativo):

```json
{
  "EXACT_KEYS": ["utm_source", "utm_medium", "fbclid", "gclid"],
  "PREFIX_KEYS": ["utm_", "mc_"],
  "ENDS_WITH": ["_hsenc", "_hsmi"],
  "FRAG_KEYS": ["utm", "ref"],
  "DOMAIN_WHITELIST": {
    "esempio.com": {}
  }
}
```

## Avvio

```bash
python -m sanitize_link_bot
```

Oppure esegui direttamente il modulo principale se il package è diverso:

```bash
python __main__.py
```

## Note

* I link `mailto:` e `tel:` non vengono modificati.
* Nei gruppi è necessario rispondere al messaggio originale e menzionare il bot.
* Se un link non è valido dopo la pulizia e la validazione è attiva, viene inviato l’URL finale raggiunto dai redirect.
