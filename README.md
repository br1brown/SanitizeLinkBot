# SanitizeLinkBot

[![Python Tests](https://github.com/br1brown/SanitizeLinkBot/actions/workflows/pytest.yml/badge.svg)](https://github.com/br1brown/SanitizeLinkBot/actions/workflows/pytest.yml)

**SanitizeLinkBot** è un bot Telegram progettato per migliorare la qualità e la privacy dei link condivisi.
Rimuove automaticamente i parametri di tracciamento, segue i redirect, valida i risultati e può reindirizzare verso frontend alternativi privacy-friendly.

Funziona in chat private, gruppi e modalità inline.


## 🚀 Caratteristiche principali

### Pulizia e sicurezza

* Rimozione automatica dei parametri di tracking (`utm_*`, `fbclid`, `gclid`, ecc.)
* Supporto a regole avanzate per dominio tramite database **ClearURLs**
* Estrazione dell’URL reale da link wrapper (es. `l.facebook.com`)
* Validazione del link finale per garantire coerenza con l’originale

### Gestione avanzata dei link

* Follow automatico dei redirect (HTTP, meta refresh, alcuni JS)
* Estrazione intelligente dai messaggi Telegram (testo, caption, entità cliccabili)
* Elaborazione batch con concorrenza e deduplicazione
* Cache LRU configurabile per migliorare le performance

### Privacy e frontend alternativi

* Possibilità di reindirizzare a versioni alternative dei siti:

  * YouTube → Invidious
  * Twitter/X → xcancel
  * TikTok → ProxiTok
  * Wikipedia → mirror privacy-friendly
  * Google → DuckDuckGo / OpenStreetMap

### Integrazione e strumenti

* Modalità inline (`@NomeBot <link>`)
* Utilizzo nei gruppi con modalità manuale o automatica
* Analisi tecnica dei link tramite `/scan` (urlscan.io)
* Sistema di preferenze configurabili per chat


## 🧭 Utilizzo

### Chat privata

Invia uno o più link: il bot risponderà con le versioni pulite o confermerà che sono già corretti.

### Gruppi

* Usa `/sanifica` rispondendo a un messaggio con link
* Oppure attiva la **modalità automatica** da `/settings`

Comportamento in modalità automatica:

* 👍 se il link è già pulito
* Risposta con link modificato se necessario
* Nessun messaggio per contenuti senza link

### Modalità inline

```
@NomeDelBot <link>
```

### Analisi link

```
/scan <link>
```

Restituisce report tecnico (richiede API key urlscan.io)

### Altri comandi

| Comando     | Descrizione                          |
| ----------- | ------------------------------------ |
| `/start`    | Messaggio di benvenuto               |
| `/help`     | Guida rapida e lista funzionalità    |
| `/settings` | Impostazioni della chat corrente     |
| `/sanifica` | Pulisci i link (in risposta a un messaggio) |
| `/scan`     | Analisi tecnica tramite urlscan.io *(richiede API key)* |


## ⚙️ Configurazione BotFather

Prima dell’utilizzo, abilita queste opzioni:

* Inline Mode → Enable
* Allow Groups → Enable
* Group Privacy → Disable

## 🐍 Installazione senza Docker

### Prerequisiti

* Python 3.11+
* Token bot Telegram

### Avvio

```bash
git clone https://github.com/br1brown/SanitizeLinkBot.git
cd SanitizeLinkBot

pip install -r requirements.txt

echo "TELEGRAM_BOT_TOKEN=il_tuo_token" > .env

python -m sanitizelinkbot
```

> Su Linux/macOS viene usato automaticamente `uvloop` per migliori performance. Su Windows si usa l'event loop standard di asyncio.


## 🐳 Installazione con Docker (consigliata)

### Prerequisiti

* Docker
* Docker Compose
* Token bot Telegram

### Avvio

```bash
git clone https://github.com/br1brown/SanitizeLinkBot.git
cd SanitizeLinkBot

echo "TELEGRAM_BOT_TOKEN=il_tuo_token" > .env

docker compose up -d --build
docker logs -f sanitizelinkbot
```

### Token

Può essere fornito tramite:

* Variabile ambiente `TELEGRAM_BOT_TOKEN` (consigliato)
* File `token.txt` (sconsigliato per sicurezza)

## 🔧 Configurazione

### ClearURLs

* Scaricato automaticamente al primo avvio
* Aggiornamento periodico automatico
* Funziona anche senza (modalità fallback)

### keys.json

Definisce le regole di pulizia:

```json
{
  "EXACT_KEYS": ["utm_source", "utm_medium", "fbclid", "gclid"],
  "PREFIX_KEYS": ["utm_", "mc_"],
  "ENDS_WITH": ["_hsenc", "_hsmi"],
  "FRAG_KEYS": ["utm", "ref"],
  "DOMAIN_WHITELIST": ["esempio.com"]
}
```

---

### Variabili ambiente

| Variabile                     | Default | Descrizione                  |
| ----------------------------- | ------- | ---------------------------- |
| TELEGRAM_BOT_TOKEN            | —       | Token del bot                |
| URLSCAN_API_KEY               | —       | Abilita `/scan`              |
| BATCH_MAX_CONCURRENCY         | 6       | Link processati in parallelo |
| CACHE_MAX_SIZE                | 100     | Dimensione cache             |
| HTTP_MAX_REDIRECTS            | 30      | Limite redirect              |
| HTTP_TIMEOUT_SEC              | 30      | Timeout richieste            |
| HTTP_CONNECTIONS_PER_HOST     | 10      | Connessioni simultanee       |
| HTTP_TTL_DNS_CACHE            | 60      | Cache DNS                    |
| HTTP_VALIDA_LINK_POST_PULIZIA | true    | Validazione link             |
| LOG_LEVEL                     | INFO    | Livello log                  |


## 🧩 Frontend alternativi

### Attivi

| Sito          | Alternativa   |
| ------------- | ------------- |
| YouTube       | Invidious     |
| Twitter/X     | xcancel       |
| TikTok        | ProxiTok      |
| Wikipedia     | wl.vern.cc    |
| Google Search | DuckDuckGo    |
| Google Maps   | OpenStreetMap |

### Disabilitati (frontend non disponibili)

* Reddit
* Instagram
* Tumblr
* Genius
* Goodreads

> Nota: l’ecosistema dei frontend alternativi è instabile e soggetto a cambiamenti.


## 📁 Struttura del progetto

```
sanitizelinkbot/
├── app_config.py        # configurazione da variabili d'ambiente
├── chat_prefs.py        # preferenze per chat (persistenza su file)
├── clearurls_loader.py  # download e aggiornamento del database ClearURLs
├── getter_url.py        # fetch HTTP, redirect, estrazione titolo
├── sanitizer.py         # pipeline principale di pulizia
├── telegram_handlers.py # handler dei comandi e messaggi Telegram
├── telegram_io.py       # parsing messaggi e formatting risposte
├── url_translator.py    # traduzione verso frontend alternativi
├── urlscan_client.py    # client per le API urlscan.io
└── utils.py             # utilità condivise (logger, render template, …)

data/                    # cache del database ClearURLs (generata automaticamente)
templates/               # template HTML per i messaggi del bot
tests/
```


## 🧠 Filosofia del progetto

SanitizeLinkBot nasce con tre obiettivi principali:

* **Privacy** → eliminare tracking e redirect inutili
* **Chiarezza** → rendere i link leggibili e condivisibili
* **Automazione** → funzionare senza intervento manuale

---

## 📄 Licenza

Il codice di questo progetto è distribuito sotto licenza **MIT**.

### Dipendenze di terze parti

| Libreria | Licenza |
| -------- | ------- |
| [python-telegram-bot](https://github.com/python-telegram-bot/python-telegram-bot) | LGPL-3.0 |
| [aiohttp](https://github.com/aio-libs/aiohttp) | Apache-2.0 |
| [certifi](https://github.com/certifi/python-certifi) | MPL-2.0 |
| [tldextract](https://github.com/john-kurkowski/tldextract) | BSD-3-Clause |
| [uvloop](https://github.com/MagicStack/uvloop) | MIT / Apache-2.0 |
| [ClearURLs Rules DB](https://github.com/ClearURLs/Rules) | LGPL-3.0 |

Per i dettagli vedere il file [NOTICE](NOTICE).
