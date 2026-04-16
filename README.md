# SanitizeLinkBot
[![Python Tests](https://github.com/br1brown/SanitizeLinkBot/actions/workflows/pytest.yml/badge.svg)](https://github.com/br1brown/SanitizeLinkBot/actions/workflows/pytest.yml)

SanitizeLinkBot è un bot Telegram che rende i link più semplici da condividere: rimuove i parametri di tracking, segue i redirect, valida il risultato e può reindirizzare a **front-end alternativi** privacy-friendly. Funziona in chat privata, nei gruppi e in modalità inline.


## Funzionalità

- **Sanificazione dei link**: rimozione di parametri di tracciamento (utm, fbclid, gclid, ecc.) con corrispondenza per chiave esatta, prefisso e suffisso
- **Follow dei redirect**: segue redirect HTTP, meta refresh e alcuni redirect JS comuni
- **Validazione post-pulizia**: verifica che l'URL sanificato punti alla stessa pagina di quello originale prima di inviarlo
- **Estrazione intelligente**: usa le entità Telegram (link cliccabili, testo-link) con fallback su regex; funziona su testo e didascalie
- **Reindirizzamento a front-end alternativi** per maggiore privacy (vedi sezione dedicata)
- **Preferenze configurabili per chat** tramite `/settings` con pulsanti inline
- **Whitelist di domini**: possibilità di escludere certi domini da modifiche
- **Elaborazione in batch con concorrenza**: sanificazione di più link in parallelo con deduplicazione
- **Cache LRU per gli URL**: gli URL già elaborati vengono riutilizzati senza ripetere fetch e redirect (dimensione configurabile via `CACHE_MAX_SIZE`)
- **Modalità inline**: `@NomeDelBot <link>` restituisce la versione sanificata
- **Uso nei gruppi**: comando `/sanifica` su un messaggio contenente link, oppure **modalità automatica** che elabora ogni messaggio con link
- **Feedback visivo**: reaction 👀 durante l'elaborazione; 👍 se il link era già pulito; ❌ (con fallback 👎) se non viene trovato nessun link


## Frontend alternativi supportati

Quando la funzione **Frontend alternativo** è attiva, i link ai seguenti siti vengono reindirizzati a versioni privacy-friendly.

**Attivi:**

| Sito originale | Frontend alternativo |
|---|---|
| YouTube / YouTube Music | Invidious (inv.nadeko.net) |
| Twitter / X | xcancel.com |
| TikTok | ProxiTok (proxitok.pufe.org) |
| Wikipedia | wl.vern.cc |
| Google Ricerca | DuckDuckGo |
| Google Maps | OpenStreetMap |

**Disabilitati — frontend offline:**

| Sito originale | Ultimo frontend | Motivo |
|---|---|---|
| Reddit | teddit.net | Offline |
| Instagram | pixwox.com | Offline, nessun sostituto affidabile |
| Tumblr | tb.opnxng.com (Priviblur) | Offline |
| Genius | intellectual.insprill.net | Offline |
| Goodreads | biblioreads.eu.org | Offline, nessun sostituto affidabile |

L'ecosistema dei frontend alternativi è in continua evoluzione: le istanze pubbliche vengono spesso dismesse senza preavviso. Gli adapter disabilitati sono mantenuti nel codice commentati e possono essere riattivati non appena si trovano istanze sostitutive stabili.


## Come si usa

- **Chat privata**: invia un messaggio con uno o più link e il bot risponde sempre con le versioni pulite (o conferma che erano già puliti)
- **Nei gruppi**:
  - Rispondi a un messaggio con `/sanifica` per pulire i link di quel messaggio
  - Oppure attiva la **Modalità automatica** in `/settings`: il bot elabora ogni messaggio con link automaticamente
    - Se il link è già pulito, risponde con una reaction 👍 senza aggiungere messaggi in chat
    - Se qualcosa cambia (tracking rimosso, frontend tradotto, redirect risolto), invia la versione pulita
    - I messaggi senza link vengono ignorati silenziosamente
- **Ricerca inline**: digita `@NomeDelBot <link>` nella barra di testo
- **Impostazioni**: usa `/settings` per decidere come devono essere mostrati i risultati


## Impostazioni (`/settings`)

Le preferenze sono salvate per ogni chat (privata o gruppo) e modificabili tramite pulsanti inline:

| Impostazione | Descrizione | Default |
|---|---|---|
| **URL in chiaro** | Mostra l'URL testuale oltre al titolo | ON |
| **Titolo pagina** | Include il titolo della pagina nell'output | ON |
| **Frontend alternativo** | Reindirizza a front-end privacy per siti supportati | OFF |
| **Modalità automatica** | (solo gruppi) Elabora automaticamente tutti i messaggi con link | OFF |


## Installazione con Docker (consigliato)

### Prerequisiti

- Docker e Docker Compose installati sulla macchina
- Un bot Telegram creato tramite [@BotFather](https://t.me/BotFather)

### Configurazione BotFather

Prima di avviare il bot, assicurati di abilitare le seguenti impostazioni in BotFather (`/mybots` → il tuo bot → Bot Settings):

| Impostazione | Valore |
|---|---|
| Inline Mode | Enable |
| Allow Groups | Enable |
| Group Privacy | Disable |

### Avvio

```bash
git clone <url-repo>
cd SanitizeLinkBot

# Crea il file .env con il token del bot
echo "TELEGRAM_BOT_TOKEN=il_tuo_token" > .env

docker compose up -d --build
docker logs -f sanitizelinkbot
```


## Installazione manuale

### Requisiti

- Python 3.10+
- Dipendenze: `python-telegram-bot >= 20`, `aiohttp`, `certifi`; su Linux/Mac viene installato automaticamente anche `uvloop` per performance migliori

```bash
pip install -r requirements.txt
```

### Token

Il token può essere fornito in uno dei seguenti modi:

- Variabile di ambiente `TELEGRAM_BOT_TOKEN` (consigliato)
- File `token.txt` nella directory del progetto — comodo per avvii rapidi, ma sconsigliato: il file potrebbe finire accidentalmente in un commit o in un backup

### Avvio

```bash
python -m sanitizelinkbot
```


## Configurazione

### File `keys.json`

Definisce i parametri da rimuovere e le whitelist:

```json
{
  "EXACT_KEYS": ["utm_source", "utm_medium", "fbclid", "gclid"],
  "PREFIX_KEYS": ["utm_", "mc_"],
  "ENDS_WITH": ["_hsenc", "_hsmi"],
  "FRAG_KEYS": ["utm", "ref"],
  "DOMAIN_WHITELIST": ["esempio.com"]
}
```

### File `.env-example`

Copia il file come `.env` (o `env`) e adattalo. Le variabili non sovrascrivono quelle già presenti nell'ambiente di sistema.

| Variabile | Default | Descrizione |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | — | Token del bot (alternativa a `token.txt`) |
| `BATCH_MAX_CONCURRENCY` | `6` | Link elaborati in parallelo |
| `CACHE_MAX_SIZE` | `100` | Numero massimo di URL tenuti in cache LRU |
| `HTTP_MAX_REDIRECTS` | `30` | Numero massimo di redirect seguiti |
| `HTTP_TIMEOUT_SEC` | `30` | Timeout HTTP in secondi |
| `HTTP_CONNECTIONS_PER_HOST` | `10` | Connessioni simultanee per host |
| `HTTP_TTL_DNS_CACHE` | `60` | TTL cache DNS in secondi |
| `HTTP_VALIDA_LINK_POST_PULIZIA` | `true` | Valida l'URL pulito prima di inviarlo |
| `LOG_LEVEL` | `INFO` | Livello di log (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |


## Struttura del progetto

```
.
├── sanitizelinkbot/         # Pacchetto Python principale
│   ├── __init__.py
│   ├── __main__.py          # Entry point (python -m sanitizelinkbot)
│   ├── app_config.py        # Configurazione da variabili d'ambiente
│   ├── chat_prefs.py        # Gestione preferenze per chat (SQLite)
│   ├── getter_url.py        # Estrazione URL dai messaggi Telegram
│   ├── sanitizer.py         # Sanificazione, follow redirect, validazione, cache LRU
│   ├── telegram_handlers.py # Handler comandi ed eventi
│   ├── telegram_io.py       # Formattazione output per Telegram
│   ├── UrlTranslator.py     # Reindirizzamento a frontend alternativi
│   └── utils.py             # Funzioni di utilità condivise
├── templates/               # Template HTML per i messaggi del bot
│   ├── start.html           # Messaggio di benvenuto
│   ├── help.html            # Guida rapida
│   ├── settings_private.html
│   └── settings_group.html
├── requirements.txt         # Dipendenze Python
├── keys.json                # Regole di sanificazione e whitelist domini
├── .env-example             # Esempio variabili di configurazione
├── Dockerfile               # Immagine Docker
└── docker-compose.yml       # Configurazione Docker Compose
```
