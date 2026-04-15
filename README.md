# SanitizeLinkBot

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
- **Modalità inline**: `@NomeDelBot <link>` restituisce la versione sanificata
- **Uso nei gruppi**: comando `/sanifica` su un messaggio contenente link, oppure **modalità automatica** che elabora ogni messaggio con link
- **Feedback visivo**: reaction 👀 durante l'elaborazione, ❌ se nessun link viene trovato


## Frontend alternativi supportati

Quando la funzione **Frontend alternativo** è attiva, i link ai seguenti siti vengono reindirizzati a versioni privacy-friendly:

| Sito originale | Frontend alternativo |
|---|---|
| YouTube / YouTube Music | Invidious (yewtu.be) |
| Twitter / X | Nitter |
| Reddit | Teddit |
| TikTok | ProxiTok |
| Instagram | Pixwox |
| Wikipedia | Wikiless |
| Tumblr | Priviblur |
| Genius | Intellectual |
| Goodreads | BiblioReads |
| Google Ricerca | DuckDuckGo |
| Google Maps | OpenStreetMap |


## Come si usa

- **Chat privata**: invia un messaggio con uno o più link e il bot risponde con le versioni pulite
- **Nei gruppi**:
  - Rispondi a un messaggio con `/sanifica` per pulire i link di quel messaggio
  - Oppure attiva la **Modalità automatica** in `/settings`: il bot elaborerà ogni messaggio con link senza bisogno di comandi
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
- Dipendenze: `python-telegram-bot >= 20`, `aiohttp`, `certifi`

```bash
pip install -r requirements.txt
```

### Token

Il token può essere fornito in uno dei seguenti modi:

- Variabile di ambiente `TELEGRAM_BOT_TOKEN` (consigliato)
- File `token.txt` nella directory del progetto — comodo per chi vuole avviare il bot velocemente senza toccare variabili d'ambiente, ma sconsigliato: il file potrebbe finire accidentalmente in un commit o in un backup

### Avvio

```bash
python __main__.py
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

### File `env`

Variabili di configurazione tecnica. Non sovrascrivono variabili già presenti nell'ambiente di sistema.

| Variabile | Default | Descrizione |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | — | Token del bot (alternativa a `token.txt`) |
| `BATCH_MAX_CONCURRENCY` | `6` | Link elaborati in parallelo |
| `HTTP_MAX_REDIRECTS` | `30` | Numero massimo di redirect seguiti |
| `HTTP_TIMEOUT_SEC` | `30` | Timeout HTTP in secondi |
| `HTTP_CONNECTIONS_PER_HOST` | `10` | Connessioni simultanee per host |
| `HTTP_TTL_DNS_CACHE` | `60` | TTL cache DNS in secondi |
| `HTTP_VALIDA_LINK_POST_PULIZIA` | `true` | Valida l'URL pulito prima di inviarlo |
| `LOG_LEVEL` | `INFO` | Livello di log (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |


## Struttura del progetto

```
.
├── __main__.py              # Entry point principale
├── app_config.py            # Configurazione da variabili d'ambiente
├── chat_prefs.py            # Gestione preferenze per chat (SQLite)
├── getter_url.py            # Estrazione URL dai messaggi Telegram
├── sanitizer.py             # Sanificazione, follow redirect, validazione
├── telegram_io.py           # Formattazione output per Telegram
├── telegram_handlers.py     # Handler comandi ed eventi
├── utils.py                 # Funzioni di utilità condivise
├── UrlTranslator.py         # Reindirizzamento a frontend alternativi
├── requirements.txt         # Dipendenze Python
├── keys.json                # Regole di sanificazione e whitelist domini
├── env                      # Variabili di configurazione (non sensibili)
├── Dockerfile               # Immagine Docker
├── docker-compose.yml       # Configurazione Docker Compose
├── start.html               # Template messaggio di benvenuto
├── help.html                # Template guida rapida
├── settings_private.html    # Template impostazioni (chat privata)
└── settings_group.html      # Template impostazioni (gruppo)
```
