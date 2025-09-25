# 📌 SanitizeLinkBot

SanitizeLinkBot è un **bot Telegram** che rende i link più semplici da condividere: rimuove i parametri di tracking, segue i redirect, valida il risultato e può indirizzare a **front-end alternativi**. Funziona in chat privata, nei gruppi e in modalità inline.



## 🚀 Funzionalità

- **Sanificazione dei link**: rimozione di parametri di tracciamento (utm, fbclid, gclid, ecc.)
- **Follow dei redirect**: segue redirect HTTP, meta refresh e alcuni redirect JS comuni, verificando che l’URL sanificato sia raggiungibile
- **Potenziale Indirizzamento a front-end alternativi** (es. Nitter, Invidious)
- **Preferenze configurabili per chat** tramite `/settings` (prediligere del frontend alternativi, o mostrare titolo e URL)
- **Whitelist di domini**: possibilità di escludere certi domini da modifiche
- **Elaborazione in batch con concorrenza**: sanificazione di più link in parallelo
- **Modalità inline**: `@NomeDelBot <link>` restituisce la versione sanificata
- **Uso nei gruppi**: comando `/sanifica` su un messaggio contenente link


## 💬 Come si usa

- **Chat privata**: invia un messaggio con uno o più link e il bot risponde con le versioni pulite
- **Nei gruppi**: rispondi a un messaggio che contiene link con `/sanifica`
- **Ricerca inline**: digita `@NomeDelBot <link>` nella barra di testo
- **Impostazioni**: usa `/settings` per decidere come devono essere mostrati i risultati


## 🔧 Requisiti e installazione

* Python 3.10+
* Dipendenze principali: `python-telegram-bot >= 20`, `aiohttp`

Installazione rapida:

```bash
pip install -r requirements.txt
```


## ⚙️ Configurazione

Il token può essere fornito in uno dei seguenti modi:

* file `token.txt`
* variabile di ambiente `TELEGRAM_BOT_TOKEN`

### File `chat_prefs.json`

Memorizza le preferenze delle chat (es. formato dell’output).

### File `keys.json`

Definisce i parametri da rimuovere e le whitelist. Esempio:

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

Contiene le variabili di ambiente modificabili per la configurazione tecnica del bot.


## ▶️ Avvio

Eseguire il file principale:

```bash
python -m __main__
```

Oppure:

```bash
python __main__.py
```


## 📂 Struttura del progetto

```
.
├── __main__.py              # Entry point principale
├── app_config.py            # Configurazioni generali dell'applicazione
├── chat_prefs.py / .json    # Gestione preferenze utente
├── getter_url.py            # Logica per recupero e parsing URL
├── sanitizer.py             # Funzioni di sanificazione link
├── telegram_io.py           # Gestione I/O con le API di Telegram
├── telegram_handlers.py     # Gestione eventi e messaggi
├── utils.py                 # Funzioni di utilità
├── UrlTranslator.py         # Gestione front-end alternativi per URL
├── requirements.txt         # Dipendenze Python
├── keys.json                # File con chiavi e regole di sanificazione
├── env                      # Variabili di ambiente
└── README.md                # Documentazione
```
