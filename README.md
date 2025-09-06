# SanitizeLinkBot

Bot Telegram che:

* Pulisce i link da parametri di tracking
* Segue redirect fino all'URL finale
* Funziona sia in chat private che nei gruppi (quando menzionato)

## ⚙️ Configurazione

1. Inserire il token del bot in un file `token.txt` (oppure in variabile d'ambiente `TELEGRAM_BOT_TOKEN`)
2. Configurare i parametri nel file `config.json` (timeout, logging, ecc.)
3. I parametri di tracking da rimuovere sono definiti in `keys.json`

## 📦 Requisiti

Installare le dipendenze:

```bash
pip install -r requirements.txt
```

## 🛠️ Uso

* **In chat privata**: invia un messaggio con uno o più link, il bot risponde con la versione pulita
* **Nei gruppi**: rispondi a un messaggio contenente link e menziona il bot. Verranno restituiti i link sanificati

## 📖 Funzionalità

* Rimozione dei parametri di tracciamento (es. `utm`, `fbclid`)
* Follow dei redirect fino all'URL finale
* Pulizia di frammenti superflui (`#...`)

## ✅ Vantaggi

* Collegamenti più brevi
* Migliore leggibilità
* Maggiore rispetto della privacy
