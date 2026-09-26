# Changelog

## 2026-09-25

### `/scan` ora usa ScanMalware.com al posto di urlscan.io

- Il comando `/scan` non richiede più alcuna API key né account: l'API di [ScanMalware.com](https://scanmalware.com) è anonima. `/scan` è quindi **sempre attivo**.
- La variabile `URLSCAN_API_KEY` non è più letta. Al suo posto esiste `SCANMALWARE_API_KEY`, **opzionale**: serve solo ad alzare il rate limit (600 → 3000 richieste/minuto), non a sbloccare il comando.
- La risposta include il verdetto di sicurezza (malevolo / rischio alto / sospetto / nessuna minaccia) con punteggio di rischio e i principali fattori di rischio, lo screenshot della pagina (sotto spoiler) e il link al report completo.
- Le scansioni sono inviate come **unlisted** (prima, con urlscan, erano pubbliche): non compaiono nella ricerca, negli elenchi né nei feed di ScanMalware, ma il report resta visibile a chi ha il link e l'URL è comunque conservato dal servizio (nessuna politica di retention dichiarata). Per questo `/scan` è ora **disattivato di default** e si abilita per chat da `/settings` → **Scan esterno** (nuova preferenza `scan_enabled`, migrazione automatica del DB): in un gruppo nessuno può mandare a un servizio terzo un link riservato postato da altri senza che la chat l'abbia scelto.
- Il verdetto viene calcolato da ScanMalware dopo la cattura della pagina: il bot attende fino a 2 minuti; se il verdetto non è ancora pronto risponde comunque con il link al report.

## 2026-09-02

### ⚠️ Azione richiesta per chi ha già un deploy Docker in produzione

Il container ora gira come utente non-root (`botuser`, uid 999) invece che come `root`. Se hai già un volume `bot-data` esistente (creato quando il container girava da root), i file al suo interno sono di proprietà di `root` e `botuser` non potrà scriverci: `chat_prefs.db` e gli aggiornamenti automatici di ClearURLs/Debounce falliranno in silenzio.

**Prima di aggiornare a questa immagine su un volume esistente**, sistema i permessi una volta sola:

```bash
docker run --rm -v bot-data:/data alpine chown -R 999:999 /data
```

Un volume nuovo (mai usato prima) non ha bisogno di questo passaggio: l'immagine crea `/app/data` già di proprietà di `botuser`, quindi Docker inizializza il volume con i permessi corretti in automatico al primo mount.

### Sicurezza e infrastruttura

- Il container Docker gira ora come utente non privilegiato (`botuser`) invece che come `root`.
- Immagine base aggiornata da Python 3.10 a 3.12.
- `data/` esclusa da `.dockerignore`: prima un build locale poteva infornare nell'immagine regole ClearURLs/Debounce datate presenti sul disco dello sviluppatore.

### Affidabilità

- I redirect HTTP ora rispettano davvero `HTTP_MAX_REDIRECTS`: il parametro era già in configurazione ma non veniva passato ad aiohttp, che si fermava al suo default di 10 hop — le catene di redirect più lunghe (pubblicità, shortener) fallivano.
- Aggiunto un retry automatico per errori di rete transitori (connessione rifiutata, reset, timeout) durante il recupero dei segnali di una pagina.
- Gli handler Telegram principali (gruppo, chat privata, `/sanifica`) ora gestiscono gli errori imprevisti: prima potevano lasciare la reaction 👀 bloccata e nessuna risposta, senza alcun segnale visibile all'utente.
- Corretto un bug nell'estrazione del link reale dalle pagine di consenso cookie di Google/YouTube: un `+` letterale nell'URL di destinazione (comune nei link Google Foto/Drive/Maps) veniva convertito in uno spazio, rompendo il link.
- Le pagine di consenso concatenate (fino a 3 in sequenza) vengono ora seguite tutte, non solo la prima.

### Nuove funzionalità

- Integrata la lista Debounce di Brave come fonte complementare a ClearURLs per lo smontaggio dei link wrapper — copre, tra gli altri casi, lo smontaggio delle pagine AMP di Google.
- La reaction per "link già pulito" nei gruppi è cambiata da 👍 a 👨‍💻: un pollice in su su un link con contenuto negativo poteva leggersi come un giudizio su quel contenuto.

### Performance

- Resolver DNS asincrono (`aiodns`) al posto del resolver di default a thread-pool di aiohttp, se disponibile.
- Supporto alla compressione Brotli nelle risposte HTTP, se disponibile.

### Configurazione

- Nuove variabili d'ambiente `MAX_UNWRAP_HOPS` e `MAX_CONSENT_HOPS` (default 3 entrambe) per i limiti anti-loop nello smontaggio dei link wrapper e degli interstitial di consenso.
