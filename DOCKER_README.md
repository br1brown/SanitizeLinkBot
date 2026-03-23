# SanitizeLinkBot - Docker Setup

## Quick Start (Development)

```bash
cd /c/Users/br1br/source/repos/SanitizeLinkBot

# Copia il file di esempio
cp .env.docker.example .env.docker

# Edita .env.docker e inserisci il tuo TELEGRAM_BOT_TOKEN
# Usa il tuo editor preferito

# Avvia il bot
docker compose up --build
```

## Comandi Utili

```bash
# Avvia in background
docker compose up --build -d

# Ferma il bot
docker compose down

# Logs in tempo reale
docker compose logs -f

# Accedi al container
docker compose exec sanitizelinkbot bash

# Ricostruisci l'immagine
docker compose up --build

# Pulisci i dati
docker compose down -v  # Attenzione: cancella il volume!
```

## Production Deployment

```bash
# Usa la config di produzione
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Verifica lo stato
docker compose logs sanitizelinkbot
```

## Development vs Production

### Development (`docker-compose.override.yml` - applicato automaticamente)
- ✅ Codice montato in bind mount (hot reload)
- ✅ Debug abilitato
- ✅ TTY interattiva

### Production (`docker-compose.prod.yml`)
- ✅ Codice baked nell'immagine (immutabile)
- ✅ Logging strutturato (json-file, max 10mb)
- ✅ Restart sempre attivo

## Environment Variables

Copia `.env.docker.example` in `.env.docker` e personalizza:

```env
TELEGRAM_BOT_TOKEN=your_token_here
BATCH_MAX_CONCURRENCY=6
HTTP_CONNECTIONS_PER_HOST=10
HTTP_MAX_REDIRECTS=30
HTTP_TIMEOUT_SEC=30
HTTP_TTL_DNS_CACHE=60
HTTP_VALIDA_LINK_POST_PULIZIA=true
LOG_LEVEL=INFO
```

⚠️ **Non committare `.env.docker` su Git!** È nel `.gitignore`.

## Volume

- `bot-data`: Persiste i dati del bot tra i container

## Health Check

Il bot ha un health check integrato che verifica ogni 30 secondi.

```bash
docker ps  # Vedi lo status (healthy/unhealthy)
```

## Troubleshooting

**Il bot non parte:**
```bash
docker compose logs sanitizelinkbot
```

**Errore: "Can't connect to Telegram"**
- Verifica di aver copiato `.env.docker` e inserito il token

**Vuoi rigenerare l'immagine:**
```bash
docker compose up --build
```

**Vuoi cancellare tutto e ricominciare:**
```bash
docker compose down -v
docker image rm sanitizelinkbot
docker compose up --build
```
