from __future__ import annotations

import asyncio
import aiohttp
from typing import Optional, Dict, Any
from .utils import logger

class UrlScanClient:
    """Client asincrono per l'API di urlscan.io."""

    BASE_URL = "https://urlscan.io/api/v1"

    def __init__(self, api_key: str, session: aiohttp.ClientSession) -> None:
        self.api_key = api_key
        self.session = session
        self.headers = {
            "API-Key": self.api_key,
            "Content-Type": "application/json",
        }

    async def submit_scan(self, url: str, visibility: str = "private") -> Optional[str]:
        """Invia un URL per la scansione e restituisce l'UUID."""
        endpoint = f"{self.BASE_URL}/scan/"
        payload = {
            "url": url,
            "visibility": visibility,
            "tags": ["SanitizeLinkBot"]
        }

        try:
            async with self.session.post(endpoint, headers=self.headers, json=payload) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("uuid")
                else:
                    text = await resp.text()
                    logger.error("Errore invio urlscan.io (%d): %s", resp.status, text)
                    return None
        except Exception as err:
            logger.exception("Eccezione durante l'invio a urlscan.io: %s", err)
            return None

    async def fetch_result(self, uuid: str) -> Optional[Dict[str, Any]]:
        """Recupera il risultato di una scansione tramite UUID."""
        endpoint = f"{self.BASE_URL}/result/{uuid}/"
        try:
            async with self.session.get(endpoint, headers=self.headers) as resp:
                if resp.status == 200:
                    return await resp.json()
                elif resp.status == 404:
                    return None  # In corso
                else:
                    text = await resp.text()
                    logger.warning("Errore recupero risultato urlscan.io (%d): %s", resp.status, text)
                    return {"error": resp.status}
        except Exception as err:
            logger.exception("Eccezione durante il recupero da urlscan.io: %s", err)
            return {"error": "exception"}

    async def wait_for_result(self, uuid: str, timeout_sec: int = 60, interval_sec: int = 5) -> Optional[Dict[str, Any]]:
        """Esegue il polling finché il risultato non è pronto o scatta il timeout."""
        start_time = asyncio.get_event_loop().time()
        while (asyncio.get_event_loop().time() - start_time) < timeout_sec:
            result = await self.fetch_result(uuid)
            if result:
                if "error" in result:
                    return None
                return result
            await asyncio.sleep(interval_sec)
        logger.warning("Timeout durante l'attesa del risultato urlscan.io per %s", uuid)
        return None
