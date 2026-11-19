"""Proxy Manager for TanPha V5. Handles IP rotation and Behavioral Jitter."""
import random
import logging
import itertools
import time

logger = logging.getLogger(__name__)

class ProxyManager:
    def __init__(self, proxy_list: list = None, min_delay: float = 1.0, max_delay: float = 3.5):
        self.proxies = proxy_list or []
        self.proxy_cycle = None
        self.min_delay = min_delay
        self.max_delay = max_delay
        
        if self.proxies:
            self.proxy_cycle = itertools.cycle(self.proxies)
            logger.info(f"ProxyManager initialized with {len(self.proxies)} proxies.")

    def get_next_proxy(self, apply_jitter: bool = True) -> dict:
        """
        Ngambil proxy berikutnya dan nambahin jeda waktu acak (Jitter).
        """
        if not self.proxy_cycle:
            if apply_jitter:
                self._apply_jitter()
            return None
        
        if apply_jitter:
            self._apply_jitter()

        proxy_url = next(self.proxy_cycle)
        return {
            "http": proxy_url,
            "https": proxy_url
        }

    def _apply_jitter(self):
        """Nambahin delay acak biar nggak kena behavioral rate-limiting."""
        if self.min_delay > 0 or self.max_delay > 0:
            delay = random.uniform(self.min_delay, self.max_delay)
            logger.debug(f"Jitter applied: Sleeping for {delay:.2f} seconds.")
            time.sleep(delay)

    def add_proxy(self, proxy_url: str):
        if proxy_url not in self.proxies:
            self.proxies.append(proxy_url)
            self.proxy_cycle = itertools.cycle(self.proxies)

    @staticmethod
    def load_from_file(filepath: str) -> list:
        try:
            with open(filepath, "r") as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except Exception:
            return []
