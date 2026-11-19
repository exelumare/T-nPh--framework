"""Crawler Engine for TanPha V6. Explores links and extracts parameters."""
import logging
from urllib.parse import urlparse, urljoin, parse_qsl
from bs4 import BeautifulSoup
from core.context import TargetContext

logger = logging.getLogger(__name__)

class CrawlerEngine:
    def __init__(self, max_depth=2, max_urls=50):
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.visited_urls = set()
        self.found_endpoints = set()

    def crawl(self, context: TargetContext, auth_checker=None):
        print(f"\n[CRAWLER] Starting crawl on {context.target.base_url} (Max Depth: {self.max_depth})...")
        
        start_url = context.target.base_url
        queue = [(start_url, 0)] # (URL, Depth)
        
        # Tambahin URL awal ke visited
        self.visited_urls.add(start_url)

        while queue and len(self.visited_urls) <= self.max_urls:
            current_url, depth = queue.pop(0)
            
            if depth > self.max_depth:
                continue

            print(f"    [>] Crawling (Depth {depth}): {current_url}")
            
            try:
                # Pake HTTPClient biar tetep patuh sama LAS & Evasion
                res = context.http_client.request("GET", current_url, auth_checker=auth_checker, timeout=10)
                
                if not res or not res.success or not res.response:
                    continue
                    
                content_type = res.response.headers.get("Content-Type", "").lower()
                if "text/html" not in content_type:
                    continue

                soup = BeautifulSoup(res.response.text, "html.parser")

                # 1. Ekstrak Form
                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    method = form.get("method", "GET").upper()
                    action_url = urljoin(current_url, action) if action else current_url
                    
                    # Cek scope sebelum masukin
                    if auth_checker and not auth_checker(action_url):
                        continue

                    inputs = [i.get("name") for i in form.find_all(["input", "textarea"]) if i.get("name")]
                    if inputs:
                        self.found_endpoints.add((action_url, method, tuple(inputs)))

                # 2. Ekstrak Link (<a href>)
                for a_tag in soup.find_all("a", href=True):
                    link = a_tag["href"]
                    
                    # Skip link sampah
                    if link.startswith("javascript:") or link.startswith("mailto:") or link.startswith("#"):
                        continue
                        
                    next_url = urljoin(current_url, link)
                    
                    # Cek scope (jangan sampe crawler keluar dari target)
                    if auth_checker and not auth_checker(next_url):
                        continue
                        
                    # Cek parameter di URL
                    parsed_url = urlparse(next_url)
                    if parsed_url.query:
                        params = [k for k, v in parse_qsl(parsed_url.query)]
                        if params:
                            self.found_endpoints.add((next_url, "GET", tuple(params)))
                    
                    # Masukin ke antrean kalau belum pernah dikunjungi
                    if next_url not in self.visited_urls:
                        self.visited_urls.add(next_url)
                        queue.append((next_url, depth + 1))

            except Exception as e:
                logger.debug(f"Error crawling {current_url}: {e}")

        print(f"\n[CRAWLER] Finished! Visited {len(self.visited_urls)} URLs.")
        print(f"[CRAWLER] Found {len(self.found_endpoints)} endpoints with parameters:\n")
        
        # Simpan ke context.discovery (biar bisa dibaca modul)
        context.discovery.endpoints = list(self.found_endpoints)
        
        for endpoint in context.discovery.endpoints:
            print(f"    [+] {endpoint[1]} {endpoint[0]} -> Params: {endpoint[2]}")
            
        print("")
        return context.discovery.endpoints
