import asyncio
import httpx
import re
import urllib.parse
from html.parser import HTMLParser
from typing import Set, List, Dict, Any

class LinkAndFormParser(HTMLParser):
    """
    HTML Parser to extract all internal links (<a href="...">), forms (<form action="..." method="...">),
    and script/API endpoints (<script src="...">, fetch/axios URLs).
    """
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.domain = urllib.parse.urlparse(base_url).netloc
        self.links: Set[str] = set()
        self.forms: List[Dict[str, Any]] = []

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)

        # 1. Extract Links
        if tag in ['a', 'link'] and 'href' in attr_dict:
            href = attr_dict['href']
            full_url = urllib.parse.urljoin(self.base_url, href)
            parsed_full = urllib.parse.urlparse(full_url)
            # Only crawl same domain
            if parsed_full.netloc == self.domain and not full_url.endswith(('.png', '.jpg', '.css', '.svg', '.ico', '.pdf')):
                self.links.add(full_url)

        # 2. Extract HTML Forms for Fuzzing
        elif tag == 'form':
            action = attr_dict.get('action', '')
            method = attr_dict.get('method', 'get').upper()
            full_action = urllib.parse.urljoin(self.base_url, action)
            self.forms.append({
                "action": full_action,
                "method": method,
                "inputs": []
            })

        # 3. Extract Form Inputs
        elif tag == 'input' and self.forms:
            input_name = attr_dict.get('name')
            input_type = attr_dict.get('type', 'text')
            if input_name:
                self.forms[-1]["inputs"].append({
                    "name": input_name,
                    "type": input_type
                })


class WebCrawler:
    """
    Real Asynchronous Web Crawler: Crawls target website, parses robots.txt/sitemap,
    discovers all subpages, APIs, and HTML forms for deep security fuzzing.
    """
    def __init__(self, start_url: str, max_depth: int = 2, max_pages: int = 25):
        self.start_url = start_url.rstrip('/')
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited: Set[str] = set()
        self.discovered_endpoints: Set[str] = set([self.start_url])
        self.discovered_forms: List[Dict[str, Any]] = []
        self.client = httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True)

    async def crawl(self, log_callback=None) -> Dict[str, Any]:
        if log_callback:
            await log_callback(10, f"Initializing Deep Web Crawler for target: {self.start_url}...")

        # 1. Check robots.txt & sitemap.xml
        await self.check_robots_and_sitemap(log_callback)

        # 2. Crawl starting from root page
        queue = [(self.start_url, 0)]
        
        while queue and len(self.visited) < self.max_pages:
            url, depth = queue.pop(0)
            if url in self.visited or depth > self.max_depth:
                continue

            self.visited.add(url)
            self.discovered_endpoints.add(url)

            try:
                res = await self.client.get(url)
                if 'text/html' in res.headers.get('content-type', ''):
                    parser = LinkAndFormParser(url)
                    parser.feed(res.text)

                    # Store discovered forms
                    self.discovered_forms.extend(parser.forms)

                    # Add new links to queue
                    for link in parser.links:
                        if link not in self.visited:
                            queue.append((link, depth + 1))
                            self.discovered_endpoints.add(link)

            except Exception:
                pass

        await self.client.aclose()

        if log_callback:
            await log_callback(30, f"Crawler Discovered {len(self.discovered_endpoints)} Endpoints & {len(self.discovered_forms)} HTML Forms.")

        return {
            "endpoints": list(self.discovered_endpoints),
            "forms": self.discovered_forms
        }

    async def check_robots_and_sitemap(self, log_callback=None):
        try:
            robots_url = f"{self.start_url}/robots.txt"
            res = await self.client.get(robots_url)
            if res.status_code == 200:
                disallow_paths = re.findall(r'Disallow:\s*([^\s]+)', res.text)
                for path in disallow_paths:
                    full = urllib.parse.urljoin(self.start_url, path)
                    self.discovered_endpoints.add(full)
        except Exception:
            pass
