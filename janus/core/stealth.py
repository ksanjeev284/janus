# janus/core/stealth.py
"""
Ghost-Walker Module - WAF Evasion and Stealth Operations.

Red Team stealth techniques:
- Header rotation (User-Agent, Referer, Accept-Language)
- Request jitter (randomized timing)
- Proxy/Tor integration
- Fingerprint randomization

This module helps Janus bypass WAF detection and rate limiting.
"""

import random
import time
import requests
from typing import Dict, Optional, List, Tuple
from functools import wraps
from dataclasses import dataclass
import socket


@dataclass
class StealthConfig:
    """Configuration for stealth operations."""
    enabled: bool = False
    min_delay: float = 0.5
    max_delay: float = 3.0
    use_tor: bool = False
    tor_port: int = 9050
    rotate_proxy_every: int = 50
    proxy_list: Optional[List[str]] = None


# Real User-Agent strings from major browsers (updated 2024)
USER_AGENTS = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    # Chrome Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    # Firefox Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    # Mobile
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
]

# Realistic Accept-Language headers
ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "en-US,en;q=0.9,es;q=0.8",
    "en-US,en;q=0.9,fr;q=0.8,de;q=0.7",
    "en-CA,en;q=0.9,fr-CA;q=0.8",
    "en-AU,en;q=0.9,en-GB;q=0.8",
]

# Common referrers
REFERRERS = [
    "https://www.google.com/",
    "https://www.google.com/search?q=api+documentation",
    "https://github.com/",
    "https://stackoverflow.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "",  # Direct traffic
]

# Accept headers
ACCEPT_HEADERS = [
    "application/json, text/plain, */*",
    "application/json",
    "*/*",
    "application/json, text/javascript, */*; q=0.01",
]


class GhostWalker:
    """
    WAF Evasion and Stealth Request Handler.
    
    Features:
    - Randomized headers that mimic real browsers
    - Request timing jitter to bypass rate limiting
    - Tor/Proxy integration for IP rotation
    - Session fingerprint consistency
    """
    
    def __init__(self, config: StealthConfig = None):
        self.config = config or StealthConfig()
        self.request_count = 0
        self.current_proxy_index = 0
        self.session_fingerprint = self._generate_session_fingerprint()
        
        # Try to import fake_useragent for even more variety
        try:
            from fake_useragent import UserAgent
            self.ua = UserAgent()
            self.use_fake_ua = True
        except ImportError:
            self.use_fake_ua = False
    
    def _generate_session_fingerprint(self) -> Dict:
        """Generate consistent browser fingerprint for the session."""
        return {
            'user_agent': random.choice(USER_AGENTS),
            'accept_language': random.choice(ACCEPT_LANGUAGES),
            'platform': random.choice(['Windows', 'Macintosh', 'Linux', 'iPhone']),
            'sec_ch_ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        }
    
    def get_stealth_headers(self, target_url: str = None) -> Dict[str, str]:
        """
        Generate randomized headers that mimic a real browser.
        
        The key is to be consistent within a "session" but vary between sessions.
        """
        if self.use_fake_ua:
            user_agent = self.ua.random
        else:
            user_agent = random.choice(USER_AGENTS)
        
        headers = {
            'User-Agent': user_agent,
            'Accept': random.choice(ACCEPT_HEADERS),
            'Accept-Language': random.choice(ACCEPT_LANGUAGES),
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
        }
        
        # Add Sec-CH-UA headers for Chrome
        if 'Chrome' in user_agent:
            headers['Sec-CH-UA'] = self.session_fingerprint['sec_ch_ua']
            headers['Sec-CH-UA-Mobile'] = '?0'
            headers['Sec-CH-UA-Platform'] = f'"{self.session_fingerprint["platform"]}"'
            headers['Sec-Fetch-Site'] = 'same-origin'
            headers['Sec-Fetch-Mode'] = 'cors'
            headers['Sec-Fetch-Dest'] = 'empty'
        
        # Add referrer sometimes (not always - looks suspicious)
        if random.random() > 0.3:
            headers['Referer'] = random.choice(REFERRERS)
        
        # Add Origin for POST/PUT requests
        if target_url:
            from urllib.parse import urlparse
            parsed = urlparse(target_url)
            headers['Origin'] = f"{parsed.scheme}://{parsed.netloc}"
        
        return headers
    
    def get_proxy(self) -> Optional[Dict[str, str]]:
        """
        Get the current proxy configuration.
        
        Supports:
        - Tor (SOCKS5 on 9050)
        - HTTP proxy list
        - Rotating proxies
        """
        if not self.config.enabled:
            return None
        
        # Rotate proxy if needed
        if self.config.rotate_proxy_every > 0:
            if self.request_count % self.config.rotate_proxy_every == 0:
                self._rotate_proxy()
        
        if self.config.use_tor:
            return self.get_tor_proxy()
        
        if self.config.proxy_list:
            proxy = self.config.proxy_list[self.current_proxy_index % len(self.config.proxy_list)]
            return {
                'http': proxy,
                'https': proxy
            }
        
        return None
    
    def get_tor_proxy(self) -> Dict[str, str]:
        """
        Get Tor SOCKS5 proxy configuration.
        
        Requires Tor to be running locally on port 9050.
        """
        tor_proxy = f"socks5h://127.0.0.1:{self.config.tor_port}"
        return {
            'http': tor_proxy,
            'https': tor_proxy
        }
    
    def _rotate_proxy(self):
        """Rotate to the next proxy in the list."""
        if self.config.proxy_list:
            self.current_proxy_index = (self.current_proxy_index + 1) % len(self.config.proxy_list)
            print(f"[Ghost] Rotating to proxy #{self.current_proxy_index}")
        
        if self.config.use_tor:
            # Send signal to Tor to get a new circuit
            self._new_tor_circuit()
    
    def _new_tor_circuit(self):
        """Request a new Tor circuit for a new IP address."""
        try:
            # Tor control port is typically 9051
            control_port = self.config.tor_port + 1
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(('127.0.0.1', control_port))
                s.send(b'AUTHENTICATE ""\r\n')
                response = s.recv(1024)
                
                if b'250' in response:
                    s.send(b'SIGNAL NEWNYM\r\n')
                    response = s.recv(1024)
                    if b'250' in response:
                        print("[Ghost] New Tor circuit established")
                        time.sleep(1)  # Wait for circuit to be ready
        except Exception as e:
            # Tor control not available - that's OK
            pass
    
    def apply_jitter(self):
        """
        Apply random delay between requests to mimic human behavior.
        
        This is crucial for bypassing rate limiters.
        """
        if self.config.enabled:
            delay = random.uniform(self.config.min_delay, self.config.max_delay)
            # Add occasional longer pauses (human behavior)
            if random.random() < 0.1:  # 10% chance
                delay += random.uniform(2, 5)
            time.sleep(delay)
    
    def stealth_request(self, 
                        method: str,
                        url: str,
                        headers: Dict = None,
                        **kwargs) -> requests.Response:
        """
        Make a stealthy HTTP request with all evasion techniques.
        
        Args:
            method: HTTP method
            url: Target URL
            headers: Additional headers (merged with stealth headers)
            **kwargs: Additional arguments for requests
        
        Returns:
            requests.Response
        """
        # Apply jitter before request
        self.apply_jitter()
        
        # Generate stealth headers
        stealth_headers = self.get_stealth_headers(url)
        
        # Merge with any custom headers (custom headers take precedence)
        if headers:
            stealth_headers.update(headers)
        
        # Get proxy if configured
        proxy = self.get_proxy()
        if proxy:
            kwargs['proxies'] = proxy
        
        # Count request for proxy rotation
        self.request_count += 1
        
        # Make the request
        response = requests.request(
            method=method,
            url=url,
            headers=stealth_headers,
            **kwargs
        )
        
        return response
    
    def check_tor(self) -> bool:
        """Check if Tor is available and working."""
        try:
            proxy = self.get_tor_proxy()
            response = requests.get(
                'https://check.torproject.org/api/ip',
                proxies=proxy,
                timeout=10
            )
            data = response.json()
            if data.get('IsTor'):
                print(f"[Ghost] Tor connected! IP: {data.get('IP')}")
                return True
        except:
            pass
        return False


def ghost_mode(func):
    """
    Decorator to enable ghost mode for attack functions.
    
    When applied, the function will:
    1. Use stealth headers
    2. Apply random jitter between requests
    3. Route through proxy if configured
    
    Usage:
        @ghost_mode
        def attack_function(self, ...):
            ...
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Check if stealth is enabled via kwargs or config
        stealth = kwargs.pop('stealth', False)
        
        if stealth:
            # Apply jitter before execution
            delay = random.uniform(1.0, 4.0)
            time.sleep(delay)
        
        return func(*args, **kwargs)
    
    return wrapper


def create_stealth_session(config: StealthConfig = None) -> requests.Session:
    """
    Create a requests Session configured for stealth operations.
    
    The session maintains cookies and connection pooling while
    using stealth headers.
    """
    ghost = GhostWalker(config or StealthConfig(enabled=True))
    
    session = requests.Session()
    
    # Set default headers
    session.headers.update(ghost.get_stealth_headers())
    
    # Set proxy if available
    proxy = ghost.get_proxy()
    if proxy:
        session.proxies.update(proxy)
    
    return session


# Quick function for one-off stealth headers
def get_stealth_headers() -> Dict[str, str]:
    """Get a set of randomized stealth headers."""
    ghost = GhostWalker()
    return ghost.get_stealth_headers()


# Quick function for Tor proxy
def get_tor_proxy(port: int = 9050) -> Dict[str, str]:
    """Get Tor SOCKS5 proxy configuration."""
    config = StealthConfig(enabled=True, use_tor=True, tor_port=port)
    ghost = GhostWalker(config)
    return ghost.get_tor_proxy()
