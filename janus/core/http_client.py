# janus/core/http_client.py
"""
Centralized HTTP Client for Janus.

Provides a unified interface for all HTTP requests with support for:
- Proxy servers (HTTP, SOCKS4, SOCKS5)
- Custom headers
- Rate limiting
- SSL verification control
- Request/Response logging
- Retry logic
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Dict, Any, Optional, Tuple, List, Callable
from dataclasses import dataclass, field
from datetime import datetime
import time
import json
import urllib3

# Suppress SSL warnings when verification is disabled
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class ProxyConfig:
    """Configuration for proxy servers."""
    enabled: bool = False
    http_proxy: str = ""      # http://user:pass@host:port
    https_proxy: str = ""     # https://user:pass@host:port
    socks_proxy: str = ""     # socks5://user:pass@host:port
    no_proxy: List[str] = field(default_factory=list)  # Bypass list
    
    def get_proxies(self) -> Optional[Dict[str, str]]:
        """Get requests-compatible proxy dict."""
        if not self.enabled:
            return None
        
        proxies = {}
        if self.http_proxy:
            proxies['http'] = self.http_proxy
        if self.https_proxy:
            proxies['https'] = self.https_proxy
        elif self.socks_proxy:
            # SOCKS proxy for both HTTP and HTTPS
            proxies['http'] = self.socks_proxy
            proxies['https'] = self.socks_proxy
        
        return proxies if proxies else None


@dataclass 
class RequestConfig:
    """Configuration for HTTP requests."""
    timeout: int = 30
    verify_ssl: bool = True
    follow_redirects: bool = True
    max_retries: int = 3
    retry_backoff: float = 0.5
    rate_limit_delay: float = 0.0  # Seconds between requests
    user_agent: str = "Janus-Security-Scanner/2.0"


@dataclass
class RequestLog:
    """Log entry for a single request."""
    timestamp: str
    method: str
    url: str
    status_code: int
    response_time_ms: float
    error: Optional[str] = None


class JanusHTTPClient:
    """
    Unified HTTP client for Janus security scanner.
    
    Features:
    - Proxy support (HTTP, HTTPS, SOCKS5)
    - Custom headers per-request or global
    - Rate limiting
    - Automatic retries with exponential backoff
    - Request logging
    - SSL verification control
    
    Usage:
        client = JanusHTTPClient()
        client.set_proxy("http://proxy.example.com:8080")
        client.add_global_header("X-Custom-Header", "value")
        
        status, body, raw = client.request("GET", "https://api.example.com/endpoint",
                                           token="Bearer xyz",
                                           headers={"X-Extra": "header"})
    """
    
    def __init__(
        self,
        proxy_config: Optional[ProxyConfig] = None,
        request_config: Optional[RequestConfig] = None
    ):
        self.proxy_config = proxy_config or ProxyConfig()
        self.request_config = request_config or RequestConfig()
        self.global_headers: Dict[str, str] = {}
        self.request_log: List[RequestLog] = []
        self.session = self._create_session()
        self._last_request_time = 0.0
    
    def _create_session(self) -> requests.Session:
        """Create a requests session with retry logic."""
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=self.request_config.max_retries,
            backoff_factor=self.request_config.retry_backoff,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE", "PATCH"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    # =========================================================================
    # Configuration Methods
    # =========================================================================
    
    def set_proxy(self, proxy_url: str, proxy_type: str = "http") -> None:
        """
        Set a proxy server.
        
        Args:
            proxy_url: Full proxy URL (e.g., "http://user:pass@host:port")
            proxy_type: "http", "https", or "socks5"
        """
        self.proxy_config.enabled = True
        
        if proxy_type == "http":
            self.proxy_config.http_proxy = proxy_url
        elif proxy_type == "https":
            self.proxy_config.https_proxy = proxy_url
        elif proxy_type in ("socks5", "socks"):
            self.proxy_config.socks_proxy = proxy_url
        
        print(f"[*] Proxy configured: {proxy_type}://{proxy_url.split('@')[-1] if '@' in proxy_url else proxy_url}")
    
    def set_tor_proxy(self, port: int = 9050) -> None:
        """Configure Tor SOCKS proxy."""
        self.set_proxy(f"socks5h://127.0.0.1:{port}", "socks5")
        print("[*] Tor proxy configured")
    
    def disable_proxy(self) -> None:
        """Disable proxy."""
        self.proxy_config.enabled = False
        print("[*] Proxy disabled")
    
    def add_global_header(self, name: str, value: str) -> None:
        """Add a header that will be included in all requests."""
        self.global_headers[name] = value
    
    def remove_global_header(self, name: str) -> None:
        """Remove a global header."""
        if name in self.global_headers:
            del self.global_headers[name]
    
    def set_global_headers(self, headers: Dict[str, str]) -> None:
        """Set multiple global headers at once."""
        self.global_headers.update(headers)
    
    def clear_global_headers(self) -> None:
        """Clear all global headers."""
        self.global_headers.clear()
    
    def set_timeout(self, timeout: int) -> None:
        """Set request timeout in seconds."""
        self.request_config.timeout = timeout
    
    def set_ssl_verify(self, verify: bool) -> None:
        """Enable/disable SSL certificate verification."""
        self.request_config.verify_ssl = verify
        if not verify:
            print("[!] SSL verification disabled - not recommended for production")
    
    def set_rate_limit(self, delay: float) -> None:
        """Set minimum delay between requests in seconds."""
        self.request_config.rate_limit_delay = delay
    
    def set_user_agent(self, user_agent: str) -> None:
        """Set the User-Agent header."""
        self.request_config.user_agent = user_agent
    
    # =========================================================================
    # Request Methods
    # =========================================================================
    
    def request(
        self,
        method: str,
        url: str,
        token: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[Dict] = None,
        params: Optional[Dict] = None,
        **kwargs
    ) -> Tuple[int, Any, str]:
        """
        Make an HTTP request.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            url: Target URL
            token: Authorization token (auto-formatted with Bearer if needed)
            headers: Additional headers for this request only
            body: JSON body for POST/PUT/PATCH
            params: Query parameters
            **kwargs: Additional arguments to pass to requests
        
        Returns:
            Tuple of (status_code, parsed_body, raw_text)
        """
        # Rate limiting
        if self.request_config.rate_limit_delay > 0:
            elapsed = time.time() - self._last_request_time
            if elapsed < self.request_config.rate_limit_delay:
                time.sleep(self.request_config.rate_limit_delay - elapsed)
        
        # Build headers
        request_headers = {
            "User-Agent": self.request_config.user_agent,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        
        # Add global headers
        request_headers.update(self.global_headers)
        
        # Add request-specific headers
        if headers:
            request_headers.update(headers)
        
        # Add authorization
        if token:
            if token.lower().startswith("bearer ") or token.lower().startswith("basic "):
                request_headers["Authorization"] = token
            else:
                request_headers["Authorization"] = token
        
        # Get proxy config
        proxies = self.proxy_config.get_proxies()
        
        # Make the request
        start_time = time.time()
        error_msg = None
        status_code = 0
        response_body = {}
        raw_text = ""
        
        try:
            response = self.session.request(
                method=method.upper(),
                url=url,
                headers=request_headers,
                json=body if body else None,
                params=params,
                proxies=proxies,
                timeout=self.request_config.timeout,
                verify=self.request_config.verify_ssl,
                allow_redirects=self.request_config.follow_redirects,
                **kwargs
            )
            
            status_code = response.status_code
            raw_text = response.text
            
            # Parse JSON if possible
            try:
                response_body = response.json()
            except json.JSONDecodeError:
                response_body = {"_raw": raw_text[:1000]}
                
        except requests.exceptions.ProxyError as e:
            error_msg = f"Proxy error: {str(e)}"
            response_body = {"_error": error_msg}
        except requests.exceptions.SSLError as e:
            error_msg = f"SSL error: {str(e)}"
            response_body = {"_error": error_msg}
        except requests.exceptions.Timeout as e:
            error_msg = f"Timeout: {str(e)}"
            response_body = {"_error": error_msg}
        except requests.exceptions.ConnectionError as e:
            error_msg = f"Connection error: {str(e)}"
            response_body = {"_error": error_msg}
        except Exception as e:
            error_msg = f"Request failed: {str(e)}"
            response_body = {"_error": error_msg}
        
        # Log the request
        response_time = (time.time() - start_time) * 1000
        self._last_request_time = time.time()
        
        self.request_log.append(RequestLog(
            timestamp=datetime.now().isoformat(),
            method=method.upper(),
            url=url,
            status_code=status_code,
            response_time_ms=response_time,
            error=error_msg
        ))
        
        return status_code, response_body, raw_text
    
    def get(self, url: str, **kwargs) -> Tuple[int, Any, str]:
        """Make a GET request."""
        return self.request("GET", url, **kwargs)
    
    def post(self, url: str, body: Dict = None, **kwargs) -> Tuple[int, Any, str]:
        """Make a POST request."""
        return self.request("POST", url, body=body, **kwargs)
    
    def put(self, url: str, body: Dict = None, **kwargs) -> Tuple[int, Any, str]:
        """Make a PUT request."""
        return self.request("PUT", url, body=body, **kwargs)
    
    def delete(self, url: str, **kwargs) -> Tuple[int, Any, str]:
        """Make a DELETE request."""
        return self.request("DELETE", url, **kwargs)
    
    def patch(self, url: str, body: Dict = None, **kwargs) -> Tuple[int, Any, str]:
        """Make a PATCH request."""
        return self.request("PATCH", url, body=body, **kwargs)
    
    # =========================================================================
    # Utility Methods
    # =========================================================================
    
    def get_request_log(self, limit: int = 100) -> List[Dict]:
        """Get recent request logs."""
        return [
            {
                "timestamp": log.timestamp,
                "method": log.method,
                "url": log.url,
                "status": log.status_code,
                "time_ms": round(log.response_time_ms, 2),
                "error": log.error
            }
            for log in self.request_log[-limit:]
        ]
    
    def clear_log(self) -> None:
        """Clear request log."""
        self.request_log.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get request statistics."""
        if not self.request_log:
            return {"total_requests": 0}
        
        total = len(self.request_log)
        errors = len([l for l in self.request_log if l.error])
        times = [l.response_time_ms for l in self.request_log if not l.error]
        
        return {
            "total_requests": total,
            "successful": total - errors,
            "errors": errors,
            "avg_response_ms": sum(times) / len(times) if times else 0,
            "min_response_ms": min(times) if times else 0,
            "max_response_ms": max(times) if times else 0,
        }
    
    def test_connection(self, url: str = "https://httpbin.org/ip") -> bool:
        """Test if requests can be made (optionally through proxy)."""
        try:
            status, body, _ = self.get(url)
            return status == 200
        except:
            return False


# Global default client instance
_default_client: Optional[JanusHTTPClient] = None


def get_default_client() -> JanusHTTPClient:
    """Get or create the default HTTP client."""
    global _default_client
    if _default_client is None:
        _default_client = JanusHTTPClient()
    return _default_client


def configure_global_proxy(proxy_url: str, proxy_type: str = "http") -> None:
    """Configure proxy for the default client."""
    get_default_client().set_proxy(proxy_url, proxy_type)


def configure_global_headers(headers: Dict[str, str]) -> None:
    """Set global headers for the default client."""
    get_default_client().set_global_headers(headers)
