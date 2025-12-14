# janus/attack/rate_limit_tester.py
"""
API Rate Limiting Tester.

Tests if rate limiting is properly implemented on API endpoints.
Useful for identifying endpoints vulnerable to brute force attacks.
"""

import requests
import time
import threading
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


@dataclass
class RateLimitResult:
    """Result of rate limit testing."""
    endpoint: str
    method: str
    requests_sent: int
    successful_requests: int
    blocked_requests: int
    rate_limit_detected: bool
    limit_threshold: Optional[int]
    time_window: Optional[float]
    severity: str
    evidence: str
    recommendation: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


class RateLimitTester:
    """
    API Rate Limiting Tester.
    
    Tests endpoints for proper rate limiting by:
    - Sending rapid requests to detect limits
    - Analyzing response headers for rate limit info
    - Checking for 429 Too Many Requests responses
    """
    
    # Common rate limit headers
    RATE_LIMIT_HEADERS = [
        'X-RateLimit-Limit',
        'X-RateLimit-Remaining',
        'X-RateLimit-Reset',
        'X-Rate-Limit-Limit',
        'X-Rate-Limit-Remaining',
        'RateLimit-Limit',
        'RateLimit-Remaining',
        'RateLimit-Reset',
        'Retry-After',
    ]
    
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
    
    def test_endpoint(
        self,
        endpoint: str,
        method: str = "GET",
        token: Optional[str] = None,
        body: Optional[Dict] = None,
        num_requests: int = 50,
        delay: float = 0.0,
        concurrent: bool = True
    ) -> RateLimitResult:
        """
        Test an endpoint for rate limiting.
        
        Args:
            endpoint: Target endpoint URL
            method: HTTP method
            token: Optional authorization token
            body: Request body for POST/PUT
            num_requests: Number of requests to send
            delay: Delay between requests (seconds)
            concurrent: Whether to send requests concurrently
        
        Returns:
            RateLimitResult with analysis
        """
        headers = {'Authorization': token} if token else {}
        
        results = []
        rate_limit_info = {}
        
        if concurrent:
            results = self._send_concurrent(endpoint, method, headers, body, num_requests)
        else:
            results = self._send_sequential(endpoint, method, headers, body, num_requests, delay)
        
        # Analyze results
        successful = sum(1 for r in results if r.get('status') in [200, 201, 204])
        blocked = sum(1 for r in results if r.get('status') == 429)
        other = sum(1 for r in results if r.get('status') not in [200, 201, 204, 429])
        
        # Check for rate limit headers
        for result in results:
            for header in self.RATE_LIMIT_HEADERS:
                if header in result.get('headers', {}):
                    rate_limit_info[header] = result['headers'][header]
        
        # Determine if rate limiting is in place
        rate_limit_detected = blocked > 0 or len(rate_limit_info) > 0
        
        # Estimate threshold
        limit_threshold = None
        if blocked > 0:
            # Find where blocking started
            for i, r in enumerate(results):
                if r.get('status') == 429:
                    limit_threshold = i
                    break
        
        # Parse rate limit from headers
        if 'X-RateLimit-Limit' in rate_limit_info:
            try:
                limit_threshold = int(rate_limit_info['X-RateLimit-Limit'])
            except:
                pass
        
        # Determine severity and recommendation
        if not rate_limit_detected:
            severity = 'HIGH'
            evidence = f"No rate limiting detected after {num_requests} requests. All {successful} requests succeeded."
            recommendation = "Implement rate limiting using a token bucket or sliding window algorithm. Recommended: 100 requests per minute for most APIs."
        elif blocked > 0:
            severity = 'INFO'
            evidence = f"Rate limiting active: {successful} allowed, {blocked} blocked (429). Limit detected around {limit_threshold} requests."
            recommendation = "Rate limiting is properly configured."
        else:
            severity = 'LOW'
            evidence = f"Rate limit headers present but no blocking observed: {rate_limit_info}"
            recommendation = "Verify rate limits are enforced, not just tracked."
        
        return RateLimitResult(
            endpoint=endpoint,
            method=method,
            requests_sent=num_requests,
            successful_requests=successful,
            blocked_requests=blocked,
            rate_limit_detected=rate_limit_detected,
            limit_threshold=limit_threshold,
            time_window=None,  # Would need multiple tests to determine
            severity=severity,
            evidence=evidence,
            recommendation=recommendation
        )
    
    def _send_concurrent(
        self,
        endpoint: str,
        method: str,
        headers: Dict,
        body: Optional[Dict],
        num_requests: int
    ) -> List[Dict]:
        """Send requests concurrently using thread pool."""
        results = []
        
        def make_request(i):
            try:
                if method.upper() == "GET":
                    resp = requests.get(endpoint, headers=headers, timeout=self.timeout)
                elif method.upper() == "POST":
                    resp = requests.post(endpoint, json=body, headers=headers, timeout=self.timeout)
                else:
                    resp = requests.request(method, endpoint, json=body, headers=headers, timeout=self.timeout)
                
                return {
                    'index': i,
                    'status': resp.status_code,
                    'headers': dict(resp.headers),
                    'time': resp.elapsed.total_seconds()
                }
            except Exception as e:
                return {
                    'index': i,
                    'status': 0,
                    'error': str(e)
                }
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request, i) for i in range(num_requests)]
            for future in as_completed(futures):
                results.append(future.result())
        
        # Sort by index to maintain order
        results.sort(key=lambda x: x.get('index', 0))
        return results
    
    def _send_sequential(
        self,
        endpoint: str,
        method: str,
        headers: Dict,
        body: Optional[Dict],
        num_requests: int,
        delay: float
    ) -> List[Dict]:
        """Send requests sequentially with optional delay."""
        results = []
        
        for i in range(num_requests):
            try:
                if method.upper() == "GET":
                    resp = requests.get(endpoint, headers=headers, timeout=self.timeout)
                elif method.upper() == "POST":
                    resp = requests.post(endpoint, json=body, headers=headers, timeout=self.timeout)
                else:
                    resp = requests.request(method, endpoint, json=body, headers=headers, timeout=self.timeout)
                
                results.append({
                    'index': i,
                    'status': resp.status_code,
                    'headers': dict(resp.headers),
                    'time': resp.elapsed.total_seconds()
                })
                
                # Check if we've been blocked
                if resp.status_code == 429:
                    # Try to get retry-after
                    retry = resp.headers.get('Retry-After')
                    results[-1]['retry_after'] = retry
                
                if delay > 0:
                    time.sleep(delay)
                    
            except Exception as e:
                results.append({
                    'index': i,
                    'status': 0,
                    'error': str(e)
                })
        
        return results
    
    def test_brute_force_protection(
        self,
        login_endpoint: str,
        username_param: str = "username",
        password_param: str = "password",
        test_username: str = "admin",
        num_attempts: int = 20
    ) -> RateLimitResult:
        """
        Test login endpoint for brute force protection.
        
        Args:
            login_endpoint: Login endpoint URL
            username_param: Username field name
            password_param: Password field name
            test_username: Username to test with
            num_attempts: Number of failed login attempts
        
        Returns:
            RateLimitResult for brute force testing
        """
        results = []
        
        for i in range(num_attempts):
            body = {
                username_param: test_username,
                password_param: f"wrong_password_{i}"
            }
            
            try:
                resp = requests.post(
                    login_endpoint,
                    json=body,
                    timeout=self.timeout
                )
                
                results.append({
                    'index': i,
                    'status': resp.status_code,
                    'headers': dict(resp.headers)
                })
                
                # If blocked, record it
                if resp.status_code == 429:
                    break
                    
            except Exception as e:
                results.append({'index': i, 'status': 0, 'error': str(e)})
        
        blocked = sum(1 for r in results if r.get('status') == 429)
        total = len(results)
        
        if blocked > 0:
            severity = 'INFO'
            evidence = f"Brute force protection active: blocked after {total} attempts"
            recommendation = "Account lockout is properly configured."
        else:
            severity = 'CRITICAL'
            evidence = f"No brute force protection: {total} failed login attempts allowed without blocking"
            recommendation = "Implement account lockout or progressive delays after failed attempts. Consider CAPTCHA after 3-5 failures."
        
        return RateLimitResult(
            endpoint=login_endpoint,
            method="POST",
            requests_sent=total,
            successful_requests=0,
            blocked_requests=blocked,
            rate_limit_detected=blocked > 0,
            limit_threshold=total if blocked == 0 else total - 1,
            time_window=None,
            severity=severity,
            evidence=evidence,
            recommendation=recommendation
        )
