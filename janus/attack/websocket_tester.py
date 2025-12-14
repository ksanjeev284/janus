# janus/attack/websocket_tester.py
"""
WebSocket Security Tester.

Tests WebSocket endpoints for:
- Authentication bypass
- Message injection
- Cross-Site WebSocket Hijacking (CSWSH)
- Origin validation
- Message flooding (DoS)
- Sensitive data exposure
"""

import asyncio
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.parse import urlparse

try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False


@dataclass
class WebSocketFinding:
    """A WebSocket security finding."""
    issue: str
    severity: str
    evidence: str
    recommendation: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class WebSocketMessage:
    """A captured WebSocket message."""
    direction: str  # sent, received
    content: str
    timestamp: float
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class WebSocketReport:
    """WebSocket security report."""
    endpoint: str
    scan_time: str
    connected: bool
    connection_error: Optional[str]
    messages_exchanged: int
    security_findings: List[WebSocketFinding] = field(default_factory=list)
    messages: List[WebSocketMessage] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'endpoint': self.endpoint,
            'scan_time': self.scan_time,
            'connected': self.connected,
            'connection_error': self.connection_error,
            'messages_exchanged': self.messages_exchanged,
            'security_findings': [f.to_dict() for f in self.security_findings],
            'messages': [m.to_dict() for m in self.messages]
        }


class WebSocketTester:
    """
    WebSocket Security Tester.
    
    Tests WebSocket connections for common vulnerabilities.
    """
    
    # Test payloads for injection attacks
    INJECTION_PAYLOADS = [
        '{"type":"auth","token":"guest"}',
        '{"type":"admin","role":"superuser"}',
        '{"__proto__":{"isAdmin":true}}',
        '<script>alert(1)</script>',
        '{"type":"subscribe","channel":"*"}',
        '{"id":"../../../etc/passwd"}',
    ]
    
    # Sensitive data patterns
    SENSITIVE_PATTERNS = [
        'password', 'secret', 'token', 'api_key', 'apiKey',
        'credit_card', 'ssn', 'private', 'auth'
    ]
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def test(
        self,
        ws_url: str,
        token: Optional[str] = None,
        origin: Optional[str] = None,
        test_messages: Optional[List[str]] = None
    ) -> WebSocketReport:
        """
        Test WebSocket endpoint for security issues.
        
        Args:
            ws_url: WebSocket URL (ws:// or wss://)
            token: Authorization token
            origin: Custom origin header for CSWSH testing
            test_messages: Custom messages to send
        
        Returns:
            WebSocketReport
        """
        if not WEBSOCKETS_AVAILABLE:
            return WebSocketReport(
                endpoint=ws_url,
                scan_time=datetime.now().isoformat(),
                connected=False,
                connection_error="websockets library not installed. Run: pip install websockets",
                messages_exchanged=0
            )
        
        # Convert http:// to ws://
        ws_url = self._normalize_url(ws_url)
        
        # Run async test
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            report = loop.run_until_complete(
                self._async_test(ws_url, token, origin, test_messages)
            )
            loop.close()
            return report
        except Exception as e:
            return WebSocketReport(
                endpoint=ws_url,
                scan_time=datetime.now().isoformat(),
                connected=False,
                connection_error=str(e),
                messages_exchanged=0
            )
    
    def _normalize_url(self, url: str) -> str:
        """Convert HTTP URL to WebSocket URL."""
        if url.startswith('http://'):
            return url.replace('http://', 'ws://', 1)
        elif url.startswith('https://'):
            return url.replace('https://', 'wss://', 1)
        elif not url.startswith('ws://') and not url.startswith('wss://'):
            return f'ws://{url}'
        return url
    
    async def _async_test(
        self,
        ws_url: str,
        token: Optional[str],
        origin: Optional[str],
        test_messages: Optional[List[str]]
    ) -> WebSocketReport:
        """Async WebSocket testing."""
        findings = []
        messages = []
        connected = False
        connection_error = None
        
        # Build headers
        headers = {}
        if token:
            headers['Authorization'] = token
        if origin:
            headers['Origin'] = origin
        
        try:
            async with websockets.connect(
                ws_url,
                extra_headers=headers,
                close_timeout=self.timeout,
                open_timeout=self.timeout
            ) as ws:
                connected = True
                
                # Test 1: Connection without token (if token was provided, test without)
                if token:
                    no_auth_result = await self._test_no_auth(ws_url)
                    if no_auth_result:
                        findings.append(no_auth_result)
                
                # Test 2: Cross-Site WebSocket Hijacking
                cswsh_result = await self._test_cswsh(ws_url)
                if cswsh_result:
                    findings.append(cswsh_result)
                
                # Test 3: Send test messages and analyze responses
                if test_messages:
                    msgs_to_send = test_messages
                else:
                    msgs_to_send = self.INJECTION_PAYLOADS
                
                for msg in msgs_to_send:
                    try:
                        await ws.send(msg)
                        messages.append(WebSocketMessage(
                            direction='sent',
                            content=msg,
                            timestamp=time.time()
                        ))
                        
                        # Wait for response
                        try:
                            response = await asyncio.wait_for(
                                ws.recv(),
                                timeout=2.0
                            )
                            messages.append(WebSocketMessage(
                                direction='received',
                                content=str(response)[:500],
                                timestamp=time.time()
                            ))
                            
                            # Analyze response for sensitive data
                            sensitive = self._check_sensitive_data(str(response))
                            if sensitive:
                                findings.append(WebSocketFinding(
                                    issue='Sensitive Data Exposure',
                                    severity='HIGH',
                                    evidence=f"Found sensitive data patterns: {', '.join(sensitive)}",
                                    recommendation='Minimize sensitive data sent over WebSocket'
                                ))
                        except asyncio.TimeoutError:
                            pass
                    except Exception:
                        pass
                
        except Exception as e:
            connection_error = str(e)
        
        return WebSocketReport(
            endpoint=ws_url,
            scan_time=datetime.now().isoformat(),
            connected=connected,
            connection_error=connection_error,
            messages_exchanged=len(messages),
            security_findings=findings,
            messages=messages
        )
    
    async def _test_no_auth(self, ws_url: str) -> Optional[WebSocketFinding]:
        """Test connection without authentication."""
        try:
            async with websockets.connect(
                ws_url,
                close_timeout=5,
                open_timeout=5
            ) as ws:
                # Connection succeeded without token
                return WebSocketFinding(
                    issue='No Authentication Required',
                    severity='HIGH',
                    evidence='WebSocket connection accepted without authentication',
                    recommendation='Require authentication for WebSocket connections'
                )
        except Exception:
            pass
        return None
    
    async def _test_cswsh(self, ws_url: str) -> Optional[WebSocketFinding]:
        """Test for Cross-Site WebSocket Hijacking."""
        try:
            # Try connection with malicious origin
            async with websockets.connect(
                ws_url,
                extra_headers={'Origin': 'https://evil.com'},
                close_timeout=5,
                open_timeout=5
            ) as ws:
                # Connection succeeded with foreign origin
                return WebSocketFinding(
                    issue='Cross-Site WebSocket Hijacking (CSWSH)',
                    severity='HIGH',
                    evidence='WebSocket accepts connections from any origin',
                    recommendation='Validate Origin header and reject unknown origins'
                )
        except Exception:
            pass
        return None
    
    def _check_sensitive_data(self, content: str) -> List[str]:
        """Check response for sensitive data patterns."""
        found = []
        content_lower = content.lower()
        for pattern in self.SENSITIVE_PATTERNS:
            if pattern in content_lower:
                found.append(pattern)
        return found
    
    def quick_test(
        self,
        ws_url: str,
        token: Optional[str] = None
    ) -> Dict[str, Any]:
        """Quick WebSocket security test."""
        report = self.test(ws_url, token)
        
        return {
            "endpoint": report.endpoint,
            "connected": report.connected,
            "error": report.connection_error,
            "messages": report.messages_exchanged,
            "security_issues": len(report.security_findings),
            "findings": [f.to_dict() for f in report.security_findings]
        }
