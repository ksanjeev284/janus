# janus/core/notifications.py
"""
Webhook Notification System for Janus.

Sends real-time alerts for security findings via:
- Discord webhooks
- Slack webhooks
- Generic HTTP webhooks
- Email (SMTP)
"""

import requests
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Callable
from datetime import datetime
from abc import ABC, abstractmethod


@dataclass
class NotificationConfig:
    """Configuration for notifications."""
    enabled: bool = True
    min_severity: str = "HIGH"  # Only notify on HIGH and CRITICAL
    severity_order: List[str] = field(default_factory=lambda: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    
    def should_notify(self, severity: str) -> bool:
        """Check if severity level warrants notification."""
        if not self.enabled:
            return False
        try:
            return self.severity_order.index(severity) >= self.severity_order.index(self.min_severity)
        except ValueError:
            return True  # Default to notify for unknown severity


class NotificationChannel(ABC):
    """Abstract base class for notification channels."""
    
    @abstractmethod
    def send(self, finding: Dict[str, Any]) -> bool:
        """Send a notification. Returns True on success."""
        pass
    
    @abstractmethod
    def test_connection(self) -> bool:
        """Test if the notification channel is properly configured."""
        pass


class DiscordWebhook(NotificationChannel):
    """Discord webhook notification channel."""
    
    def __init__(self, webhook_url: str, username: str = "Janus Security"):
        self.webhook_url = webhook_url
        self.username = username
    
    def _get_color(self, severity: str) -> int:
        """Get Discord embed color for severity level."""
        colors = {
            "CRITICAL": 0xFF0000,  # Red
            "HIGH": 0xFF8800,      # Orange
            "MEDIUM": 0xFFFF00,    # Yellow
            "LOW": 0x00FF00,       # Green
            "INFO": 0x0088FF       # Blue
        }
        return colors.get(severity, 0x808080)
    
    def send(self, finding: Dict[str, Any]) -> bool:
        """Send finding to Discord."""
        try:
            severity = finding.get('severity', 'INFO')
            
            embed = {
                "title": f"🚨 {finding.get('vulnerability_type', 'Security Finding')}",
                "description": finding.get('evidence', 'No description available'),
                "color": self._get_color(severity),
                "fields": [
                    {"name": "Endpoint", "value": f"`{finding.get('endpoint', 'N/A')}`", "inline": True},
                    {"name": "Severity", "value": severity, "inline": True},
                    {"name": "Confidence", "value": f"{finding.get('confidence', 0):.0%}", "inline": True},
                ],
                "footer": {"text": "Janus Security Scanner"},
                "timestamp": datetime.now().isoformat()
            }
            
            if finding.get('recommendation'):
                embed["fields"].append({
                    "name": "Recommendation",
                    "value": finding.get('recommendation')[:1024],
                    "inline": False
                })
            
            payload = {
                "username": self.username,
                "embeds": [embed]
            }
            
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )
            return response.status_code == 204
            
        except Exception as e:
            print(f"Discord notification failed: {e}")
            return False
    
    def test_connection(self) -> bool:
        """Test Discord webhook connection."""
        try:
            response = requests.post(
                self.webhook_url,
                json={
                    "username": self.username,
                    "content": "🔱 Janus notification test - connection successful!"
                },
                timeout=10
            )
            return response.status_code == 204
        except:
            return False


class SlackWebhook(NotificationChannel):
    """Slack webhook notification channel."""
    
    def __init__(self, webhook_url: str, channel: str = "#security"):
        self.webhook_url = webhook_url
        self.channel = channel
    
    def _get_color(self, severity: str) -> str:
        """Get Slack attachment color for severity."""
        colors = {
            "CRITICAL": "#FF0000",
            "HIGH": "#FF8800",
            "MEDIUM": "#FFFF00",
            "LOW": "#00FF00",
            "INFO": "#0088FF"
        }
        return colors.get(severity, "#808080")
    
    def send(self, finding: Dict[str, Any]) -> bool:
        """Send finding to Slack."""
        try:
            severity = finding.get('severity', 'INFO')
            
            attachment = {
                "color": self._get_color(severity),
                "title": f"🚨 {finding.get('vulnerability_type', 'Security Finding')}",
                "text": finding.get('evidence', 'No description'),
                "fields": [
                    {"title": "Endpoint", "value": finding.get('endpoint', 'N/A'), "short": True},
                    {"title": "Severity", "value": severity, "short": True},
                    {"title": "Confidence", "value": f"{finding.get('confidence', 0):.0%}", "short": True},
                    {"title": "Status", "value": finding.get('status', 'N/A'), "short": True},
                ],
                "footer": "Janus Security Scanner",
                "ts": int(datetime.now().timestamp())
            }
            
            if finding.get('recommendation'):
                attachment["fields"].append({
                    "title": "Recommendation",
                    "value": finding.get('recommendation')[:500],
                    "short": False
                })
            
            payload = {
                "channel": self.channel,
                "attachments": [attachment]
            }
            
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )
            return response.status_code == 200
            
        except Exception as e:
            print(f"Slack notification failed: {e}")
            return False
    
    def test_connection(self) -> bool:
        """Test Slack webhook."""
        try:
            response = requests.post(
                self.webhook_url,
                json={"text": "🔱 Janus notification test - connection successful!"},
                timeout=10
            )
            return response.status_code == 200
        except:
            return False


class GenericWebhook(NotificationChannel):
    """Generic HTTP webhook notification channel."""
    
    def __init__(
        self, 
        webhook_url: str, 
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
        template: Optional[Callable[[Dict], Dict]] = None
    ):
        self.webhook_url = webhook_url
        self.method = method.upper()
        self.headers = headers or {"Content-Type": "application/json"}
        self.template = template or (lambda x: x)  # Identity by default
    
    def send(self, finding: Dict[str, Any]) -> bool:
        """Send finding to generic webhook."""
        try:
            payload = self.template(finding)
            
            if self.method == "POST":
                response = requests.post(
                    self.webhook_url,
                    json=payload,
                    headers=self.headers,
                    timeout=10
                )
            else:
                response = requests.request(
                    self.method,
                    self.webhook_url,
                    json=payload,
                    headers=self.headers,
                    timeout=10
                )
            
            return response.status_code in [200, 201, 202, 204]
            
        except Exception as e:
            print(f"Webhook notification failed: {e}")
            return False
    
    def test_connection(self) -> bool:
        """Test the webhook endpoint."""
        try:
            response = requests.request(
                self.method,
                self.webhook_url,
                json={"test": True, "source": "janus"},
                headers=self.headers,
                timeout=10
            )
            return response.status_code in [200, 201, 202, 204]
        except:
            return False


class EmailNotifier(NotificationChannel):
    """Email notification channel via SMTP."""
    
    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        username: str,
        password: str,
        from_addr: str,
        to_addrs: List[str],
        use_tls: bool = True
    ):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_addr = from_addr
        self.to_addrs = to_addrs
        self.use_tls = use_tls
    
    def send(self, finding: Dict[str, Any]) -> bool:
        """Send finding via email."""
        try:
            severity = finding.get('severity', 'INFO')
            subject = f"🚨 Janus Alert: {severity} - {finding.get('vulnerability_type', 'Security Finding')}"
            
            html = f"""
            <html>
            <body style="font-family: Arial, sans-serif;">
                <h2 style="color: #FF0000;">Janus Security Alert</h2>
                <table style="border-collapse: collapse; width: 100%;">
                    <tr>
                        <td style="padding: 8px; border: 1px solid #ddd;"><strong>Vulnerability</strong></td>
                        <td style="padding: 8px; border: 1px solid #ddd;">{finding.get('vulnerability_type', 'N/A')}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border: 1px solid #ddd;"><strong>Endpoint</strong></td>
                        <td style="padding: 8px; border: 1px solid #ddd;"><code>{finding.get('endpoint', 'N/A')}</code></td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border: 1px solid #ddd;"><strong>Severity</strong></td>
                        <td style="padding: 8px; border: 1px solid #ddd;">{severity}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border: 1px solid #ddd;"><strong>Evidence</strong></td>
                        <td style="padding: 8px; border: 1px solid #ddd;">{finding.get('evidence', 'N/A')}</td>
                    </tr>
                </table>
                <p style="color: #666; font-size: 12px;">Sent by Janus Security Scanner</p>
            </body>
            </html>
            """
            
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.from_addr
            msg['To'] = ', '.join(self.to_addrs)
            msg.attach(MIMEText(html, 'html'))
            
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                server.login(self.username, self.password)
                server.sendmail(self.from_addr, self.to_addrs, msg.as_string())
            
            return True
            
        except Exception as e:
            print(f"Email notification failed: {e}")
            return False
    
    def test_connection(self) -> bool:
        """Test SMTP connection."""
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                server.login(self.username, self.password)
            return True
        except:
            return False


class NotificationManager:
    """
    Manages multiple notification channels.
    
    Usage:
        manager = NotificationManager()
        manager.add_channel(DiscordWebhook(url))
        manager.add_channel(SlackWebhook(url))
        manager.notify(finding_dict)
    """
    
    def __init__(self, config: Optional[NotificationConfig] = None):
        self.config = config or NotificationConfig()
        self.channels: List[NotificationChannel] = []
    
    def add_channel(self, channel: NotificationChannel) -> None:
        """Add a notification channel."""
        self.channels.append(channel)
    
    def remove_channel(self, channel: NotificationChannel) -> None:
        """Remove a notification channel."""
        if channel in self.channels:
            self.channels.remove(channel)
    
    def notify(self, finding: Dict[str, Any]) -> Dict[str, bool]:
        """
        Send notification to all channels.
        
        Returns dict of channel_class_name -> success_status
        """
        severity = finding.get('severity', 'INFO')
        
        if not self.config.should_notify(severity):
            return {}
        
        results = {}
        for channel in self.channels:
            channel_name = channel.__class__.__name__
            results[channel_name] = channel.send(finding)
        
        return results
    
    def notify_batch(self, findings: List[Dict[str, Any]]) -> int:
        """
        Send notifications for multiple findings.
        Returns count of successfully notified findings.
        """
        success_count = 0
        for finding in findings:
            results = self.notify(finding)
            if any(results.values()):
                success_count += 1
        return success_count
    
    def test_all_channels(self) -> Dict[str, bool]:
        """Test all configured channels."""
        return {
            channel.__class__.__name__: channel.test_connection()
            for channel in self.channels
        }
