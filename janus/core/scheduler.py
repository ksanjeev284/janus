# janus/core/scheduler.py
"""
Scheduled Scan Manager for Janus Security Scanner.

Features:
- Cron-like scheduling for automatic scans
- Multiple scan profiles
- Email/webhook notifications on completion
- Persistent schedule storage
"""

import json
import os
import time
import threading
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Callable
from pathlib import Path

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
    from apscheduler.triggers.interval import IntervalTrigger
    APSCHEDULER_AVAILABLE = True
except ImportError:
    APSCHEDULER_AVAILABLE = False


@dataclass
class ScanSchedule:
    """A scheduled scan configuration."""
    id: str
    name: str
    target_url: str
    modules: List[str] = field(default_factory=list)
    schedule_type: str = "interval"  # interval, cron, daily, weekly
    interval_hours: int = 24
    cron_expression: str = ""
    token: str = ""
    param: str = ""
    notify_webhook: str = ""
    notify_email: str = ""
    output_dir: str = "reports"
    enabled: bool = True
    last_run: str = ""
    next_run: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ScanSchedule':
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class ScheduleResult:
    """Result of a scheduled scan."""
    schedule_id: str
    schedule_name: str
    target_url: str
    start_time: str
    end_time: str
    success: bool
    findings_count: int
    report_path: str
    error: str = ""
    
    def to_dict(self) -> Dict:
        return asdict(self)


class ScanScheduler:
    """
    Schedule and manage automatic security scans.
    
    Requires: pip install apscheduler
    """
    
    def __init__(self, data_dir: str = ".janus", start_immediately: bool = False):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self.schedules_file = self.data_dir / "schedules.json"
        self.history_file = self.data_dir / "scan_history.json"
        
        self.schedules: Dict[str, ScanSchedule] = {}
        self.history: List[ScheduleResult] = []
        self.scheduler: Optional[BackgroundScheduler] = None
        self._running_jobs: Dict[str, bool] = {}
        
        # Load existing schedules
        self._load_schedules()
        self._load_history()
        
        if start_immediately and APSCHEDULER_AVAILABLE:
            self.start()
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
    
    def start(self) -> bool:
        """Start the scheduler."""
        if not APSCHEDULER_AVAILABLE:
            print("Warning: apscheduler not installed. Run: pip install apscheduler")
            return False
        
        if self.scheduler is None:
            self.scheduler = BackgroundScheduler()
        
        if not self.scheduler.running:
            self.scheduler.start()
            
            # Re-add all enabled schedules
            for schedule in self.schedules.values():
                if schedule.enabled:
                    self._add_job(schedule)
        
        return True
    
    def stop(self):
        """Stop the scheduler."""
        if self.scheduler and self.scheduler.running:
            self.scheduler.shutdown()
    
    def add_schedule(self, schedule: ScanSchedule) -> bool:
        """Add a new scan schedule."""
        self.schedules[schedule.id] = schedule
        self._save_schedules()
        
        if self.scheduler and self.scheduler.running and schedule.enabled:
            self._add_job(schedule)
        
        return True
    
    def remove_schedule(self, schedule_id: str) -> bool:
        """Remove a schedule."""
        if schedule_id in self.schedules:
            del self.schedules[schedule_id]
            self._save_schedules()
            
            if self.scheduler:
                try:
                    self.scheduler.remove_job(schedule_id)
                except:
                    pass
            
            return True
        return False
    
    def enable_schedule(self, schedule_id: str) -> bool:
        """Enable a schedule."""
        if schedule_id in self.schedules:
            self.schedules[schedule_id].enabled = True
            self._save_schedules()
            
            if self.scheduler and self.scheduler.running:
                self._add_job(self.schedules[schedule_id])
            
            return True
        return False
    
    def disable_schedule(self, schedule_id: str) -> bool:
        """Disable a schedule."""
        if schedule_id in self.schedules:
            self.schedules[schedule_id].enabled = False
            self._save_schedules()
            
            if self.scheduler:
                try:
                    self.scheduler.remove_job(schedule_id)
                except:
                    pass
            
            return True
        return False
    
    def get_schedule(self, schedule_id: str) -> Optional[ScanSchedule]:
        """Get a schedule by ID."""
        return self.schedules.get(schedule_id)
    
    def list_schedules(self) -> List[ScanSchedule]:
        """List all schedules."""
        return list(self.schedules.values())
    
    def get_history(self, limit: int = 50) -> List[ScheduleResult]:
        """Get scan history."""
        return self.history[-limit:]
    
    def run_now(self, schedule_id: str) -> Optional[ScheduleResult]:
        """Run a schedule immediately."""
        schedule = self.schedules.get(schedule_id)
        if schedule:
            return self._execute_scan(schedule)
        return None
    
    def _add_job(self, schedule: ScanSchedule):
        """Add a job to the scheduler."""
        if not self.scheduler:
            return
        
        # Remove existing job if any
        try:
            self.scheduler.remove_job(schedule.id)
        except:
            pass
        
        # Create trigger based on schedule type
        if schedule.schedule_type == "interval":
            trigger = IntervalTrigger(hours=schedule.interval_hours)
        elif schedule.schedule_type == "cron" and schedule.cron_expression:
            # Parse cron expression (minute hour day month weekday)
            parts = schedule.cron_expression.split()
            if len(parts) == 5:
                trigger = CronTrigger(
                    minute=parts[0],
                    hour=parts[1],
                    day=parts[2],
                    month=parts[3],
                    day_of_week=parts[4]
                )
            else:
                trigger = IntervalTrigger(hours=24)
        elif schedule.schedule_type == "daily":
            trigger = CronTrigger(hour=0, minute=0)
        elif schedule.schedule_type == "weekly":
            trigger = CronTrigger(day_of_week='mon', hour=0, minute=0)
        else:
            trigger = IntervalTrigger(hours=24)
        
        # Add job
        job = self.scheduler.add_job(
            self._execute_scan,
            trigger=trigger,
            args=[schedule],
            id=schedule.id,
            name=schedule.name,
            replace_existing=True
        )
        
        # Update next run time
        if job.next_run_time:
            schedule.next_run = job.next_run_time.isoformat()
            self._save_schedules()
    
    def _execute_scan(self, schedule: ScanSchedule) -> ScheduleResult:
        """Execute a scheduled scan."""
        from janus.core.auto_scanner import AutoScanner
        
        start_time = datetime.now()
        success = False
        findings_count = 0
        report_path = ""
        error = ""
        
        try:
            # Run scan
            scanner = AutoScanner(timeout=60)
            report = scanner.scan(
                url=schedule.target_url,
                token=schedule.token if schedule.token else None,
                param=schedule.param if schedule.param else None,
                modules=schedule.modules if schedule.modules else None
            )
            
            success = True
            findings_count = report.total_findings
            
            # Save report
            output_dir = Path(schedule.output_dir)
            output_dir.mkdir(exist_ok=True)
            
            timestamp = start_time.strftime('%Y%m%d_%H%M%S')
            report_filename = f"scan_{schedule.id}_{timestamp}.html"
            report_path = str(output_dir / report_filename)
            
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(report.to_html())
            
            # Generate PDF if available
            try:
                from janus.reporting.pdf_generator import PDFReportGenerator
                pdf_path = str(output_dir / f"scan_{schedule.id}_{timestamp}.pdf")
                generator = PDFReportGenerator()
                generator.generate(report.to_dict(), pdf_path)
            except:
                pass
            
            # Send notifications
            if schedule.notify_webhook:
                self._send_webhook(schedule.notify_webhook, schedule, report)
            
        except Exception as e:
            error = str(e)
        
        end_time = datetime.now()
        
        # Update schedule last run
        schedule.last_run = start_time.isoformat()
        self._save_schedules()
        
        # Create result
        result = ScheduleResult(
            schedule_id=schedule.id,
            schedule_name=schedule.name,
            target_url=schedule.target_url,
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            success=success,
            findings_count=findings_count,
            report_path=report_path,
            error=error
        )
        
        # Add to history
        self.history.append(result)
        self._save_history()
        
        return result
    
    def _send_webhook(self, webhook_url: str, schedule: ScanSchedule, report):
        """Send webhook notification."""
        import requests
        
        try:
            payload = {
                "event": "scan_complete",
                "schedule_id": schedule.id,
                "schedule_name": schedule.name,
                "target_url": schedule.target_url,
                "total_findings": report.total_findings,
                "critical": report.critical_count,
                "high": report.high_count,
                "timestamp": datetime.now().isoformat()
            }
            
            requests.post(webhook_url, json=payload, timeout=10)
        except:
            pass
    
    def _load_schedules(self):
        """Load schedules from file."""
        if self.schedules_file.exists():
            try:
                with open(self.schedules_file, 'r') as f:
                    data = json.load(f)
                    for item in data:
                        schedule = ScanSchedule.from_dict(item)
                        self.schedules[schedule.id] = schedule
            except:
                pass
    
    def _save_schedules(self):
        """Save schedules to file."""
        try:
            with open(self.schedules_file, 'w') as f:
                json.dump([s.to_dict() for s in self.schedules.values()], f, indent=2)
        except:
            pass
    
    def _load_history(self):
        """Load history from file."""
        if self.history_file.exists():
            try:
                with open(self.history_file, 'r') as f:
                    data = json.load(f)
                    self.history = [ScheduleResult(**item) for item in data]
            except:
                pass
    
    def _save_history(self):
        """Save history to file."""
        try:
            # Keep last 100 entries
            self.history = self.history[-100:]
            with open(self.history_file, 'w') as f:
                json.dump([h.to_dict() for h in self.history], f, indent=2)
        except:
            pass


def create_schedule(
    name: str,
    target_url: str,
    schedule_type: str = "daily",
    interval_hours: int = 24,
    modules: Optional[List[str]] = None,
    **kwargs
) -> ScanSchedule:
    """
    Create a new scan schedule.
    
    Args:
        name: Schedule name
        target_url: Target URL to scan
        schedule_type: "interval", "daily", "weekly", or "cron"
        interval_hours: Hours between scans (for interval type)
        modules: List of modules to run
        **kwargs: Additional schedule options
    
    Returns:
        ScanSchedule instance
    """
    import uuid
    
    return ScanSchedule(
        id=str(uuid.uuid4())[:8],
        name=name,
        target_url=target_url,
        schedule_type=schedule_type,
        interval_hours=interval_hours,
        modules=modules or [],
        **kwargs
    )
