"""
Time-based scanning and scheduling system.
"""
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Any, Callable
from sqlalchemy.orm import Session
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.date import DateTrigger

from database import get_db_manager, Scan

logger = logging.getLogger(__name__)


class ScanScheduler:
    """Schedule scans and automated tasks."""
    
    def __init__(self, analyzer=None, db_session: Optional[Session] = None):
        """
        Initialize scan scheduler.
        
        Args:
            analyzer: NetSpearNetworkAnalyzer instance
            db_session: Optional database session
        """
        self.db = get_db_manager()
        self.db_session = db_session
        self.analyzer = analyzer
        self.scheduler = BackgroundScheduler()
        self.scheduler.start()
        self.job_ids = {}
    
    def _get_session(self) -> Session:
        """Get or create database session."""
        return self.db_session or self.db.get_session()
    
    def schedule_scan(
        self,
        target_ip: str,
        scan_type: str = "quick",
        schedule_type: str = "interval",
        interval_minutes: Optional[int] = None,
        cron_expression: Optional[str] = None,
        run_at: Optional[datetime] = None,
        stealth: bool = False,
        mode: str = "SAFE",
    ) -> Optional[str]:
        """
        Schedule a scan.
        
        Args:
            target_ip: Target IP address
            scan_type: Type of scan
            schedule_type: Type of schedule (interval, cron, once)
            interval_minutes: Interval in minutes (for interval type)
            cron_expression: Cron expression (for cron type)
            run_at: Specific datetime (for once type)
            stealth: Whether to use stealth mode
            mode: Scan mode
            
        Returns:
            Job ID
        """
        if not self.analyzer:
            logger.error("Analyzer not available for scheduled scan")
            return None
        
        def execute_scan():
            logger.info(f"Executing scheduled scan: {scan_type} on {target_ip}")
            try:
                self.analyzer.scanner.run_nmap_scan(
                    target_ip,
                    scan_type,
                    stealth=stealth,
                    mode=mode,
                )
            except Exception as e:
                logger.error(f"Scheduled scan failed: {e}")
        
        job_id = f"scan_{target_ip}_{datetime.now(timezone.utc).timestamp()}"
        
        try:
            if schedule_type == "interval":
                if not interval_minutes:
                    interval_minutes = 60
                trigger = IntervalTrigger(minutes=interval_minutes)
                job = self.scheduler.add_job(
                    execute_scan,
                    trigger=trigger,
                    id=job_id,
                    name=f"Scan {target_ip}",
                )
            
            elif schedule_type == "cron":
                if not cron_expression:
                    cron_expression = "0 * * * *"  # Every hour
                # Parse cron expression (format: minute hour day month day_of_week)
                parts = cron_expression.split()
                if len(parts) == 5:
                    trigger = CronTrigger(
                        minute=parts[0],
                        hour=parts[1],
                        day=parts[2],
                        month=parts[3],
                        day_of_week=parts[4],
                    )
                    job = self.scheduler.add_job(
                        execute_scan,
                        trigger=trigger,
                        id=job_id,
                        name=f"Scan {target_ip}",
                    )
                else:
                    logger.error(f"Invalid cron expression: {cron_expression}")
                    return None
            
            elif schedule_type == "once":
                if not run_at:
                    run_at = datetime.now(timezone.utc) + timedelta(minutes=5)
                trigger = DateTrigger(run_date=run_at)
                job = self.scheduler.add_job(
                    execute_scan,
                    trigger=trigger,
                    id=job_id,
                    name=f"Scan {target_ip}",
                )
            
            else:
                logger.error(f"Unknown schedule type: {schedule_type}")
                return None
            
            self.job_ids[job_id] = {
                "target_ip": target_ip,
                "scan_type": scan_type,
                "schedule_type": schedule_type,
            }
            
            logger.info(f"Scheduled scan job: {job_id}")
            return job_id
            
        except Exception as e:
            logger.error(f"Failed to schedule scan: {e}")
            return None
    
    def cancel_job(self, job_id: str) -> bool:
        """
        Cancel a scheduled job.
        
        Args:
            job_id: Job ID
            
        Returns:
            True if successful
        """
        try:
            self.scheduler.remove_job(job_id)
            if job_id in self.job_ids:
                del self.job_ids[job_id]
            logger.info(f"Cancelled job: {job_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to cancel job: {e}")
            return False
    
    def list_jobs(self) -> List[Dict[str, Any]]:
        """List all scheduled jobs."""
        jobs = []
        for job in self.scheduler.get_jobs():
            jobs.append({
                "job_id": job.id,
                "name": job.name,
                "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
            })
        return jobs
    
    def shutdown(self):
        """Shutdown the scheduler."""
        self.scheduler.shutdown()

