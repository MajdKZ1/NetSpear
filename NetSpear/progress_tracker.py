"""
Progress tracking system for NetSpear Network Analyzer.

Provides accurate, real-time progress tracking for long-running operations.
"""
import threading
import time
import sys
from typing import Optional, Callable
from enum import Enum

NETSPEAR_PURPLE = "\033[38;2;122;6;205m"
RESET = "\033[0m"

class ProgressStage(Enum):
    """Progress stages for different operations."""
    INITIALIZING = "Initializing"
    SCANNING = "Scanning"
    ANALYZING = "Analyzing"
    ENUMERATING = "Enumerating"
    GENERATING = "Generating"
    COMPLETING = "Completing"


class ProgressTracker:
    """Real-time progress tracker with accurate percentage calculation."""
    
    def __init__(self, total_steps: int, description: str = "Processing", 
                 show_percentage: bool = True):
        """
        Initialize progress tracker.
        
        Args:
            total_steps: Total number of steps to complete
            description: Description of the operation
            show_percentage: Whether to show percentage
        """
        self.total_steps = total_steps
        self.current_step = 0
        self.description = description
        self.show_percentage = show_percentage
        self.start_time = time.time()
        self.last_update = 0
        self.update_interval = 0.1  # Update every 100ms
        self.lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.stage: Optional[ProgressStage] = None
    
    def start(self) -> None:
        """Start the progress tracker."""
        self._running = True
        self._thread = threading.Thread(target=self._update_loop, daemon=True)
        self._thread.start()
    
    def update(self, step: int, stage: Optional[ProgressStage] = None) -> None:
        """
        Update progress.
        
        Args:
            step: Current step number (0 to total_steps)
            stage: Optional progress stage
        """
        with self.lock:
            self.current_step = min(step, self.total_steps)
            if stage:
                self.stage = stage
    
    def increment(self, amount: int = 1, stage: Optional[ProgressStage] = None) -> None:
        """
        Increment progress by amount.
        
        Args:
            amount: Number of steps to increment
            stage: Optional progress stage
        """
        with self.lock:
            self.current_step = min(self.current_step + amount, self.total_steps)
            if stage:
                self.stage = stage
    
    def set_stage(self, stage: ProgressStage) -> None:
        """Set the current progress stage."""
        with self.lock:
            self.stage = stage
    
    def finish(self) -> None:
        """Finish and stop the progress tracker."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=1.0)
        self._render(100.0, True)
    
    def _update_loop(self) -> None:
        """Internal update loop for progress display."""
        while self._running:
            with self.lock:
                if self.total_steps > 0:
                    percentage = (self.current_step / self.total_steps) * 100
                else:
                    percentage = 0
                self._render(percentage, False)
            time.sleep(self.update_interval)
    
    def _render(self, percentage: float, final: bool = False) -> None:
        """
        Render the progress bar.
        
        Args:
            percentage: Current percentage (0-100)
            final: Whether this is the final render
        """
        bar_len = 32
        percentage = max(0, min(100, percentage))
        filled = int(bar_len * percentage / 100)
        bar = "█" * filled + "░" * (bar_len - filled)
        
        stage_text = f" [{self.stage.value}]" if self.stage else ""
        desc_text = f"{self.description}{stage_text}"
        
        if self.show_percentage:
            text = f"{NETSPEAR_PURPLE}{desc_text} [{bar}] {percentage:5.1f}%{RESET}"
        else:
            text = f"{NETSPEAR_PURPLE}{desc_text} [{bar}]{RESET}"
        
        sys.stdout.write(f"\r{text}")
        sys.stdout.flush()
        
        if final:
            sys.stdout.write("\n")
            sys.stdout.flush()
            elapsed = time.time() - self.start_time
            if elapsed > 0:
                print(f"{NETSPEAR_PURPLE}Completed in {elapsed:.2f}s{RESET}")


class MultiTaskProgressTracker:
    """Progress tracker for multiple parallel tasks."""
    
    def __init__(self, total_tasks: int, description: str = "Processing tasks"):
        """
        Initialize multi-task progress tracker.
        
        Args:
            total_tasks: Total number of tasks
            description: Description of the operation
        """
        self.total_tasks = total_tasks
        self.completed_tasks = 0
        self.description = description
        self.start_time = time.time()
        self.lock = threading.Lock()
        self.task_statuses: dict = {}
    
    def task_started(self, task_id: str, task_name: str) -> None:
        """Mark a task as started."""
        with self.lock:
            self.task_statuses[task_id] = {"name": task_name, "status": "running"}
    
    def task_completed(self, task_id: str) -> None:
        """Mark a task as completed."""
        with self.lock:
            if task_id in self.task_statuses:
                self.task_statuses[task_id]["status"] = "completed"
            self.completed_tasks += 1
            self._render()
    
    def task_failed(self, task_id: str, error: str = "") -> None:
        """Mark a task as failed."""
        with self.lock:
            if task_id in self.task_statuses:
                self.task_statuses[task_id]["status"] = "failed"
                self.task_statuses[task_id]["error"] = error
            self.completed_tasks += 1
            self._render()
    
    def _render(self) -> None:
        """Render the progress display."""
        percentage = (self.completed_tasks / self.total_tasks * 100) if self.total_tasks > 0 else 0
        bar_len = 32
        filled = int(bar_len * percentage / 100)
        bar = "█" * filled + "░" * (bar_len - filled)
        
        text = f"{NETSPEAR_PURPLE}{self.description} [{bar}] {self.completed_tasks}/{self.total_tasks} tasks ({percentage:.1f}%){RESET}"
        sys.stdout.write(f"\r{text}")
        sys.stdout.flush()
    
    def finish(self) -> None:
        """Finish and display final status."""
        self._render()
        sys.stdout.write("\n")
        sys.stdout.flush()
        elapsed = time.time() - self.start_time
        print(f"{NETSPEAR_PURPLE}All tasks completed in {elapsed:.2f}s{RESET}")


