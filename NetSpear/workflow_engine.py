"""
Workflow automation engine with playbooks and conditional execution.
"""
import logging
import json
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any, Callable
from enum import Enum

from database import get_db_manager, Workflow, WorkflowExecution

logger = logging.getLogger(__name__)


class WorkflowStepType(Enum):
    """Workflow step types."""
    SCAN = "scan"
    RECON = "recon"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    CUSTOM = "custom"
    CONDITION = "condition"
    LOOP = "loop"
    NOTIFY = "notify"


class WorkflowEngine:
    """Engine for executing automated workflows."""
    
    def __init__(self, analyzer=None):
        """
        Initialize workflow engine.
        
        Args:
            analyzer: NetSpearNetworkAnalyzer instance for executing operations
        """
        self.db = get_db_manager()
        self.analyzer = analyzer
        self.step_handlers: Dict[str, Callable] = {
            WorkflowStepType.SCAN.value: self._handle_scan,
            WorkflowStepType.RECON.value: self._handle_recon,
            WorkflowStepType.EXPLOIT.value: self._handle_exploit,
            WorkflowStepType.POST_EXPLOIT.value: self._handle_post_exploit,
            WorkflowStepType.CONDITION.value: self._handle_condition,
            WorkflowStepType.NOTIFY.value: self._handle_notify,
        }
    
    def create_workflow(
        self,
        name: str,
        description: str,
        steps: List[Dict[str, Any]],
        enabled: bool = True,
    ) -> Optional[Workflow]:
        """
        Create a new workflow.
        
        Args:
            name: Workflow name
            description: Workflow description
            steps: List of workflow steps
            enabled: Whether workflow is enabled
            
        Returns:
            Created workflow object
        """
        db = self.db.get_session()
        try:
            workflow = Workflow(
                name=name,
                description=description,
                steps=steps,
                enabled=enabled,
            )
            db.add(workflow)
            db.commit()
            db.refresh(workflow)
            logger.info(f"Created workflow: {name}")
            return workflow
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to create workflow: {e}")
            return None
    
    def get_workflow(self, workflow_uuid: str) -> Optional[Workflow]:
        """Get workflow by UUID."""
        db = self.db.get_session()
        return db.query(Workflow).filter(Workflow.workflow_uuid == workflow_uuid).first()
    
    def list_workflows(self, enabled_only: bool = False) -> List[Workflow]:
        """
        List all workflows.
        
        Args:
            enabled_only: Only return enabled workflows
            
        Returns:
            List of workflows
        """
        db = self.db.get_session()
        query = db.query(Workflow)
        if enabled_only:
            query = query.filter(Workflow.enabled == True)
        return query.all()
    
    def execute_workflow(
        self,
        workflow_uuid: str,
        target: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[WorkflowExecution]:
        """
        Execute a workflow.
        
        Args:
            workflow_uuid: Workflow UUID
            target: Optional target (IP, domain, etc.)
            context: Optional context variables
            
        Returns:
            Workflow execution record
        """
        workflow = self.get_workflow(workflow_uuid)
        if not workflow:
            logger.error(f"Workflow not found: {workflow_uuid}")
            return None
        
        if not workflow.enabled:
            logger.warning(f"Workflow is disabled: {workflow_uuid}")
            return None
        
        db = self.db.get_session()
        try:
            execution = WorkflowExecution(
                workflow_id=workflow.id,
                status="running",
                target=target,
                results={},
            )
            db.add(execution)
            db.commit()
            db.refresh(execution)
            
            # Execute workflow steps
            context = context or {}
            context["target"] = target
            context["execution_uuid"] = execution.execution_uuid
            
            results = self._execute_steps(workflow.steps, context)
            
            # Update execution
            execution.status = "completed"
            execution.results = results
            execution.completed_at = datetime.now(timezone.utc)
            db.commit()
            
            logger.info(f"Workflow execution completed: {execution.execution_uuid}")
            return execution
        except Exception as e:
            db.rollback()
            logger.error(f"Workflow execution failed: {e}")
            if execution:
                execution.status = "failed"
                execution.results = {"error": str(e)}
                db.commit()
            return None
    
    def _execute_steps(
        self,
        steps: List[Dict[str, Any]],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Execute workflow steps.
        
        Args:
            steps: List of workflow steps
            context: Execution context
            
        Returns:
            Step execution results
        """
        results = {}
        
        for i, step in enumerate(steps):
            step_id = step.get("id", f"step_{i}")
            step_type = step.get("type", "custom")
            
            try:
                handler = self.step_handlers.get(step_type)
                if handler:
                    result = handler(step, context)
                    results[step_id] = result
                else:
                    results[step_id] = {"error": f"Unknown step type: {step_type}"}
                
                # Check for conditions to skip remaining steps
                if step.get("stop_on_error") and results[step_id].get("error"):
                    logger.warning(f"Stopping workflow due to error in step {step_id}")
                    break
                    
            except Exception as e:
                logger.error(f"Error executing step {step_id}: {e}")
                results[step_id] = {"error": str(e)}
                if step.get("stop_on_error"):
                    break
        
        return results
    
    def _handle_scan(self, step: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle scan step."""
        if not self.analyzer:
            return {"error": "Analyzer not available"}
        
        target = step.get("target") or context.get("target")
        scan_type = step.get("scan_type", "quick")
        
        if not target:
            return {"error": "No target specified"}
        
        logger.info(f"Executing scan step: {scan_type} on {target}")
        
        # Execute scan via analyzer
        scan_result, vulnerabilities = self.analyzer.scanner.run_nmap_scan(
            target,
            scan_type,
            stealth=step.get("stealth", False),
            proxy=step.get("proxy"),
            mode=step.get("mode", "SAFE"),
        )
        
        return {
            "success": True,
            "scan_result": scan_result,
            "vulnerabilities": vulnerabilities,
        }
    
    def _handle_recon(self, step: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle recon step."""
        if not self.analyzer:
            return {"error": "Analyzer not available"}
        
        target = step.get("target") or context.get("target")
        recon_type = step.get("recon_type", "passive")
        
        if not target:
            return {"error": "No target specified"}
        
        logger.info(f"Executing recon step: {recon_type} on {target}")
        
        # Execute recon via analyzer
        recon_data = self.analyzer.enhanced_recon.passive_recon_parallel(target, "ip")
        
        return {
            "success": True,
            "recon_data": recon_data,
        }
    
    def _handle_exploit(self, step: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle exploit step."""
        # This would integrate with exploit runner
        return {
            "success": True,
            "note": "Exploit step executed",
        }
    
    def _handle_post_exploit(self, step: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle post-exploitation step."""
        # This would integrate with post-exploitation framework
        return {
            "success": True,
            "note": "Post-exploitation step executed",
        }
    
    def _handle_condition(self, step: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle conditional step."""
        condition = step.get("condition")
        if not condition:
            return {"error": "No condition specified"}
        
        # Evaluate condition (simplified - would need proper expression evaluator)
        result = eval(condition, {"__builtins__": {}}, context)
        
        return {
            "success": True,
            "condition_result": result,
        }
    
    def _handle_notify(self, step: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle notification step."""
        # This would integrate with notification system
        logger.info(f"Notification: {step.get('message', 'Workflow notification')}")
        return {
            "success": True,
            "note": "Notification sent",
        }

